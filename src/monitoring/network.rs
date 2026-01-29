use crate::events::{BaseEvent, EventType};
use crate::events::network::NetworkEvent;
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::error::Error;
use crate::monitoring::common::{is_browser_related_process, get_process_name_cached, GLOBAL_SENDER,create_connection_signature, ConnectionAttempt, get_timestamp, cleanup_tracking_data, RECENT_CONNECTIONS, CONNECTION_TRACKER, DNS_CACHE, QUIC_CONNECTIONS};
use windows::Win32::System::Diagnostics::Etw::*;
use windows::core::{GUID, PWSTR};
use windows::{
    Win32::{
        Foundation::{ERROR_SUCCESS}
    },
};

// GUID for Microsoft-Windows-TCPIP
const TCPIP_PROVIDER_GUID: u128 = 0x7dd42a49532948328dfd43d979153a88u128;

// TCP/IP Event IDs
const EVENT_ID_TCPIP_SEND: u16 = 10;
const EVENT_ID_TCPIP_RECV: u16 = 11;
const EVENT_ID_TCPIP_CONNECT: u16 = 12;
const EVENT_ID_TCPIP_DISCONNECT: u16 = 13;
const EVENT_ID_TCPIP_RECONNECT: u16 = 16;

// UDP Event IDs
const EVENT_ID_UDP_SEND: u16 = 42;
const EVENT_ID_UDP_RECV: u16 = 43;

// TCP/IP event data structures
#[repr(C)]
struct TcpIpV4Event {
    pid: u32,
    size: u32,
    daddr: u32,
    saddr: u32,
    dport: u16,
    sport: u16,
}

#[repr(C)]
struct TcpIpV6Event {
    pid: u32,
    size: u32,
    daddr: [u8; 16],
    saddr: [u8; 16],
    dport: u16,
    sport: u16,
}

fn should_log_connection(
    pid: u32, 
    process_name: &str,
    saddr: &str, 
    sport: u16, 
    daddr: &str, 
    dport: u16, 
    direction: &str,
    network_type: &str,
) -> bool {
    let is_browser = is_browser_related_process(pid, process_name);
    
    // Skip browser loopback connections entirely (they're just IPC)
    if is_browser && network_type == "Loopback" {
        return false;
    }
    
    // ALWAYS log these event types for external connections
    if network_type == "External" {
        match direction {
            "Connect" | "Disconnect" | "Reconnect" => {
                return true;
            }
            _ => {}
        }
        
        // For Send/Recv, deduplicate
        let sig = create_connection_signature(pid, saddr, sport, daddr, dport);
        
        if let Ok(mut recent) = RECENT_CONNECTIONS.lock() {
            if recent.contains(&sig) {
                return false;
            }
            
            recent.insert(sig);
            
            if recent.len() > 5000 {
                recent.clear();
            }
        }
        
        return true;
    }
    
    if is_browser {
        if let Ok(mut tracker) = CONNECTION_TRACKER.lock() {
            let attempts = tracker.entry(pid).or_insert_with(Vec::new);
            
            if attempts.len() < 15 {
                attempts.push(ConnectionAttempt {
                    timestamp: get_timestamp(),
                    dest_addr: daddr.to_string(),
                    dest_port: dport,
                    network_type: network_type.to_string(),
                });
                return true;
            }
            
            let is_new = !attempts.iter().any(|a| 
                a.dest_addr == daddr && a.dest_port == dport
            );
            
            if is_new {
                attempts.push(ConnectionAttempt {
                    timestamp: get_timestamp(),
                    dest_addr: daddr.to_string(),
                    dest_port: dport,
                    network_type: network_type.to_string(),
                });
                return true;
            }
        }
    }
    
    if network_type != "External" {
        let sig = create_connection_signature(pid, saddr, sport, daddr, dport);
        
        if let Ok(mut recent) = RECENT_CONNECTIONS.lock() {
            if recent.len() > 2000 {
                recent.clear();
            }
            
            if recent.contains(&sig) {
                return false;
            }
            
            recent.insert(sig);
        }
    }
    
    true
}

fn is_suspicious_loopback(process_name: &str, sport: u16, dport: u16) -> bool {
    const SUSPICIOUS_PROCESSES: &[&str] = &[
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe",
    ];
    
    let lower_name = process_name.to_lowercase();
    
    if SUSPICIOUS_PROCESSES.iter().any(|&p| lower_name.contains(p)) {
        return true;
    }
    
    const COMMON_PORTS: &[u16] = &[80, 443, 3389, 5985, 5986, 8080];
    if !COMMON_PORTS.contains(&sport) && !COMMON_PORTS.contains(&dport) {
        if sport < 49152 && dport < 49152 {
            return true;
        }
    }
    
    false
}

fn should_correlate(_pid: u32, process_name: &str, _dest_addr: &str, network_type: &str) -> bool {
    if network_type == "External" {
        return true;
    }
    
    const SUSPICIOUS_NAMES: &[&str] = &[
        "powershell", "cmd", "wscript", "cscript", 
        "mshta", "rundll32", "regsvr32", "certutil"
    ];
    
    let lower_name = process_name.to_lowercase();
    if SUSPICIOUS_NAMES.iter().any(|&name| lower_name.contains(name)) {
        return true;
    }
    
    if network_type == "LocalNetwork" {
        return true;
    }
    
    false
}

pub fn start_tcpip_listener(
    tx: Sender<BaseEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, Box<dyn Error>> {
    let handle = std::thread::spawn(move || {
        unsafe {
            {
                let mut guard = GLOBAL_SENDER.lock().unwrap();
                *guard = Some(Arc::new(tx.clone()));
            }

            let session_name = widestring::U16CString::from_str("EDR_TCPIP_LOGGER").unwrap();
            
            let mut stop_buffer = vec![0u8; std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024];
            let stop_props = stop_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
            (*stop_props).Wnode.BufferSize = stop_buffer.len() as u32;
            (*stop_props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            
            let stop_result = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PWSTR(session_name.as_ptr() as *mut u16),
                stop_props,
                EVENT_TRACE_CONTROL_STOP,
            );
            
            if stop_result == ERROR_SUCCESS {
                log::info!("Stopped existing TCP/IP session");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }

            let mut buffer = vec![0u8; std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024];
            let props = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

            (*props).Wnode.BufferSize = buffer.len() as u32;
            (*props).Wnode.ClientContext = 1;
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

            let mut session_handle = CONTROLTRACE_HANDLE::default();

            let status = StartTraceW(
                &mut session_handle,
                PWSTR(session_name.as_ptr() as *mut u16),
                props,
            );

            if status != ERROR_SUCCESS {
                log::error!("StartTraceW failed for TCPIP: 0x{:08X}", status.0);
                {
                    let mut guard = GLOBAL_SENDER.lock().unwrap();
                    *guard = None;
                }
                return;
            }

            log::info!("✅ TCP/IP ETW session started");

            let provider_guid = GUID::from_u128(TCPIP_PROVIDER_GUID);
            
            let enable_result = EnableTraceEx2(
                session_handle,
                &provider_guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0 as u32,
                5,
                0xFFFFFFFF,
                0,
                0,
                None,
            );

            if enable_result != ERROR_SUCCESS {
                log::warn!("EnableTraceEx2 failed: 0x{:08X}", enable_result.0);
            } else {
                log::info!("✅ TCP/IP provider enabled");
            }

            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName = PWSTR(session_name.as_ptr() as *mut u16);
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;

            unsafe extern "system" fn tcpip_callback(record: *mut EVENT_RECORD) {
                if record.is_null() {
                    return;
                }

                let rec = unsafe { &*record };
                let header = &rec.EventHeader;
                let pid = header.ProcessId;
                let event_id = header.EventDescriptor.Id;

                if pid <= 4 || pid == 0 {
                    return;
                }

                let process_name = get_process_name_cached(pid);
                let is_browser = is_browser_related_process(pid, &process_name);
                
                if !is_browser {
                    let lower = process_name.to_lowercase();
                    if lower.contains("svchost") || lower.contains("system") ||
                       lower.contains("csrss") || lower.contains("wininit") ||
                       lower.contains("services") || lower.contains("endpoint-threat-detection") {
                        return;
                    }
                }

                if rec.UserDataLength > 0 && !rec.UserData.is_null() {
                    let (saddr, daddr, sport, dport, _is_ipv6) = match event_id {
                        EVENT_ID_TCPIP_SEND | EVENT_ID_TCPIP_RECV | 
                        EVENT_ID_TCPIP_CONNECT | EVENT_ID_TCPIP_DISCONNECT | 
                        EVENT_ID_TCPIP_RECONNECT | EVENT_ID_UDP_SEND | EVENT_ID_UDP_RECV => {
                            parse_tcpip_event(rec.UserData, rec.UserDataLength as usize)
                        }
                        _ => return,
                    };

                    if saddr.is_empty() || daddr.is_empty() {
                        return;
                    }

                    let direction = match event_id {
                        EVENT_ID_TCPIP_SEND => "TCP Send",
                        EVENT_ID_TCPIP_RECV => "TCP Recv",
                        EVENT_ID_TCPIP_CONNECT => "TCP Connect",
                        EVENT_ID_TCPIP_DISCONNECT => "TCP Disconnect",
                        EVENT_ID_TCPIP_RECONNECT => "TCP Reconnect",
                        EVENT_ID_UDP_SEND => "UDP Send",
                        EVENT_ID_UDP_RECV => "UDP Recv",
                        _ => "Unknown",
                    };

                    // Determine protocol type
                    let protocol = match event_id {
                        EVENT_ID_UDP_SEND | EVENT_ID_UDP_RECV => "UDP",
                        _ => "TCP",
                    };

                    let network_type = classify_network_connection(&saddr, &daddr);

                    // For UDP, track QUIC connections (HTTP/3 over UDP on port 443)
                    if protocol == "UDP" {
                        handle_udp_event(pid, &process_name, &daddr, dport, network_type, event_id, &saddr, sport);
                        return; // Don't process UDP further
                    }
                    
                    if !should_log_connection(pid, &process_name, &saddr, sport, &daddr, dport, direction, network_type) {
                        return;
                    }
                    
                    if network_type == "Loopback" && !is_browser && !is_suspicious_loopback(&process_name, sport, dport) {
                        return;
                    }

                    log_network_event(
                        &process_name, pid, direction, network_type,
                        protocol,
                        &saddr, sport, &daddr, dport, is_browser
                    );

                    let should_correlate_flag = network_type == "External" || 
                                                is_browser ||
                                                should_correlate(pid, &process_name, &daddr, network_type);
                    
                    if should_correlate_flag {
                        let net_direction = match event_id {
                            EVENT_ID_TCPIP_SEND | EVENT_ID_TCPIP_CONNECT | EVENT_ID_TCPIP_RECONNECT => 
                                crate::events::network::NetworkDirection::Outbound,
                            _ => crate::events::network::NetworkDirection::Inbound,
                        };

                        let net = NetworkEvent::new(
                            pid, process_name, net_direction,
                            crate::events::network::Protocol::TCP,
                            saddr, sport, daddr, dport,
                        );
                        
                        let base = BaseEvent::new(EventType::NetworkConnection(net));
                        
                        if let Ok(guard) = GLOBAL_SENDER.lock() {
                            if let Some(sender) = guard.as_ref() {
                                let _ = sender.send(base);
                            }
                        }
                    }
                }
            }

            logfile.Anonymous2.EventRecordCallback = Some(tcpip_callback);

            let trace_handle = OpenTraceW(&mut logfile);
            if trace_handle.Value == u64::MAX {
                log::error!("OpenTraceW failed for TCPIP");
                let _ = ControlTraceW(
                    session_handle,
                    PWSTR(session_name.as_ptr() as *mut u16),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
                {
                    let mut guard = GLOBAL_SENDER.lock().unwrap();
                    *guard = None;
                }
                return;
            }

            log::info!("✅ TCP/IP ETW trace opened");

            let process_trace_handle = trace_handle;
            let process_thread = std::thread::spawn(move || {
                let _ = ProcessTrace(&[process_trace_handle], None, None);
            });

            let mut cleanup_counter = 0;
            while shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(200));
                
                // Run cleanup every 30 seconds
                cleanup_counter += 1;
                if cleanup_counter >= 150 {
                    cleanup_tracking_data();
                    cleanup_counter = 0;
                }
            }

            let _ = CloseTrace(trace_handle);
            
            let _ = ControlTraceW(
                session_handle,
                PWSTR(session_name.as_ptr() as *mut u16),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );

            let _ = process_thread.join();

            {
                let mut guard = GLOBAL_SENDER.lock().unwrap();
                *guard = None;
            }

            log::info!("✅ TCP/IP ETW session stopped");
        }
    });

    Ok(handle)
}

fn handle_udp_event(
    pid: u32,
    process_name: &str,
    daddr: &str,
    dport: u16,
    network_type: &str,
    event_id: u16,
    saddr: &str,
    sport: u16,
) {
    // Filter out local UDP noise
    if network_type == "Loopback" {
        return;
    }
    
    // DNS queries
    if dport == 53 {
        let dns_sig = format!("{}->DNS", pid);
        
        let mut should_log_dns = false;
        
        if let Ok(mut dns_cache) = DNS_CACHE.lock() {
            if !dns_cache.contains(&dns_sig) {
                dns_cache.insert(dns_sig);
                should_log_dns = true;
                
                if dns_cache.len() > 100 {
                    dns_cache.clear();
                }
            }
        }
        
        if should_log_dns {
            log::info!(
                "\n\
                ┌─ DNS Event ─────────────────────────────\n\
                │ Process Name = {}\n\
                │ PID  = {}\n\
                │ Destination = {}\n\
                └───────────────────────────────────────────────",
                process_name, pid, daddr
            );
        }
        return;
    }

    // Filter out multicast/broadcast noise (SSDP, mDNS, etc.)
    if daddr.starts_with("239.") || daddr.starts_with("224.") || 
    daddr == "255.255.255.255" || dport == 1900 || dport == 5353 {
        // These are legitimate discovery protocols but generate spam
        // Only log first occurrence per process
        let multicast_sig = format!("{}-multicast", pid);
        
        if let Ok(mut dns_cache) = DNS_CACHE.lock() {
            if !dns_cache.contains(&multicast_sig) {
                dns_cache.insert(multicast_sig);
                log::info!(
                    "\n\
                    ┌─ Multicast Event ─────────────────────────────\n\
                    │ Process Name = {}\n\
                    │ PID  = {}\n\
                    │ Protocol = {}\n\
                    │ Destination = {}:{}\n\
                    └───────────────────────────────────────────────",
                    process_name, pid,
                    if dport == 1900 { "SSDP" } else if dport == 5353 { "mDNS" } else { "Multicast" },
                    daddr, dport
                );
            }
        }
        return;
    }
    
    // QUIC/HTTP3 (UDP on port 443)
    if dport == 443 && network_type == "External" {
        let quic_sig = format!("{}->{}:{}", pid, daddr, dport);

        let mut should_log = false;
        if let Ok(mut quic_conns) = QUIC_CONNECTIONS.lock() {
            if !quic_conns.contains(&quic_sig) {
                quic_conns.insert(quic_sig);
                should_log = true;
                
                // Limit cache size
                if quic_conns.len() > 1000 {
                    quic_conns.clear();
                }
            }
        }
        
        if should_log {
            log::info!(
                "\n\
                ┌─ QUIC/HTTP3 Event ─────────────────────────────\n\
                │ Process Name = {}\n\
                │ PID  = {}\n\
                │ Destination = {}:{}\n\
                │ IP Owner = {}\n\
                └───────────────────────────────────────────────",
                process_name, pid, daddr, dport, identify_ip_owner(daddr)
            );
            
            // Create network event for correlation
            let net_direction = if event_id == EVENT_ID_UDP_SEND {
                crate::events::network::NetworkDirection::Outbound
            } else {
                crate::events::network::NetworkDirection::Inbound
            };

            let net = NetworkEvent::new(
                pid, process_name.to_string(), net_direction,
                crate::events::network::Protocol::UDP,
                saddr.to_string(), sport, 
                daddr.to_string(), dport,
            );
            
            let base = BaseEvent::new(EventType::NetworkConnection(net));
            
            if let Ok(guard) = GLOBAL_SENDER.lock() {
                if let Some(sender) = guard.as_ref() {
                    let _ = sender.send(base);
                }
            }
        }
        return;
    }
    
    // Other UDP - only log external
    if network_type == "External" {
        log::info!(
            "\n\
            ┌─ UDP Event ─────────────────────────────\n\
            │ Process Name = {}\n\
            │ PID  = {}\n\
            │ Direction = {}\n\
            │ Destination = {}:{}\n\
            │ Network Type = {}\n\
            └───────────────────────────────────────────────",
            process_name, pid, 
            if event_id == EVENT_ID_UDP_SEND { "Send" } else { "Recv" },
            daddr, dport, network_type
        );
    }
}

fn identify_ip_owner(ip: &str) -> &'static str {
    // Google IP ranges
    if ip.starts_with("142.250.") || ip.starts_with("142.251.") ||
       ip.starts_with("172.217.") || ip.starts_with("216.58.") ||
       ip.starts_with("34.") || ip.starts_with("35.") ||
       ip.starts_with("130.211.") {
        return "[Google/YouTube]";
    }
    
    // Cloudflare
    if ip.starts_with("104.16.") || ip.starts_with("104.17.") ||
       ip.starts_with("172.64.") || ip.starts_with("104.18.") {
        return "[Cloudflare CDN]";
    }
    
    // Amazon/AWS
    if ip.starts_with("54.") || ip.starts_with("52.") ||
       ip.starts_with("18.") {
        return "[Amazon AWS]";
    }
    
    // Microsoft
    if ip.starts_with("13.") || ip.starts_with("20.") ||
       ip.starts_with("40.") || ip.starts_with("104.") {
        return "[Microsoft]";
    }
    
    // Akamai
    if ip.starts_with("23.") || ip.starts_with("184.") {
        return "[Akamai CDN]";
    }
    
    // Facebook/Meta
    if ip.starts_with("157.240.") || ip.starts_with("31.13.") {
        return "[Facebook/Meta]";
    }
    
    ""
}

unsafe fn parse_tcpip_event(user_data: *const std::ffi::c_void, data_len: usize) -> (String, String, u16, u16, bool) {
    if data_len >= std::mem::size_of::<TcpIpV4Event>() {
        let event = &*(user_data as *const TcpIpV4Event);
        
        let saddr = u32::from_be(event.saddr);
        let daddr = u32::from_be(event.daddr);
        
        let saddr_bytes = saddr.to_be_bytes();
        let daddr_bytes = daddr.to_be_bytes();
        
        let saddr_str = format!("{}.{}.{}.{}", 
            saddr_bytes[0], saddr_bytes[1], saddr_bytes[2], saddr_bytes[3]);
        let daddr_str = format!("{}.{}.{}.{}", 
            daddr_bytes[0], daddr_bytes[1], daddr_bytes[2], daddr_bytes[3]);
        
        let sport = u16::from_be(event.sport);
        let dport = u16::from_be(event.dport);
        
        return (saddr_str, daddr_str, sport, dport, false);
    }
    
    if data_len >= std::mem::size_of::<TcpIpV6Event>() {
        let event = &*(user_data as *const TcpIpV6Event);
        
        let saddr = format_ipv6(&event.saddr);
        let daddr = format_ipv6(&event.daddr);
        
        let sport = u16::from_be(event.sport);
        let dport = u16::from_be(event.dport);
        
        return (saddr, daddr, sport, dport, true);
    }
    
    (String::new(), String::new(), 0, 0, false)
}

fn format_ipv6(bytes: &[u8; 16]) -> String {
    let mut result = String::new();
    for i in (0..16).step_by(2) {
        if i > 0 {
            result.push(':');
        }
        result.push_str(&format!("{:02x}{:02x}", bytes[i], bytes[i + 1]));
    }
    result
}

fn classify_network_connection(saddr: &str, daddr: &str) -> &'static str {
    // Loopback
    if saddr.starts_with("127.") || daddr.starts_with("127.") ||
       saddr == "::1" || daddr == "::1" ||
       saddr == "0:0:0:0:0:0:0:1" || daddr == "0:0:0:0:0:0:0:1" {
        return "Loopback";
    }
    
    // Multicast/Broadcast
    if saddr.starts_with("224.") || saddr.starts_with("239.") || saddr == "255.255.255.255" ||
       daddr.starts_with("224.") || daddr.starts_with("239.") || daddr == "255.255.255.255" ||
       saddr.starts_with("ff") || daddr.starts_with("ff") { // IPv6 multicast
        return "Multicast";
    }
    
    // Local network - (both addresses private)
    if is_private_ipv4(saddr) && is_private_ipv4(daddr) {
        return "LocalNetwork";
    }
    
    if (is_ipv6_link_local(saddr) && is_ipv6_link_local(daddr)) ||
       (is_ipv6_unique_local(saddr) && is_ipv6_unique_local(daddr)) {
        return "LocalNetwork";
    }
    
    if (is_private_ipv4(saddr) || is_ipv6_link_local(saddr) || is_ipv6_unique_local(saddr)) &&
       (is_private_ipv4(daddr) || is_ipv6_link_local(daddr) || is_ipv6_unique_local(daddr)) {
        return "LocalNetwork";
    }
    
    "External"
}

fn is_private_ipv4(addr: &str) -> bool {
    if let Some(first_dot) = addr.find('.') {
        let first_octet = &addr[..first_dot];
        match first_octet.parse::<u8>() {
            Ok(10) => return true,
            Ok(172) => {
                if let Some(second_dot) = addr[first_dot+1..].find('.') {
                    let second_octet_start = first_dot + 1;
                    let second_octet_end = second_octet_start + second_dot;
                    let second_octet = &addr[second_octet_start..second_octet_end];
                    if let Ok(num) = second_octet.parse::<u8>() {
                        return num >= 16 && num <= 31;
                    }
                }
            }
            Ok(192) => {
                let rest = &addr[first_dot+1..];
                return rest.starts_with("168.");
            }
            _ => {}
        }
    }
    false
}

fn is_ipv6_link_local(addr: &str) -> bool {
    addr.to_lowercase().starts_with("fe80:")
}

fn is_ipv6_unique_local(addr: &str) -> bool {
    let lower = addr.to_lowercase();
    lower.starts_with("fc") || lower.starts_with("fd")
}

fn log_network_event(
    process_name: &str,
    pid: u32,
    direction: &str,
    network_type: &str,
    protocol: &str,
    saddr: &str,
    sport: u16,
    daddr: &str,
    dport: u16,
    is_browser: bool,
) {
    let browser_tag = if is_browser { " [BROWSER]" } else { "" };
    
    let protocol_type = if protocol == "UDP" { 
        identify_udp_service(dport) 
    } else { 
        "IPv4"
    };
    
    log::info!(
        "\n\
        ┌─ {}/IP Event{} ────────────────────────────────\n\
        │ Process      = {}\n\
        │ PID          = {}\n\
        │ Direction    = {}\n\
        │ Network Type = {}\n\
        │ Protocol     = {}\n\
        │ Source       = {}:{}\n\
        │ Destination  = {}:{}\n\
        └───────────────────────────────────────────────",
        protocol,
        browser_tag,
        process_name,
        pid,
        direction,
        network_type,
        protocol_type,
        saddr,
        sport,
        daddr,
        dport
    );
}

fn identify_udp_service(port: u16) -> &'static str {
    match port {
        53 => "DNS",
        123 => "NTP",
        161 | 162 => "SNMP",
        500 => "IKE/IPSec",
        1900 => "SSDP",
        3478 => "STUN",
        5353 => "mDNS",
        _ => {
            if port == 443 {
                "QUIC (HTTP/3)"
            } else {
                "UDP"
            }
        }
    }
}