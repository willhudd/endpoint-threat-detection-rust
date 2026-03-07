use crate::events::{BaseEvent, EventType};
use crate::events::network::NetworkEvent;
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use crate::utils::common::{
    is_browser_related_process,
    is_system_process,
    get_process_name_cached,
    get_timestamp,
    cleanup_tracking_data,
    ConnectionAttempt,
    GLOBAL_SENDER,
    RECENT_CONNECTIONS,
    CONNECTION_TRACKER,
    DNS_CACHE,
    QUIC_CONNECTIONS,
};
use windows::Win32::System::Diagnostics::Etw::*;
use windows::core::{GUID, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;

const TCPIP_PROVIDER_GUID: u128 = 0x7dd42a49532948328dfd43d979153a88u128;

const EVENT_ID_TCPIP_SEND: u16 = 10;
const EVENT_ID_TCPIP_RECV: u16 = 11;
const EVENT_ID_TCPIP_CONNECT: u16 = 12;
const EVENT_ID_TCPIP_DISCONNECT: u16 = 13;
const EVENT_ID_TCPIP_RECONNECT: u16 = 16;

const EVENT_ID_UDP_SEND: u16 = 42;
const EVENT_ID_UDP_RECV: u16 = 43;

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

pub fn start_network_monitor(
    tx: Sender<BaseEvent>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        run_network_monitor(tx, shutdown);
    })
}

pub fn run_network_monitor(
    tx: Sender<BaseEvent>,
    shutdown: Arc<AtomicBool>,
) {
    unsafe {
        {
            let mut guard = GLOBAL_SENDER.lock().unwrap();
            *guard = Some(Arc::new(tx.clone()));
        }

        let session_name = widestring::U16CString::from_str("HIDS_NETWORK_MONITOR").unwrap();

        // Stop any existing session before starting a new one
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
            log::info!("Stopped Existing Network Monitor Session");
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
            log::error!("Network Monitor StartTraceW Failed: 0x{:08X}", status.0);
            match status.0 {
                0x000000B7 => log::error!("Network Monitor already running"),
                0x00000005 => log::error!("Access denied - run as Administrator"),
                _ => {}
            }
            let mut guard = GLOBAL_SENDER.lock().unwrap();
            *guard = None;
            return;
        }
        log::info!("✅ Network Monitor session started");

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

            if pid <= 4 {
                return;
            }

            let process_name = get_process_name_cached(pid);
            let is_browser = is_browser_related_process(pid, &process_name);

            if !is_browser && is_system_process(&process_name) {
                return;
            }

            if rec.UserDataLength == 0 || rec.UserData.is_null() {
                return;
            }

            let (saddr, daddr, sport, dport, _is_ipv6) = match event_id {
                EVENT_ID_TCPIP_SEND | EVENT_ID_TCPIP_RECV    |
                EVENT_ID_TCPIP_CONNECT | EVENT_ID_TCPIP_DISCONNECT |
                EVENT_ID_TCPIP_RECONNECT | EVENT_ID_UDP_SEND | EVENT_ID_UDP_RECV => {
                    parse_tcpip_event(rec.UserData, rec.UserDataLength as usize)
                }
                _ => return,
            };

            if saddr.is_empty() || daddr.is_empty() {
                return;
            }

            let protocol = match event_id {
                EVENT_ID_UDP_SEND | EVENT_ID_UDP_RECV => "UDP",
                _                                     => "TCP",
            };

            let network_type = classify_network_connection(&saddr, &daddr);

            if protocol == "UDP" {
                handle_udp_event(pid, &process_name, &saddr, sport, &daddr, dport, network_type, event_id);
                return;
            }

            if network_type == "Loopback" && !is_browser && !is_suspicious_loopback(&process_name, sport, dport) {
                return;
            }

            if network_type != "External"
                && !is_browser
                && !is_suspicious_loopback(&process_name, sport, dport)
            {
                return;
            }

            let net_direction = match event_id {
                EVENT_ID_TCPIP_SEND | EVENT_ID_TCPIP_CONNECT | EVENT_ID_TCPIP_RECONNECT =>
                    crate::events::network::NetworkDirection::Outbound,
                _ =>
                    crate::events::network::NetworkDirection::Inbound,
            };

            let net = NetworkEvent::new(
                pid,
                process_name,
                net_direction,
                crate::events::network::Protocol::TCP,
                saddr,
                sport,
                daddr,
                dport,
            );
            let base = BaseEvent::new(EventType::NetworkConnection(net));

            if let Ok(guard) = GLOBAL_SENDER.lock() {
                if let Some(sender) = guard.as_ref() {
                    let _ = sender.send(base);
                }
            }
        }

        logfile.Anonymous2.EventRecordCallback = Some(tcpip_callback);

        let trace_handle = OpenTraceW(&mut logfile);
        if trace_handle.Value == u64::MAX {
            log::error!("Network Monitor OpenTraceW Failed");
            let _ = ControlTraceW(
                session_handle,
                PWSTR(session_name.as_ptr() as *mut u16),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
            let mut guard = GLOBAL_SENDER.lock().unwrap();
            *guard = None;
            return;
        }
        log::info!("✅ Network Monitor OpenTraceW Opened");

        let etw_thread = std::thread::spawn(move || {
            let _ = ProcessTrace(&[trace_handle], None, None);
        });

        let mut cleanup_counter = 0u32;
        while shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(200));
            cleanup_counter += 1;
            if cleanup_counter >= 150 {
                // ~30 seconds
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
        let _ = etw_thread.join();

        {
            let mut guard = GLOBAL_SENDER.lock().unwrap();
            *guard = None;
        }
        log::info!("✅ Network Monitor session stopped");
    }
}

fn is_suspicious_loopback(process_name: &str, sport: u16, dport: u16) -> bool {
    const SUSPICIOUS_PROCESSES: &[&str] = &[
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe",
    ];
    const COMMON_PORTS: &[u16] = &[80, 443, 3389, 5985, 5986, 8080];

    let lower_name = process_name.to_lowercase();
    if SUSPICIOUS_PROCESSES.iter().any(|&p| lower_name.contains(p)) {
        return true;
    }
    if !COMMON_PORTS.contains(&sport) && !COMMON_PORTS.contains(&dport) {
        if sport < 49152 && dport < 49152 {
            return true;
        }
    }
    false
}

fn handle_udp_event(
    pid: u32,
    process_name: &str,
    saddr: &str,
    sport: u16,
    daddr: &str,
    dport: u16,
    network_type: &str,
    event_id: u16,
) {
    if network_type == "Loopback" {
        return;
    }

    // DNS
    if dport == 53 {
        let sig = format!("{}->DNS", pid);
        if let Ok(mut dns_cache) = DNS_CACHE.lock() {
            if dns_cache.contains(&sig) {
                return;
            }
            dns_cache.insert(sig);
            if dns_cache.len() > 100 {
                dns_cache.clear();
            }
        }
        return;
    }

    // Multicast/broadcast discovery protocols (SSDP, mDNS, etc.)
    if daddr.starts_with("239.") || daddr.starts_with("224.") ||
       daddr == "255.255.255.255" || dport == 1900 || dport == 5353 {
        let sig = format!("{}-multicast", pid);
        if let Ok(mut dns_cache) = DNS_CACHE.lock() {
            if !dns_cache.contains(&sig) {
                dns_cache.insert(sig);
            }
        }
        return;
    }

    // QUIC / HTTP3 (UDP/443 external)
    if dport == 443 && network_type == "External" {
        let sig = format!("{}->{}:{}", pid, daddr, dport);
        let mut should_log = false;
        if let Ok(mut quic_conns) = QUIC_CONNECTIONS.lock() {
            if !quic_conns.contains(&sig) {
                quic_conns.insert(sig);
                should_log = true;
                if quic_conns.len() > 1000 {
                    quic_conns.clear();
                }
            }
        }

        if should_log {

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
}

fn classify_network_connection(saddr: &str, daddr: &str) -> &'static str {
    // Loopback
    if saddr.starts_with("127.") || daddr.starts_with("127.") ||
       saddr == "::1" || daddr == "::1" ||
       saddr == "0:0:0:0:0:0:0:1" || daddr == "0:0:0:0:0:0:0:1" {
        return "Loopback";
    }
    // Multicast / broadcast
    if saddr.starts_with("224.") || saddr.starts_with("239.") || saddr == "255.255.255.255" ||
       daddr.starts_with("224.") || daddr.starts_with("239.") || daddr == "255.255.255.255" ||
       saddr.starts_with("ff") || daddr.starts_with("ff") {
        return "Multicast";
    }
    // Local network
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
                if let Some(second_dot) = addr[first_dot + 1..].find('.') {
                    let second_octet = &addr[first_dot + 1..first_dot + 1 + second_dot];
                    if let Ok(num) = second_octet.parse::<u8>() {
                        return num >= 16 && num <= 31;
                    }
                }
            }
            Ok(192) => return addr[first_dot + 1..].starts_with("168."),
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

unsafe fn parse_tcpip_event(
    user_data: *const std::ffi::c_void,
    data_len: usize,
) -> (String, String, u16, u16, bool) {
    if data_len >= std::mem::size_of::<TcpIpV4Event>() {
        let event = &*(user_data as *const TcpIpV4Event);
        let saddr_bytes = u32::from_be(event.saddr).to_be_bytes();
        let daddr_bytes = u32::from_be(event.daddr).to_be_bytes();
        let saddr = format!("{}.{}.{}.{}", saddr_bytes[0], saddr_bytes[1], saddr_bytes[2], saddr_bytes[3]);
        let daddr = format!("{}.{}.{}.{}", daddr_bytes[0], daddr_bytes[1], daddr_bytes[2], daddr_bytes[3]);
        return (saddr, daddr, u16::from_be(event.sport), u16::from_be(event.dport), false);
    }

    if data_len >= std::mem::size_of::<TcpIpV6Event>() {
        let event = &*(user_data as *const TcpIpV6Event);
        return (
            format_ipv6(&event.saddr),
            format_ipv6(&event.daddr),
            u16::from_be(event.sport),
            u16::from_be(event.dport),
            true,
        );
    }

    (String::new(), String::new(), 0, 0, false)
}

fn format_ipv6(bytes: &[u8; 16]) -> String {
    bytes.chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join(":")
}