use crate::events::{BaseEvent, EventType};
use crate::events::process::ProcessEvent;
use crate::events::network::NetworkEvent;
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::error::Error;
use std::collections::{HashSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use windows::core::GUID;
use windows::{
    Win32::{
        Foundation::{ERROR_SUCCESS, CloseHandle},
        System::Diagnostics::Etw::*,
        System::Threading::PROCESS_QUERY_INFORMATION,
        System::ProcessStatus::GetModuleFileNameExW,
        System::Threading::OpenProcess,
    },
};

use std::sync::Mutex;

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

// kernel ETW constants
const WNODE_FLAG_TRACED_GUID: u32 = 0x00020000;
const EVENT_TRACE_FLAG_PROCESS: u32 = 0x00000001;
const EVENT_TRACE_FLAG_NETWORK_TCPIP: u32 = 0x00000100;

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

#[derive(Clone, Debug)]
struct ProcessInfo {
    name: String,
    cached_at: u64,
    parent_pid: u32,
    command_line: Option<String>,
}

#[derive(Clone, Debug)]
struct ConnectionAttempt {
    timestamp: u64,
    dest_addr: String,
    dest_port: u16,
    network_type: String,
}

// global storage
lazy_static::lazy_static! {
    static ref GLOBAL_SENDER: Mutex<Option<Arc<Sender<BaseEvent>>>> = Mutex::new(None);
    static ref RECENT_CONNECTIONS: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    static ref PROCESS_NAME_CACHE: Mutex<HashMap<u32, ProcessInfo>> = Mutex::new(HashMap::new());
    static ref CONNECTION_TRACKER: Mutex<HashMap<u32, Vec<ConnectionAttempt>>> = Mutex::new(HashMap::new());
    static ref RECENT_PROCESS_STARTS: Mutex<HashMap<u32, ProcessInfo>> = Mutex::new(HashMap::new());
    static ref QUIC_CONNECTIONS: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    static ref DNS_CACHE: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// process name resolution with fallback priority
fn get_process_name_cached(pid: u32) -> String {
    let now = get_timestamp();
    
    // check recent process starts FIRST (catches fast-exiting Chrome processes)
    if let Ok(recent) = RECENT_PROCESS_STARTS.lock() {
        if let Some(info) = recent.get(&pid) {
            // extended validity window for recent starts (60 seconds)
            if now - info.cached_at < 60 {
                return info.name.clone();
            }
        }
    }
    
    // check main cache
    if let Ok(cache) = PROCESS_NAME_CACHE.lock() {
        if let Some(info) = cache.get(&pid) {
            if now - info.cached_at < 60 {
                return info.name.clone();
            }
        }
    }
    
    // try to resolve NOW (process might still be running)
    if let Some(name) = resolve_process_name(pid) {
        // cache in BOTH places for redundancy
        if let Ok(mut cache) = PROCESS_NAME_CACHE.lock() {
            cache.insert(pid, ProcessInfo {
                name: name.clone(),
                cached_at: now,
                parent_pid: 0,
                command_line: None,
            });
        }
        if let Ok(mut recent) = RECENT_PROCESS_STARTS.lock() {
            recent.insert(pid, ProcessInfo {
                name: name.clone(),
                cached_at: now,
                parent_pid: 0,
                command_line: None,
            });
        }
        return name;
    }
    
    // last resort - check if we have ANY cached info
    if let Ok(recent) = RECENT_PROCESS_STARTS.lock() {
        if let Some(info) = recent.get(&pid) {
            // use even expired cache for fast-exiting processes
            log::debug!("Using expired cache for PID {} (age: {}s)", pid, now - info.cached_at);
            return info.name.clone();
        }
    }
    
    if let Ok(cache) = PROCESS_NAME_CACHE.lock() {
        if let Some(info) = cache.get(&pid) {
            log::debug!("Using expired main cache for PID {} (age: {}s)", pid, now - info.cached_at);
            return info.name.clone();
        }
    }
    
    String::from("Unknown")
}

// store process info when process starts with better caching
fn cache_process_start(pid: u32, parent_pid: u32, process_name: &str, command_line: Option<String>) {
    let now = get_timestamp();
    let info = ProcessInfo {
        name: process_name.to_string(),
        cached_at: now,
        parent_pid,
        command_line: command_line.clone(),
    };
    
    // store in BOTH caches immediately
    if let Ok(mut recent) = RECENT_PROCESS_STARTS.lock() {
        recent.insert(pid, info.clone());
        
        // cleanup old entries (keep last 2000)
        if recent.len() > 2000 {
            recent.retain(|_, info| now - info.cached_at < 120); // keep for 2 minutes
        }
    }
    
    if let Ok(mut cache) = PROCESS_NAME_CACHE.lock() {
        cache.insert(pid, info);
    }
}

fn create_connection_signature(pid: u32, saddr: &str, sport: u16, daddr: &str, dport: u16) -> String {
    format!("{}:{}->{}:{}", pid, saddr, daddr, dport)
}

// check if a process is a chrome subprocess by checking parent
fn is_chrome_subprocess(pid: u32, process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    
    // direct chrome indicators
    if lower.contains("chrome") {
        return true;
    }
    
    // check if parent is chrome
    if let Ok(cache) = PROCESS_NAME_CACHE.lock() {
        if let Some(info) = cache.get(&pid) {
            if info.parent_pid != 0 {
                if let Some(parent_info) = cache.get(&info.parent_pid) {
                    return parent_info.name.to_lowercase().contains("chrome");
                }
            }
        }
    }
    
    // check recent starts
    if let Ok(recent) = RECENT_PROCESS_STARTS.lock() {
        if let Some(info) = recent.get(&pid) {
            if info.parent_pid != 0 {
                if let Some(parent_info) = recent.get(&info.parent_pid) {
                    return parent_info.name.to_lowercase().contains("chrome");
                }
            }
        }
    }
    
    false
}

// better browser detection
fn is_browser_related_process(pid: u32, process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    
    // main browser executables
    let browsers = vec![
        "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", 
        "brave.exe", "vivaldi.exe", "iexplore.exe", "edge.exe"
    ];
    
    if browsers.iter().any(|&b| lower.contains(b)) {
        return true;
    }
    
    // check if it's a chrome subprocess
    if is_chrome_subprocess(pid, process_name) {
        return true;
    }
    
    // browser helper processes
    let helpers = vec![
        "gpu-process", "renderer", "utility", "network-service",
        "storage-service", "plugin", "extension", "web-helper",
        "browser_broker", "browser helper", "crashpad", "nacl",
    ];
    
    if helpers.iter().any(|&h| lower.contains(h)) {
        return true;
    }
    
    // chrome subprocess indicator
    if lower.contains("--type=") {
        return true;
    }
    
    false
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
    
    // skip browser loopback connections entirely (they're just IPC)
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
        
        // for Send/Recv, deduplicate
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
    let suspicious_processes = vec![
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe",
    ];
    
    let lower_name = process_name.to_lowercase();
    
    if suspicious_processes.iter().any(|&p| lower_name.contains(p)) {
        return true;
    }
    
    let common_ports = vec![80, 443, 3389, 5985, 5986, 8080];
    if !common_ports.contains(&sport) && !common_ports.contains(&dport) {
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
    
    let suspicious_names = vec![
        "powershell", "cmd", "wscript", "cscript", 
        "mshta", "rundll32", "regsvr32", "certutil"
    ];
    
    let lower_name = process_name.to_lowercase();
    if suspicious_names.iter().any(|&name| lower_name.contains(name)) {
        return true;
    }
    
    if network_type == "LocalNetwork" {
        return true;
    }
    
    false
}

fn is_common_short_lived_process(process_name: &str) -> bool {
    let common_short_lived = vec![
        "conhost.exe", "dllhost.exe", "runtimebroker.exe",
        "taskhostw.exe", "backgroundtaskhost.exe",
    ];
    
    let lower = process_name.to_lowercase();
    common_short_lived.iter().any(|&name| lower.contains(name))
}

pub fn cleanup_tracking_data() {
    let now = get_timestamp();
    
    // main cache: keep for 5 minutes
    if let Ok(mut cache) = PROCESS_NAME_CACHE.lock() {
        cache.retain(|_, info| {
            let age = now - info.cached_at;
            // keep chrome processes longer (10 minutes vs 5 minutes)
            if info.name.to_lowercase().contains("chrome") {
                age < 600
            } else {
                age < 300
            }
        });
    }
    
    // recent starts: keep for 2 minutes
    if let Ok(mut recent) = RECENT_PROCESS_STARTS.lock() {
        recent.retain(|_, info| {
            let age = now - info.cached_at;
            // keep chrome subprocesses longer (5 minutes vs 2 minutes)
            if info.name.to_lowercase().contains("chrome") {
                age < 300
            } else {
                age < 120
            }
        });
    }
    
    // connection tracker: keep for 10 minutes
    if let Ok(mut tracker) = CONNECTION_TRACKER.lock() {
        tracker.retain(|_, attempts| {
            attempts.retain(|a| now - a.timestamp < 600);
            !attempts.is_empty()
        });
    }
    
    // recent connections: clear when too large
    if let Ok(mut recent) = RECENT_CONNECTIONS.lock() {
        if recent.len() > 5000 {
            recent.clear();
        }
    }
}

pub fn start_kernel_monitor(
    tx: Sender<BaseEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, Box<dyn Error>> {
    let handle = std::thread::spawn(move || {
        unsafe {
            {
                let mut guard = GLOBAL_SENDER.lock().unwrap();
                *guard = Some(Arc::new(tx.clone()));
            }

            log::info!("Attempting to start kernel ETW session...");

            let mut stop_buffer = vec![0u8; std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024];
            let stop_props = stop_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
            (*stop_props).Wnode.BufferSize = stop_buffer.len() as u32;
            
            let stop_result = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                KERNEL_LOGGER_NAMEW,
                stop_props,
                EVENT_TRACE_CONTROL_STOP,
            );
            
            if stop_result == ERROR_SUCCESS {
                log::info!("Stopped existing kernel logger session");
            }

            let mut buffer = vec![0u8; std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024];
            let props = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

            (*props).Wnode.BufferSize = buffer.len() as u32;
            (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props).Wnode.Guid = SystemTraceControlGuid;
            (*props).Wnode.ClientContext = 1;
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).EnableFlags = EVENT_TRACE_FLAG(EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_NETWORK_TCPIP);
            (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

            let mut session_handle = CONTROLTRACE_HANDLE::default();

            let status = StartTraceW(&mut session_handle, KERNEL_LOGGER_NAMEW, props);

            if status != ERROR_SUCCESS {
                log::error!("StartTraceW failed: 0x{:08X}", status.0);
                if status.0 == 0x000000B7 {
                    log::error!("Kernel logger already running");
                } else if status.0 == 0x00000005 {
                    log::error!("Access denied - run as Administrator");
                }
            } else {
                log::info!("✅ Kernel ETW session started");
            }

            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName = windows::core::PWSTR(KERNEL_LOGGER_NAMEW.as_ptr() as *mut u16);
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;

            unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
                if record.is_null() {
                    return;
                }

                let rec = unsafe { &*record };
                let header = &rec.EventHeader;
                let opcode = header.EventDescriptor.Opcode;
                let pid = header.ProcessId;

                if pid <= 4 || pid == 0 {
                    return;
                }

                let process_name = get_process_name_cached(pid);

                let lower = process_name.to_lowercase();
                if lower.contains("svchost") || lower.contains("system") ||
                   lower.contains("csrss") || lower.contains("wininit") ||
                   lower.contains("services") {
                    return;
                }

                let event_result = match opcode {
                    1 => {
                        // process start - CACHE IMMEDIATELY
                        let parent_pid = if rec.UserDataLength >= 4 && !rec.UserData.is_null() {
                            unsafe { *(rec.UserData as *const u32) }
                        } else {
                            0
                        };
                        
                        cache_process_start(pid, parent_pid, &process_name, None);
                        
                        log::info!(
                            "┌─ Process Started ─────────────────────────────\n\
                             │ Name = {}\n\
                             │ PID  = {}\n\
                             │ PPID = {}\n\
                             └───────────────────────────────────────────────",
                            process_name, pid, parent_pid
                        );
                        
                        let event = ProcessEvent::new_start(pid, parent_pid, process_name.clone());
                        Some(BaseEvent::new(EventType::ProcessStart(event)))
                    }
                    2 => {
                        if !is_common_short_lived_process(&process_name) {
                            log::info!(
                                "┌─ Process Ended ───────────────────────────────\n\
                                 │ Name = {}\n\
                                 │ PID  = {}\n\
                                 └───────────────────────────────────────────────",
                                process_name, pid
                            );
                        }
                        let event = ProcessEvent::new_end(pid, process_name.clone(), None);
                        Some(BaseEvent::new(EventType::ProcessEnd(event)))
                    }
                    _ => None,
                };

                if let Some(base_event) = event_result {
                    if let Ok(guard) = GLOBAL_SENDER.lock() {
                        if let Some(sender) = guard.as_ref() {
                            let _ = sender.send(base_event);
                        }
                    }
                }
            }

            logfile.Anonymous2.EventRecordCallback = Some(event_callback);

            let trace_handle = OpenTraceW(&mut logfile);
            if trace_handle.Value == u64::MAX {
                log::error!("OpenTraceW failed");
                let _ = ControlTraceW(session_handle, KERNEL_LOGGER_NAMEW, props, EVENT_TRACE_CONTROL_STOP);
                {
                    let mut guard = GLOBAL_SENDER.lock().unwrap();
                    *guard = None;
                }
                return;
            }

            log::info!("✅ Kernel ETW trace opened");

            let process_trace_handle = trace_handle;
            let process_thread = std::thread::spawn(move || {
                let _ = ProcessTrace(&[process_trace_handle], None, None);
            });

            log::info!("✅ Kernel ETW trace processing started");

            let mut cleanup_counter = 0;
            while shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(200));
                
                // run cleanup every ~30 seconds (150 iterations * 200ms)
                cleanup_counter += 1;
                if cleanup_counter >= 150 {
                    cleanup_tracking_data();
                    cleanup_counter = 0;
                }
            }

            log::info!("🛑 Stopping kernel ETW session...");

            let _ = CloseTrace(trace_handle);
            let _ = ControlTraceW(session_handle, KERNEL_LOGGER_NAMEW, props, EVENT_TRACE_CONTROL_STOP);
            let _ = process_thread.join();

            {
                let mut guard = GLOBAL_SENDER.lock().unwrap();
                *guard = None;
            }

            log::info!("✅ Kernel ETW session stopped");
        }
    });

    Ok(handle)
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

            log::info!("Starting TCP/IP ETW listener...");

            let session_name = widestring::U16CString::from_str("EDR_TCPIP_LOGGER").unwrap();
            
            let mut stop_buffer = vec![0u8; std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024];
            let stop_props = stop_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
            (*stop_props).Wnode.BufferSize = stop_buffer.len() as u32;
            (*stop_props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            
            let stop_result = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                windows::core::PWSTR(session_name.as_ptr() as *mut u16),
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
                windows::core::PWSTR(session_name.as_ptr() as *mut u16),
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
            logfile.LoggerName = windows::core::PWSTR(session_name.as_ptr() as *mut u16);
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
                       lower.contains("services") {
                        return;
                    }
                }

                if rec.UserDataLength > 0 && !rec.UserData.is_null() {
                    let (saddr, daddr, sport, dport, is_ipv6) = match event_id {
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

                    // determine protocol type
                    let protocol = match event_id {
                        EVENT_ID_UDP_SEND | EVENT_ID_UDP_RECV => "UDP",
                        _ => "TCP",
                    };

                    let network_type = classify_network_connection(&saddr, &daddr);

                    // for UDP, track QUIC connections (HTTP/3 over UDP on port 443)
                    if protocol == "UDP" {
                        // filter out local UDP noise
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
                                log::debug!(
                                    "🔍 DNS: {} (PID:{}) querying {}",
                                    process_name, pid, daddr
                                );
                            }
                            return;
                        }

                        // filter out multicast/broadcast noise (SSDP, mDNS, etc.)
                        if daddr.starts_with("239.") || daddr.starts_with("224.") || 
                        daddr == "255.255.255.255" || dport == 1900 || dport == 5353 {
                            // these are legitimate discovery protocols but generate spam
                            // only log first occurrence per process
                            let multicast_sig = format!("{}-multicast", pid);
                            
                            if let Ok(mut dns_cache) = DNS_CACHE.lock() {
                                if !dns_cache.contains(&multicast_sig) {
                                    dns_cache.insert(multicast_sig);
                                    log::debug!(
                                        "📡 Multicast: {} (PID:{}) using {} on {}:{}",
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
                                    
                                    // limit cache size
                                    if quic_conns.len() > 1000 {
                                        quic_conns.clear();
                                    }
                                }
                            }
                            
                            if should_log {
                                log::info!(
                                    "🚀 QUIC/HTTP3: {} (PID:{}) -> {}:{} {}",
                                    process_name, pid, daddr, dport,
                                    identify_ip_owner(&daddr)
                                );
                                
                                // create network event for correlation
                                let net_direction = if event_id == EVENT_ID_UDP_SEND {
                                    crate::events::network::NetworkDirection::Outbound
                                } else {
                                    crate::events::network::NetworkDirection::Inbound
                                };

                                let net = NetworkEvent::new(
                                    pid, process_name.clone(), net_direction,
                                    crate::events::network::Protocol::UDP,
                                    saddr, sport, 
                                    daddr, dport,
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
                        
                        // other UDP - only log external
                        if network_type == "External" {
                            log::debug!(
                                "UDP: {} (PID:{}) {} -> {}:{} ({})",
                                process_name, pid, 
                                if event_id == EVENT_ID_UDP_SEND { "Send" } else { "Recv" },
                                daddr, dport, network_type
                            );
                        }
                        
                        return; // don't process UDP further
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
                    windows::core::PWSTR(session_name.as_ptr() as *mut u16),
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
                
                // run cleanup every 30 seconds
                cleanup_counter += 1;
                if cleanup_counter >= 150 {
                    cleanup_tracking_data();
                    cleanup_counter = 0;
                }
            }

            log::info!("🛑 Stopping TCP/IP ETW session...");

            let _ = CloseTrace(trace_handle);
            
            let _ = ControlTraceW(
                session_handle,
                windows::core::PWSTR(session_name.as_ptr() as *mut u16),
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

pub fn resolve_process_name(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if handle.is_err() {
            return None;
        }
        let h = handle.unwrap();
        let mut buffer = [0u16; 260];
        let len = GetModuleFileNameExW(Some(h), None, &mut buffer);
        let _ = CloseHandle(h);
        if len > 0 {
            let name = String::from_utf16_lossy(&buffer[..len as usize]);
            return std::path::Path::new(&name)
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());
        }
        None
    }
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
    
    if network_type == "External" {
        let protocol_type = if protocol == "UDP" { 
            identify_udp_service(dport) 
        } else { 
            "IPv4"
        };
        
        log::info!(
            "┌─ {}/IP Event{} ────────────────────────────────\n\
             │ Process      = {} (PID: {})\n\
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
    } else {
        log::debug!(
            "{}/IP{}: {} (PID:{}) {} -> {}:{} ({})",
            protocol,
            browser_tag,
            process_name,
            pid,
            direction,
            daddr,
            dport,
            network_type
        );
    }
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
            if port >= 443 && port <= 443 {
                "QUIC (HTTP/3)"
            } else {
                "UDP"
            }
        }
    }
}