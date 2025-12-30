use crate::events::{network::NetworkEvent, BaseEvent, EventType};
use crate::config::rules::Config;
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::ffi::c_void;
use std::error::Error;

// Constants for address family
const AF_INET: u32 = 2;  // IPv4

pub fn start_network_monitor(
    tx: Sender<BaseEvent>,
    config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        log::info!("Network monitor starting...");
        run_network_monitor(tx, config, shutdown);
        log::info!("Network monitor stopped");
    })
}

pub fn run_network_monitor(
    tx: Sender<BaseEvent>,
    _config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
) {
    // Try to start an ETW-based listener first. If we can't, fall back to polling
    // (shorter interval to improve chances of catching short-lived connections).
    match start_etw_listener(tx.clone(), shutdown.clone()) {
        Ok(handle) => {
            log::info!("ETW network listener started");
            // Wait for shutdown signal while ETW is running
            while !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
            }
            // Join the ETW thread when shutdown is requested
            let _ = handle.join();
            log::info!("ETW network listener stopped");
            return;
        }
        Err(e) => {
            log::error!("ETW listener failed: {}", e);
            // Try one more time after delay
            log::info!("Retrying ETW listener in 2 seconds...");
            std::thread::sleep(Duration::from_secs(2));
            
            match start_etw_listener(tx.clone(), shutdown.clone()) {
                Ok(handle) => {
                    log::info!("ETW network listener started on retry");
                    // Wait for shutdown
                    while !shutdown.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    let _ = handle.join();
                    log::info!("ETW network listener stopped");
                    return;
                }
                Err(e) => {
                    log::error!("ETW listener unavailable after retry; exiting: {}", e);
                    return;
                }
            }
        }
    }
}

// Attempt to start an ETW listener for Microsoft-Windows-TCPIP.
// Returns a JoinHandle when successfully started. If ETW can't be started
// (platform limitations, permissions, or missing implementation), an Err is returned
// and the caller should fall back to polling.
fn start_etw_listener(
    tx: Sender<BaseEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, Box<dyn Error>> {
    // Delegate to centralized ETW manager to start a TCP/IP listener.
    match crate::monitoring::etw::start_tcpip_listener(tx, shutdown) {
        Ok(handle) => Ok(handle),
        Err(e) => Err(e),
    }
}

fn scan_network_connections(
    tx: &Sender<BaseEvent>,
    previous_connections: &mut std::collections::HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Get TCP connections
    let tcp_connections = get_tcp_connections()?;
    // Get UDP connections
    let udp_connections = get_udp_connections()?;

    // Process new connections
    let all_connections: Vec<(String, u32, String, u16, String, u16, String)> = 
        tcp_connections.into_iter().chain(udp_connections).collect();

    let mut current_connections = std::collections::HashSet::new();

    for (key, pid, process_name, local_port, local_addr, remote_port, remote_addr) in all_connections {
        current_connections.insert(key.clone());

        if !previous_connections.contains(&key) {
            // New connection detected
            log::debug!("New network connection: {}:{} -> {}:{} (PID: {}, Process: {})", 
                local_addr, local_port, remote_addr, remote_port, pid, process_name);
            
            let network_event = NetworkEvent::new(
                pid,
                process_name,
                crate::events::network::NetworkDirection::Outbound,
                crate::events::network::Protocol::TCP,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
            );

            let base_event = BaseEvent::new(EventType::NetworkConnection(network_event));
            let _ = tx.send(base_event);
        }
    }

    *previous_connections = current_connections;
    Ok(())
}

fn get_tcp_connections() -> Result<Vec<(String, u32, String, u16, String, u16, String)>, windows::core::Error> {
    unsafe {
        let mut buffer_size: u32 = 0;
        let mut ret = windows::Win32::NetworkManagement::IpHelper::GetExtendedTcpTable(
            None,
            &mut buffer_size,
            false,
            AF_INET,
            windows::Win32::NetworkManagement::IpHelper::TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != 0 && ret != windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER.0 as u32 {
            return Err(windows::core::Error::from_win32());
        }

        let mut buffer = vec![0u8; buffer_size as usize];
        let table_ptr = buffer.as_mut_ptr() as *mut c_void;

        ret = windows::Win32::NetworkManagement::IpHelper::GetExtendedTcpTable(
            Some(table_ptr),
            &mut buffer_size,
            false,
            AF_INET,
            windows::Win32::NetworkManagement::IpHelper::TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != 0 {
            return Err(windows::core::Error::from_win32());
        }

        let table = table_ptr as *mut windows::Win32::NetworkManagement::IpHelper::MIB_TCPTABLE_OWNER_PID;
        let table_ref = &*table;
        let mut connections = Vec::new();

        // SAFE: Use proper iteration
        let entries_ptr = &table_ref.table as *const _ as *const windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID;
        
        for i in 0..table_ref.dwNumEntries {
            let row_ptr = entries_ptr.offset(i as isize);
            let row = &*row_ptr;
            
            let local_addr = ip_to_string(row.dwLocalAddr);
            let remote_addr = ip_to_string(row.dwRemoteAddr);
            
            // Convert port from network byte order
            let local_port = ((row.dwLocalPort >> 8) & 0xFF) as u16 | ((row.dwLocalPort & 0xFF) as u16) << 8;
            let remote_port = ((row.dwRemotePort >> 8) & 0xFF) as u16 | ((row.dwRemotePort & 0xFF) as u16) << 8;
            
            let pid = row.dwOwningPid;

            let process_name = get_process_name(pid).unwrap_or_else(|| String::from("Unknown"));

            let key = format!("{}-{}-{}-{}-{}", pid, local_addr, local_port, remote_addr, remote_port);
            
            connections.push((key, pid, process_name, local_port, local_addr, remote_port, remote_addr));
        }

        Ok(connections)
    }
}

fn get_udp_connections() -> Result<Vec<(String, u32, String, u16, String, u16, String)>, windows::core::Error> {
    unsafe {
        let mut buffer_size: u32 = 0;
        let mut ret = windows::Win32::NetworkManagement::IpHelper::GetExtendedUdpTable(
            None,
            &mut buffer_size,
            false,
            AF_INET,
            windows::Win32::NetworkManagement::IpHelper::UDP_TABLE_OWNER_PID,
            0,
        );

        if ret != 0 && ret != windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER.0 as u32 {
            return Err(windows::core::Error::from_win32());
        }

        let mut buffer = vec![0u8; buffer_size as usize];
        let table_ptr = buffer.as_mut_ptr() as *mut c_void;

        ret = windows::Win32::NetworkManagement::IpHelper::GetExtendedUdpTable(
            Some(table_ptr),
            &mut buffer_size,
            false,
            AF_INET,
            windows::Win32::NetworkManagement::IpHelper::UDP_TABLE_OWNER_PID,
            0,
        );

        if ret != 0 {
            return Err(windows::core::Error::from_win32());
        }

        let table = table_ptr as *mut windows::Win32::NetworkManagement::IpHelper::MIB_UDPTABLE_OWNER_PID;
        let table_ref = &*table;
        let mut connections = Vec::new();

        // SAFE: Use proper iteration
        let entries_ptr = &table_ref.table as *const _ as *const windows::Win32::NetworkManagement::IpHelper::MIB_UDPROW_OWNER_PID;
        
        for i in 0..table_ref.dwNumEntries {
            let row_ptr = entries_ptr.offset(i as isize);
            let row = &*row_ptr;
            
            let local_addr = ip_to_string(row.dwLocalAddr);
            
            // Convert port from network byte order
            let local_port = ((row.dwLocalPort >> 8) & 0xFF) as u16 | ((row.dwLocalPort & 0xFF) as u16) << 8;
            
            let pid = row.dwOwningPid;

            let process_name = get_process_name(pid).unwrap_or_else(|| String::from("Unknown"));

            let key = format!("{}-{}-{}", pid, local_addr, local_port);
            
            connections.push((key, pid, process_name, local_port, local_addr, 0, String::new()));
        }

        Ok(connections)
    }
}

fn ip_to_string(ip: u32) -> String {
    let octets = ip.to_le_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

fn get_process_name(pid: u32) -> Option<String> {
    use windows::{
        Win32::{
            Foundation::{CloseHandle, MAX_PATH},
            System::ProcessStatus::GetModuleFileNameExW,
            System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION},
        },
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if handle.is_err() {
            return None;
        }

        let handle = handle.unwrap();
        let mut buffer = [0u16; MAX_PATH as usize];
        let len = GetModuleFileNameExW(Some(handle), None, &mut buffer);

        let _ = CloseHandle(handle);

        if len > 0 {
            let name = String::from_utf16_lossy(&buffer[..len as usize]);
            Some(
                std::path::Path::new(&name)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("Unknown")
                    .to_string(),
            )
        } else {
            None
        }
    }
}