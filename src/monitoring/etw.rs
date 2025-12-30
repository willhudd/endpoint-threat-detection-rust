use crate::events::{BaseEvent, EventType};
use crate::events::process::ProcessEvent;
use crate::events::network::NetworkEvent;
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::error::Error;

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

// Global sender storage with thread-safe access
lazy_static::lazy_static! {
    static ref GLOBAL_SENDER: Mutex<Option<Arc<Sender<BaseEvent>>>> = Mutex::new(None);
}

// Kernel ETW constants (not all exported by windows crate)
const WNODE_FLAG_TRACED_GUID: u32 = 0x00020000;
const EVENT_TRACE_FLAG_PROCESS: u32 = 0x00000001;
const EVENT_TRACE_FLAG_NETWORK_TCPIP: u32 = 0x00000100;
const EVENT_TRACE_FLAG_REGISTRY: u32 = 0x00000004;
const EVENT_TRACE_FLAG_FILE_IO: u32 = 0x02000000;

pub fn start_kernel_monitor(
    tx: Sender<BaseEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, Box<dyn Error>> {
    let handle = std::thread::spawn(move || {
        unsafe {
            // Store sender in global for callback access
            {
                let mut guard = GLOBAL_SENDER.lock().unwrap();
                *guard = Some(Arc::new(tx.clone()));
            }

            log::info!("Attempting to start kernel ETW session...");

            // First, stop any existing kernel logger session (like in working version)
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

            // Create trace session with kernel logger (like in working version)
            let mut buffer = vec![0u8; std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024];
            let props = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

            (*props).Wnode.BufferSize = buffer.len() as u32;
            (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props).Wnode.Guid = SystemTraceControlGuid;
            (*props).Wnode.ClientContext = 1; // QPC clock
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).EnableFlags = EVENT_TRACE_FLAG(EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_NETWORK_TCPIP);
            (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

            let mut session_handle = CONTROLTRACE_HANDLE::default();

            let status = StartTraceW(
                &mut session_handle,
                KERNEL_LOGGER_NAMEW,
                props,
            );

            if status != ERROR_SUCCESS {
                log::error!("StartTraceW failed for kernel logger: 0x{:08X}", status.0);
                match status.0 {
                    0x000000B7 => {
                        log::error!("Kernel logger is already running");
                        log::info!("Trying to open existing trace...");
                    }
                    0x00000005 => {
                        log::error!("Access denied - make sure you're running as Administrator");
                    }
                    _ => {
                        log::error!("Unknown error occurred");
                    }
                }
                
                // Try to open existing trace anyway
                log::info!("Attempting to open existing kernel trace...");
            } else {
                log::info!("✅ Kernel ETW session started successfully");
            }

            // Open trace for real-time processing
            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName = windows::core::PWSTR(KERNEL_LOGGER_NAMEW.as_ptr() as *mut u16);
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;

            // Define callback - MUST be unsafe because it dereferences raw pointers
            unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
                if record.is_null() {
                    return;
                }

                // SAFETY: We've checked that record is not null
                let rec = unsafe { &*record };
                let header = &rec.EventHeader;
                let opcode = header.EventDescriptor.Opcode;
                let pid = header.ProcessId;

                if pid <= 4 || pid == 0 {
                    return;
                }

                // Get process name from PID
                let process_name = resolve_process_name(pid).unwrap_or_else(|| {
                    // Fallback: try to extract from UserData like in working version
                    if rec.UserDataLength > 0 && !rec.UserData.is_null() {
                        extract_process_name_from_userdata(rec.UserData, rec.UserDataLength as usize)
                    } else {
                        String::from("Unknown")
                    }
                });

                if 
                    process_name.to_lowercase().contains("svchost") || 
                    process_name.to_lowercase().contains("system") ||
                    process_name.to_lowercase().contains("csrss") ||
                    process_name.to_lowercase().contains("wininit") ||
                    process_name.to_lowercase().contains("services")
                {
                    return;
                }

                let event_result = match opcode {
                    1 => {
                        // Process Start
                        log::debug!("ETW Process start PID={} name={}", pid, process_name);
                        let event = ProcessEvent::new_start(pid, 0, process_name.clone());
                        Some(BaseEvent::new(EventType::ProcessStart(event)))
                    }
                    2 => {
                        // Process End
                        log::debug!("ETW Process end PID={}", pid);
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
                log::error!("OpenTraceW failed for kernel logger");
                let _ = ControlTraceW(
                    session_handle,
                    KERNEL_LOGGER_NAMEW,
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
                {
                    let mut guard = GLOBAL_SENDER.lock().unwrap();
                    *guard = None;
                }
                return;
            }

            log::info!("✅ Kernel ETW trace opened successfully");

            // Run ProcessTrace in a separate thread
            let process_trace_handle = trace_handle;
            let process_thread = std::thread::spawn(move || {
                unsafe {
                    let _ = ProcessTrace(&[process_trace_handle], None, None);
                }
            });

            log::info!("✅ Kernel ETW trace processing started");

            // Wait for shutdown signal
            while shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }

            log::info!("🛑 Stopping kernel ETW session...");

            // Close trace
            let _ = CloseTrace(trace_handle);
            
            // Stop the session
            let _ = ControlTraceW(
                session_handle,
                KERNEL_LOGGER_NAMEW,
                props,
                EVENT_TRACE_CONTROL_STOP,
            );

            // Wait for process thread to finish
            let _ = process_thread.join();

            // Clear sender
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
            // Store sender in global for callback access
            {
                let mut guard = GLOBAL_SENDER.lock().unwrap();
                *guard = Some(Arc::new(tx.clone()));
            }

            log::info!("Starting TCP/IP ETW listener...");

            // Create a user-mode session for TCP/IP
            let session_name = widestring::U16CString::from_str("EDR_TCPIP_LOGGER").unwrap();
            
            // First try to stop existing session
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

            // Create session
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
                log::error!("StartTraceW failed for TCPIP session: 0x{:08X}", status.0);
                {
                    let mut guard = GLOBAL_SENDER.lock().unwrap();
                    *guard = None;
                }
                return;
            }

            log::info!("✅ TCP/IP ETW session started successfully");

            // Enable the TCPIP provider
            let provider_guid = GUID::from_u128(TCPIP_PROVIDER_GUID);
            
            let enable_result = EnableTraceEx2(
                session_handle,
                &provider_guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0 as u32,
                5, // TRACE_LEVEL_VERBOSE
                0xFFFFFFFF, // Match all keywords
                0,
                0,
                None,
            );

            if enable_result != ERROR_SUCCESS {
                log::warn!("EnableTraceEx2 failed for TCPIP provider: 0x{:08X}", enable_result.0);
                log::info!("Will try to process trace anyway...");
            } else {
                log::info!("✅ TCP/IP provider enabled successfully");
            }

            // Open trace
            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName = windows::core::PWSTR(session_name.as_ptr() as *mut u16);
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;

            // TCP/IP event callback - MUST be unsafe
            unsafe extern "system" fn tcpip_callback(record: *mut EVENT_RECORD) {
                if record.is_null() {
                    return;
                }

                // SAFETY: We've checked that record is not null
                let rec = unsafe { &*record };
                let header = &rec.EventHeader;
                let pid = header.ProcessId;

                if pid <= 4 || pid == 0 {
                    return;
                }
                
                log::debug!("TCP/IP event received for PID: {}", pid);

                let process_name = resolve_process_name(pid).unwrap_or_else(|| String::from("Unknown"));
                if process_name.to_lowercase().contains("svchost") || 
                process_name.to_lowercase().contains("system") ||
                process_name.to_lowercase().contains("csrss") ||
                process_name.to_lowercase().contains("wininit") ||
                process_name.to_lowercase().contains("services") {
                    return;
                }

                // Create a NetworkEvent
                let net = NetworkEvent::new(
                    pid,
                    process_name,
                    crate::events::network::NetworkDirection::Outbound,
                    crate::events::network::Protocol::TCP,
                    String::from("0.0.0.0"),
                    0,
                    String::from("0.0.0.0"),
                    0,
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
                log::error!("OpenTraceW failed for TCPIP session");
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

            log::info!("✅ TCP/IP ETW trace opened successfully");

            // Run ProcessTrace in a separate thread
            let process_trace_handle = trace_handle;
            let process_thread = std::thread::spawn(move || {
                unsafe {
                    let _ = ProcessTrace(&[process_trace_handle], None, None);
                }
            });

            // Wait for shutdown signal
            while shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }

            log::info!("🛑 Stopping TCP/IP ETW session...");

            // Close trace
            let _ = CloseTrace(trace_handle);
            
            // Stop the session
            let _ = ControlTraceW(
                session_handle,
                windows::core::PWSTR(session_name.as_ptr() as *mut u16),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );

            // Wait for process thread to finish
            let _ = process_thread.join();

            // Clear sender
            {
                let mut guard = GLOBAL_SENDER.lock().unwrap();
                *guard = None;
            }

            log::info!("✅ TCP/IP ETW session stopped");
        }
    });

    Ok(handle)
}

fn resolve_process_name(pid: u32) -> Option<String> {
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

// Helper function to extract process name from ETW event UserData
fn extract_process_name_from_userdata(user_data: *const std::ffi::c_void, data_len: usize) -> String {
    unsafe {
        let user_data = user_data as *const u8;
        
        let mut found_name = String::from("Unknown");
        let mut i = 0;
        
        // Scan for potential wide string (like in working version)
        while i + 4 < data_len {
            let ptr = user_data.add(i) as *const u16;
            let mut temp_len = 0;
            
            // Check if this looks like the start of a path/executable string
            while temp_len < 260 && (i + temp_len * 2 + 2) <= data_len {
                let ch = *ptr.add(temp_len);
                if ch == 0 {
                    break;
                }
                // Allow printable ASCII, backslash, colon, quotes
                if (ch >= 32 && ch < 127) || ch == b'\\' as u16 {
                    temp_len += 1;
                } else {
                    break;
                }
            }
            
            // If we found a string with at least 4 chars
            if temp_len >= 4 {
                let slice = std::slice::from_raw_parts(ptr, temp_len);
                let mut candidate = String::from_utf16_lossy(slice);
                
                // Check if it looks like a valid path
                if candidate.contains(".exe") || candidate.contains("\\") {
                    // Clean up the string
                    candidate = candidate.trim().to_string();
                    
                    // Remove quotes if present
                    if candidate.starts_with('"') && candidate.contains('"') {
                        if let Some(end_quote) = candidate[1..].find('"') {
                            candidate = candidate[1..=end_quote].to_string();
                        }
                    }
                    
                    // Extract just the executable name from full path
                    if let Some(last_slash) = candidate.rfind('\\') {
                        found_name = candidate[last_slash + 1..].split_whitespace().next()
                            .unwrap_or(&candidate).to_string();
                    } else {
                        found_name = candidate.split_whitespace().next()
                            .unwrap_or(&candidate).to_string();
                    }
                    break;
                }
            }
            
            i += 2; // Move by 2 bytes (one wide char)
        }
        
        found_name
    }
}