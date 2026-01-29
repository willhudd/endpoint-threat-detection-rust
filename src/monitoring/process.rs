use crate::events::{BaseEvent, EventType};
use crate::events::process::ProcessEvent;
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::error::Error;
use crate::monitoring::common::*;
use windows::Win32::System::Diagnostics::Etw::*;
use windows::core::PWSTR;
use windows::{
    Win32::{
        Foundation::{ERROR_SUCCESS}
    },
};

// Kernel ETW constants
const WNODE_FLAG_TRACED_GUID: u32 = 0x00020000;
const EVENT_TRACE_FLAG_PROCESS: u32 = 0x00000001;

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
            (*props).EnableFlags = EVENT_TRACE_FLAG(EVENT_TRACE_FLAG_PROCESS);
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
            logfile.LoggerName = PWSTR(KERNEL_LOGGER_NAMEW.as_ptr() as *mut u16);
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
                   lower.contains("services") || lower.contains("endpoint-threat-detection") {
                    return;
                }

                let event_result = match opcode {
                    1 => {
                        // Process start - CACHE IMMEDIATELY
                        // ETW doesn't reliably provide PPID in UserData for Process events
                        // We'll get it later via WMI/CIM if needed
                        let parent_pid = 0;
                        
                        cache_process_start(pid, parent_pid, &process_name, None);
                        
                        log::info!(
                            "\n\
                             ┌─ Process Started ─────────────────────────────\n\
                             │ Name = {}\n\
                             │ PID  = {}\n\
                             └───────────────────────────────────────────────",
                            process_name, pid
                        );
                        
                        let event = ProcessEvent::new_start(pid, parent_pid, process_name.clone());
                        Some(BaseEvent::new(EventType::ProcessStart(event)))
                    }
                    2 => {
                        if !is_common_short_lived_process(&process_name) {
                            log::info!(
                                "\n\
                                 ┌─ Process Ended ───────────────────────────────\n\
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
                
                // Run cleanup every ~30 seconds (150 iterations * 200ms)
                cleanup_counter += 1;
                if cleanup_counter >= 150 {
                    cleanup_tracking_data();
                    cleanup_counter = 0;
                }
            }

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