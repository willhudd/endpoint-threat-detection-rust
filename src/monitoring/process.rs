use crate::events::{BaseEvent, EventType};
use crate::events::process::ProcessEvent;
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use crate::utils::common::{
    get_process_name_cached, cache_process_start, is_common_short_lived_process,
    is_system_process, cleanup_tracking_data, GLOBAL_SENDER,
};
use windows::Win32::System::Diagnostics::Etw::*;
use windows::core::PWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;

const WNODE_FLAG_TRACED_GUID: u32 = 0x00020000;
const EVENT_TRACE_FLAG_PROCESS: u32 = 0x00000001;

pub fn start_process_monitor(
    tx: Sender<BaseEvent>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        run_process_monitor(tx, shutdown);
    })
}

pub fn run_process_monitor(
    tx: Sender<BaseEvent>,
    shutdown: Arc<AtomicBool>,
) {
    unsafe {
        {
            let mut guard = GLOBAL_SENDER.lock().unwrap();
            *guard = Some(Arc::new(tx.clone()));
        }

        // Stop existing kernel logger session before starting a new one
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
            log::info!("Stopped Existing Process Monitor Session");
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
        let status = StartTraceW(
            &mut session_handle,
            KERNEL_LOGGER_NAMEW,
            props
        );

        if status != ERROR_SUCCESS {
            log::error!("Process Monitor StartTraceW Failed: 0x{:08X}", status.0);
            match status.0 {
                0x000000B7 => log::error!("Process Monitor already running"),
                0x00000005 => log::error!("Access denied - run as Administrator"),
                _ => {}
            }
            let mut guard = GLOBAL_SENDER.lock().unwrap();
            *guard = None;
            return;
        }
        log::info!("✅ Process Monitor session started");

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

            if pid <= 4 {
                return;
            }

            let process_name = get_process_name_cached(pid);

            if is_system_process(&process_name) {
                return;
            }

            let base = match opcode {
                1 => {
                    cache_process_start(
                        pid,
                        0,
                        &process_name,
                        None
                    );

                    log_process_event(
                        &process_name,
                        pid,
                        "Process Started"
                    );

                    let event = ProcessEvent::new_start(
                        pid,
                        0,
                        process_name.clone()
                    );

                    BaseEvent::new(EventType::ProcessStart(event))
                }

                2 => {
                    if !is_common_short_lived_process(&process_name) {
                        log_process_event(&process_name,
                            pid,
                            "Process Ended"
                        );
                    }

                    let event = ProcessEvent::new_end(pid, process_name.clone(), None);
                    BaseEvent::new(EventType::ProcessEnd(event))
                }

                _ => return,
            };

            if let Ok(guard) = GLOBAL_SENDER.lock() {
                if let Some(sender) = guard.as_ref() {
                    let _ = sender.send(base);
                }
            }
        }

        logfile.Anonymous2.EventRecordCallback = Some(event_callback);

        let trace_handle = OpenTraceW(&mut logfile);
        if trace_handle.Value == u64::MAX {
            log::error!("Process Monitor OpenTraceW Failed");
            let _ = ControlTraceW(
                session_handle,
                KERNEL_LOGGER_NAMEW,
                props,
                EVENT_TRACE_CONTROL_STOP
            );
            let mut guard = GLOBAL_SENDER.lock().unwrap();
            *guard = None;
            return;
        }
        log::info!("✅ Process Monitor OpenTraceW Opened");

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
            KERNEL_LOGGER_NAMEW,
            props,
            EVENT_TRACE_CONTROL_STOP
        );
        let _ = etw_thread.join();

        {
            let mut guard = GLOBAL_SENDER.lock().unwrap();
            *guard = None;
        }
        log::info!("✅ Process Monitor session stopped");
    }
}

fn log_process_event(
    process_name: &str,
    pid: u32,
    event_type: &str,
) {
    log::info!(
        "\n\
        ┌─ {} ───────────────────────────────────────────\n\
        │ Process = {}\n\
        │ PID     = {}\n\
        └────────────────────────────────────────────────",
        event_type,
        process_name,
        pid
    );
}