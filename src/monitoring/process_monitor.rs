use crate::config::rules::Config;
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub fn start_process_monitor(
    tx: Sender<crate::events::BaseEvent>,
    _config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        log::info!("Starting process monitor (ETW kernel)...");
        match crate::monitoring::etw::start_kernel_monitor(tx, shutdown) {
            Ok(handle) => {
                let _ = handle.join();
                log::info!("Process monitor stopped");
            }
            Err(e) => {
                log::error!("Failed to start kernel ETW monitor: {}", e);
            }
        }
    })
}