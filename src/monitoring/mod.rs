pub mod correlation_engine;
pub mod common;
pub mod process;
pub mod network;

use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::config::rules::Config;
use std::time::Duration;

// Process monitoring wrapper
pub fn start_process_monitor(
    tx: Sender<crate::events::BaseEvent>,
    _config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        log::info!("Starting process monitor (ETW kernel)...");
        match process::start_kernel_monitor(tx, shutdown) {
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

// Network monitoring wrapper
pub fn start_network_monitor(
    tx: Sender<crate::events::BaseEvent>,
    _config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        log::info!("Network monitor starting...");
        run_network_monitor(tx, shutdown);
        log::info!("Network monitor stopped");
    })
}

fn run_network_monitor(
    tx: Sender<crate::events::BaseEvent>,
    shutdown: Arc<AtomicBool>,
) {
    // Try to start an ETW-based listener first
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

// Attempt to start an ETW listener for Microsoft-Windows-TCPIP
fn start_etw_listener(
    tx: Sender<crate::events::BaseEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, Box<dyn std::error::Error>> {
    // Delegate to centralized ETW manager to start a TCP/IP listener
    match network::start_tcpip_listener(tx, shutdown) {
        Ok(handle) => Ok(handle),
        Err(e) => Err(e),
    }
}