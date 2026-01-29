mod config;
mod events;
mod monitoring;
mod utils;

use crate::monitoring::{start_process_monitor, start_network_monitor, correlation_engine};
use crate::utils::privilege;
use simplelog::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::io::{self, Read};
use std::sync::Once;

// Global shutdown flag with atomic ordering
static RUNNING: AtomicBool = AtomicBool::new(true);
static SHUTDOWN_ONCE: Once = Once::new();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Trace,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
    ])?;

    log::info!("=========================================");
    log::info!("       EDR System Starting");
    log::info!("=========================================");

    // Check and enable required privileges
    if !privilege::enable_required_privileges() {
        log::error!("Failed to enable required privileges. Run as Administrator!");
        log::error!("Right-click Command Prompt/PowerShell and select 'Run as Administrator'");
        return Ok(());
    }
    log::info!("✅ Required privileges enabled");

    // Create event channels
    let (process_tx, process_rx) = crossbeam_channel::unbounded();
    let (network_tx, network_rx) = crossbeam_channel::unbounded();
    let (alert_tx, alert_rx) = crossbeam_channel::unbounded();

    // Load configuration
    let config = Arc::new(config::rules::load_rules());

    // Create shutdown flags for each component
    let correlation_shutdown = Arc::new(AtomicBool::new(true));
    let process_shutdown = Arc::new(AtomicBool::new(true));
    let network_shutdown = Arc::new(AtomicBool::new(true));
    let alert_shutdown = Arc::new(AtomicBool::new(true));

    log::info!("🚀 Starting monitoring components...");

    // Start correlation engine
    let correlation_handle = correlation_engine::start_correlation_engine(
        process_rx,
        network_rx,
        alert_tx.clone(),
        Arc::clone(&config),
        Arc::clone(&correlation_shutdown),
    );

    // Start monitors with shutdown signals
    let process_handle = start_process_monitor(
        process_tx.clone(), 
        Arc::clone(&config),
        Arc::clone(&process_shutdown)
    );
    let network_handle = start_network_monitor(
        network_tx.clone(), 
        Arc::clone(&config),
        Arc::clone(&network_shutdown)
    );

    log::info!("=========================================");
    log::info!("       EDR System Running");
    log::info!("=========================================");
    log::info!("📊 Monitoring:");
    log::info!("  • Process creation/termination");
    log::info!("  • Network connections");
    log::info!("  • Suspicious activity correlation");
    log::info!("");
    log::info!("🛑 To stop:");
    log::info!("  1. Press Ctrl+C");
    log::info!("  2. OR Type 'q' then press Enter");
    log::info!("  3. OR Type 'stop' then press Enter");
    log::info!("=========================================");

    // Setup Ctrl+C handler with protection against multiple triggers
    ctrlc::set_handler({
        move || {
            SHUTDOWN_ONCE.call_once(|| {
                log::info!("");
                log::info!("🛑 Received shutdown signal");
                RUNNING.store(false, Ordering::Relaxed);
            });
        }
    })
    .expect("Failed to set Ctrl+C handler");

    // Main loop - check both Ctrl+C and manual commands
    let mut input_buffer = String::new();
    while RUNNING.load(Ordering::Relaxed) {
        // Check for manual commands (non-blocking)
        let mut buffer = [0u8; 1024];
        if let Ok(n) = io::stdin().read(&mut buffer) {
            if n > 0 {
                input_buffer.push_str(&String::from_utf8_lossy(&buffer[..n]));
                
                // Check if we have a complete line
                if input_buffer.contains('\n') || input_buffer.contains('\r') {
                    let command = input_buffer.trim().to_lowercase();
                    input_buffer.clear();
                    
                    if command == "q" || command == "quit" || command == "exit" || command == "stop" {
                        SHUTDOWN_ONCE.call_once(|| {
                            log::info!("🛑 Manual shutdown requested via command: '{}'", command);
                            RUNNING.store(false, Ordering::Relaxed);
                        });
                        break;
                    } else if command == "status" || command == "info" {
                        log::info!("📊 System Status: RUNNING");
                        log::info!("  Components: Process Monitor, Network Monitor, Correlation Engine");
                        log::info!("  Type 'q', 'quit', 'exit', or 'stop' to shutdown");
                    } else if !command.is_empty() {
                        log::info!("❓ Unknown command: '{}'", command);
                        log::info!("   Available commands: q, quit, exit, stop, status");
                    }
                }
            }
        }
        
        // Small sleep to prevent CPU spinning
        std::thread::sleep(Duration::from_millis(50));
    }

    // ========== SINGLE SHUTDOWN SEQUENCE ==========
    perform_shutdown(
        process_shutdown,
        network_shutdown,
        correlation_shutdown,
        alert_shutdown,
        process_tx,
        network_tx,
        alert_tx,
        process_handle,
        network_handle,
        correlation_handle,
    );

    Ok(())
}

fn perform_shutdown(
    process_shutdown: Arc<AtomicBool>,
    network_shutdown: Arc<AtomicBool>,
    correlation_shutdown: Arc<AtomicBool>,
    alert_shutdown: Arc<AtomicBool>,
    process_tx: crossbeam_channel::Sender<crate::events::BaseEvent>,
    network_tx: crossbeam_channel::Sender<crate::events::BaseEvent>,
    alert_tx: crossbeam_channel::Sender<crate::events::Alert>,
    process_handle: std::thread::JoinHandle<()>,
    network_handle: std::thread::JoinHandle<()>,
    correlation_handle: std::thread::JoinHandle<()>,
) {
    log::info!("");
    log::info!("=========================================");
    log::info!("       Initiating Graceful Shutdown");
    log::info!("=========================================");
    
    // Signal shutdown to all components
    log::info!("📢 Signaling shutdown to all components...");
    
    process_shutdown.store(false, Ordering::Relaxed);
    network_shutdown.store(false, Ordering::Relaxed);
    correlation_shutdown.store(false, Ordering::Relaxed);
    alert_shutdown.store(false, Ordering::Relaxed);

    // Close channels to unblock threads
    drop(process_tx);
    drop(network_tx);
    drop(alert_tx);
    
    // Define shutdown order (network first, then correlation, then process)
    let components = vec![
        ("Network Monitor", network_handle),
        ("Correlation Engine", correlation_handle),
        ("Process Monitor", process_handle),
    ];
    
    for (name, handle) in components {
        log::info!("  Waiting for {}...", name);
        match join_with_timeout(handle, Duration::from_secs(5)) {
            Ok(()) => log::info!("  ✅ {} stopped gracefully", name),
            Err(JoinError::Timeout) => log::warn!("  ⚠️  {} didn't stop in time, continuing...", name),
            Err(JoinError::Panic(e)) => log::error!("  ❌ {} panicked during shutdown: {:?}", name, e),
        }
    }

    // Verify ETW session is stopped
    log::info!("🔍 Verifying ETW session cleanup...");
    verify_etw_cleanup();
    log::info!("");
    log::info!("=========================================");
    log::info!("       Shutdown Complete");
    log::info!("=========================================");
}

// Helper function to join threads with timeout
fn join_with_timeout(handle: std::thread::JoinHandle<()>, timeout: Duration) -> Result<(), JoinError> {
    let start = std::time::Instant::now();
    
    while start.elapsed() < timeout {
        if handle.is_finished() {
            return match handle.join() {
                Ok(()) => Ok(()),
                Err(e) => Err(JoinError::Panic(e)),
            };
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    
    Err(JoinError::Timeout)
}

#[derive(Debug)]
enum JoinError {
    Timeout,
    Panic(Box<dyn std::any::Any + Send + 'static>),
}

// Helper function to verify ETW cleanup
fn verify_etw_cleanup() {
    use std::process::Command;
    
    #[cfg(windows)]
    {
        log::info!("  Running 'logman query' to check for active sessions...");
        let output = Command::new("logman")
            .args(["query"])
            .output();
            
        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("NT Kernel Logger") {
                    log::warn!("  ⚠️  NT Kernel Logger session might still be running");
                    log::info!("  You can manually stop it with: logman stop \"NT Kernel Logger\" -ets");
                } else {
                    log::info!("  ✅ No active NT Kernel Logger session found");
                }
            }
            Err(e) => {
                log::warn!("  ⚠️  Failed to run logman query: {}", e);
            }
        }
    }
    
    #[cfg(not(windows))]
    {
        log::info!("  ETW verification only available on Windows");
    }
}