mod etw;
mod registry;
mod rules;
mod logger;

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::collections::HashSet;

fn main() {
    println!("[CustomEDR] Starting sensor...");
    
    // Create shared state for events
    let process_events = Arc::new(Mutex::new(Vec::new()));
    let network_events = Arc::new(Mutex::new(Vec::new()));
    
    // Initialize logger
    logger::init_logger().expect("Failed to initialize logger");
    
    println!("[+] Starting process monitoring (ETW)...");
    let proc_events = process_events.clone();
    thread::spawn(move || {
        etw::process::start_process_monitor(proc_events);
    });
    
    println!("[+] Starting network monitoring (ETW)...");
    let net_events = network_events.clone();
    let proc_events_for_net = process_events.clone();
    
    thread::spawn(move || {
        etw::network::start_network_monitor(net_events, proc_events_for_net);
    });
    
    println!("[+] Starting registry monitoring...");
    thread::spawn(|| {
        registry::start_registry_monitor();
    });

    // Start USB keyboard monitor to detect HID-injection devices (Rubber Ducky / Pico)
    println!("[+] Starting USB keyboard monitoring...");
    thread::spawn(|| {
        registry::start_usb_monitor();
    });
    
    println!("[+] Starting detection engine...");
    thread::spawn(move || {
        let mut alerted: HashSet<(u32, String)> = HashSet::new();
        loop {
            thread::sleep(Duration::from_secs(10)); // Check every 10 seconds instead of 2
            
            // Run detection rules
            let procs = process_events.lock().unwrap();
            let nets = network_events.lock().unwrap();
            
                for proc in procs.iter() {
                    // Check Office -> PowerShell
                    if let Some(alert) = rules::detect_office_powershell(proc) {
                        let key = (proc.pid, alert.rule.clone());
                            if alerted.insert(key) {
                                logger::log_alert(&alert);
                                println!("[!] ALERT: {} - PID {} - {}", alert.rule, proc.pid, proc.image);
                        }
                    }

                    // Check suspicious command lines (encoded, iex, downloadstring, etc.)
                    if let Some(alert) = rules::detect_suspicious_cmdline(proc) {
                        let key = (proc.pid, alert.rule.clone());
                            if alerted.insert(key) {
                                logger::log_alert(&alert);
                                println!("[!] ALERT: {} - PID {} - {}", alert.rule, proc.pid, proc.image);
                        }
                    }

                    // Check for attempts to disable Windows Defender via command line
                    if let Some(alert) = rules::detect_defender_disable_by_cmdline(proc) {
                        let key = (proc.pid, alert.rule.clone());
                            if alerted.insert(key) {
                                logger::log_alert(&alert);
                                println!("[!] ALERT: {} - PID {} - {}", alert.rule, proc.pid, proc.image);
                        }
                    }

                    // Detect Discord webhook usage in command line (exfiltration)
                    if let Some(alert) = rules::detect_discord_webhook_in_cmdline(proc) {
                        let key = (proc.pid, alert.rule.clone());
                            if alerted.insert(key) {
                                logger::log_alert(&alert);
                                println!("[!] ALERT: {} - PID {} - {}", alert.rule, proc.pid, proc.image);
                        }
                    }

                    // New targeted detection: PowerShell launched hidden from a non-C: drive (removable/CIRCUITPY)
                    if let Some(alert) = rules::detect_powershell_hidden_from_removable(proc) {
                        let key = (proc.pid, alert.rule.clone());
                            if alerted.insert(key) {
                                logger::log_alert(&alert);
                                println!("[!] ALERT: {} - PID {} - {}", alert.rule, proc.pid, proc.image);
                        }
                    }

                    // Check unsigned process with network
                    for net in nets.iter() {
                        if let Some(alert) = rules::detect_unsigned_network(proc, net) {
                            let key = (proc.pid, alert.rule.clone());
                                if alerted.insert(key) {
                                    logger::log_alert(&alert);
                                    println!("[!] ALERT: {} - PID {} - {}", alert.rule, proc.pid, proc.image);
                            }
                        }
                    
                        // Additional keylogger-oriented detection: location + network to webhook
                        if let Some(alert) = rules::detect_possible_keylogger(proc, net) {
                            let key = (proc.pid, alert.rule.clone());
                                if alerted.insert(key) {
                                    logger::log_alert(&alert);
                                    println!("[!] ALERT: {} - PID {} - {}", alert.rule, proc.pid, proc.image);
                            }
                        }

                        // Generic PowerShell exfiltration heuristic: PowerShell process making external connections
                        if let Some(alert) = rules::detect_powershell_network_exfil(proc, net) {
                            let key = (proc.pid, alert.rule.clone());
                                if alerted.insert(key) {
                                    logger::log_alert(&alert);
                                    println!("[!] ALERT: {} - PID {} - {}", alert.rule, proc.pid, proc.image);
                            }
                        }
                    }
                }
        }
    });
    
    println!("[CustomEDR] Sensor is running. Press Ctrl+C to stop.");
    
    // Main loop
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}