use crate::config::rules::Config;
use crate::events::{Alert, BaseEvent, EventType};
use crossbeam_channel::{Receiver, Sender};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub fn start_correlation_engine(
    process_rx: Receiver<BaseEvent>,
    network_rx: Receiver<BaseEvent>,
    alert_tx: Sender<Alert>,
    config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        log::info!("Starting correlation engine...");
        run_correlation_engine(process_rx, network_rx, alert_tx, config, shutdown);
        log::info!("Correlation engine stopped");
    })
}

struct ProcessContext {
    start_time: chrono::DateTime<chrono::Utc>,
    process_name: String,
    pid: u32,
    network_connections: Vec<chrono::DateTime<chrono::Utc>>,
    suspicious_activities: Vec<String>,
}

pub fn run_correlation_engine(
    process_rx: Receiver<BaseEvent>,
    network_rx: Receiver<BaseEvent>,
    alert_tx: Sender<Alert>,
    config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
) {
    let mut process_contexts: HashMap<u32, ProcessContext> = HashMap::new();
    
    while shutdown.load(Ordering::Relaxed) {
        // Process both channels with timeout
        crossbeam_channel::select! {
            recv(process_rx) -> event => {
                if let Ok(event) = event {
                    process_event(&event, &mut process_contexts, &alert_tx, &config);
                }
            },
            recv(network_rx) -> event => {
                if let Ok(event) = event {
                    process_event(&event, &mut process_contexts, &alert_tx, &config);
                }
            },
            recv(crossbeam_channel::after(Duration::from_millis(100))) -> _ => {
                // Timeout - clean up old contexts
                cleanup_old_contexts(&mut process_contexts);
            }
        }
    }
}

fn process_event(
    event: &BaseEvent,
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_tx: &Sender<Alert>,
    config: &Config,
) {
    match &event.event_type {
        EventType::ProcessStart(process_event) => {
            // Check for suspicious process creation
            if is_suspicious_process(&process_event.process_name, config) {
                let alert = Alert::new(
                    crate::events::alert::AlertSeverity::High,
                    "SuspiciousProcessStart",
                    &format!("Suspicious process started: {}", process_event.process_name),
                    &process_event.process_name,
                    process_event.pid,
                    vec![format!("Process: {}", process_event.process_name)],
                );
                let _ = alert_tx.send(alert);
            }

            // Store process context
            process_contexts.insert(
                process_event.pid,
                ProcessContext {
                    start_time: chrono::Utc::now(),
                    process_name: process_event.process_name.clone(),
                    pid: process_event.pid,
                    network_connections: Vec::new(),
                    suspicious_activities: Vec::new(),
                },
            );
        }
        EventType::ProcessEnd(process_event) => {
            // Clean up process context
            process_contexts.remove(&process_event.pid);
        }
        EventType::NetworkConnection(network_event) => {
            // Check for suspicious network activity
            if let Some(context) = process_contexts.get_mut(&network_event.pid) {
                context.network_connections.push(chrono::Utc::now());

                // Detect rapid connection attempts
                if context.network_connections.len() > 5 {
                    let recent_connections = context.network_connections
                        .iter()
                        .filter(|&&time| time > chrono::Utc::now() - chrono::Duration::seconds(10))
                        .count();

                    if recent_connections > 5 {
                        let alert = Alert::new(
                            crate::events::alert::AlertSeverity::Medium,
                            "RapidNetworkConnections",
                            "Rapid network connections detected",
                            &context.process_name,
                            context.pid,
                            vec![format!("{} connections in 10 seconds", recent_connections)],
                        );
                        let _ = alert_tx.send(alert);
                    }
                }

                // Check for connections to suspicious destinations
                if is_suspicious_destination(&network_event.remote_address, config) {
                    let alert = Alert::new(
                        crate::events::alert::AlertSeverity::High,
                        "SuspiciousNetworkConnection",
                        &format!("Connection to suspicious destination: {}", network_event.remote_address),
                        &context.process_name,
                        context.pid,
                        vec![
                            format!("Destination: {}", network_event.remote_address),
                            format!("Port: {}", network_event.remote_port),
                        ],
                    );
                    let _ = alert_tx.send(alert);
                }

                // Cross-reference: New process making network connections
                let process_age = chrono::Utc::now() - context.start_time;
                if process_age < chrono::Duration::seconds(5) && !context.network_connections.is_empty() {
                    let alert = Alert::new(
                        crate::events::alert::AlertSeverity::Medium,
                        "NewProcessNetworkActivity",
                        "New process making network connections",
                        &context.process_name,
                        context.pid,
                        vec![
                            format!("Process age: {} seconds", process_age.num_seconds()),
                            format!("Connections made: {}", context.network_connections.len()),
                        ],
                    );
                    let _ = alert_tx.send(alert);
                }
            }
        }
        _ => {}
    }
}

fn cleanup_old_contexts(process_contexts: &mut HashMap<u32, ProcessContext>) {
    let now = chrono::Utc::now();
    let old_pids: Vec<u32> = process_contexts
        .iter()
        .filter(|(_, context)| now - context.start_time > chrono::Duration::minutes(10))
        .map(|(&pid, _)| pid)
        .collect();
    
    for pid in old_pids {
        process_contexts.remove(&pid);
    }
}

fn is_suspicious_process(process_name: &str, config: &Config) -> bool {
    // FILTER: First check if it's a known system process
    let lower_name = process_name.to_lowercase();
    
    // Skip Windows system processes
    let system_processes = vec![
        "svchost.exe", "system", "system idle process", 
        "csrss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "winlogon.exe", "explorer.exe",
        "dwm.exe", "taskhostw.exe", "runtimebroker.exe"
    ];
    
    if system_processes.iter().any(|&p| lower_name.contains(p)) {
        return false;
    }
    
    let suspicious_names = vec![
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
    ];

    let name_lower = process_name.to_lowercase();
    suspicious_names.iter().any(|&name| name_lower.contains(name)) ||
    config.suspicious_process_patterns.iter().any(|pattern| {
        let regex = regex::Regex::new(pattern).unwrap();
        regex.is_match(&name_lower)
    })
}

fn is_suspicious_destination(address: &str, config: &Config) -> bool {
    // Check against known malicious IPs/domains
    let suspicious_domains = vec![
        "malicious.com",
        "evil-domain.net",
    ];

    // Check if it's a private/internal address (less suspicious)
    if address.starts_with("192.168.") || 
       address.starts_with("10.") || 
       address.starts_with("127.") ||
       address == "::1" {
        return false;
    }

    // Check against suspicious patterns
    suspicious_domains.iter().any(|&domain| address.contains(domain)) ||
    config.suspicious_network_patterns.iter().any(|pattern| {
        let regex = regex::Regex::new(pattern).unwrap();
        regex.is_match(address)
    })
}