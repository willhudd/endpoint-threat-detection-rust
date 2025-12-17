use shared::{NetworkEvent, ProcessEvent};
use std::sync::{Arc, Mutex};
use std::process::Command;
use std::time::Duration;
use std::thread;
use std::collections::HashSet;

fn is_private_or_local(addr: &str) -> bool {
    let a = addr.trim_matches(|c| c == '[' || c == ']').trim();
    if a.starts_with("127.") || a == "::1" || a == "localhost" {
        return true;
    }
    if a.starts_with("10.") || a.starts_with("192.168.") || a.starts_with("169.254.") {
        return true;
    }
    // 172.16.0.0 - 172.31.255.255
    if a.starts_with("172.") {
        if let Some(second) = a.split('.').nth(1) {
            if let Ok(n) = second.parse::<u8>() {
                if n >= 16 && n <= 31 {
                    return true;
                }
            }
        }
    }
    false
}

/// Start network monitor and optionally populate process events for quick correlation.
pub fn start_network_monitor(
    events: Arc<Mutex<Vec<NetworkEvent>>>,
    proc_events: Arc<Mutex<Vec<ProcessEvent>>>,
) {
    println!("[Network Monitor] Starting netstat-based monitoring...");
    
    thread::spawn(move || {
        let mut seen_connections = HashSet::new();
        
        loop {
            // Query active network connections
            let output = Command::new("netstat")
                .args(&["-ano"]) // -a all, -n numeric, -o show PID
                .output();

            if let Ok(output) = output {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    for line in stdout.lines().skip(4) { // Skip netstat headers
                        if line.trim().is_empty() {
                            continue;
                        }
                        
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        
                        // Parse TCP connections: Proto Local-Addr Remote-Addr State PID
                        if parts.len() >= 5 && parts[0] == "TCP" {
                            let local = parts[1];
                            let remote = parts[2];
                            let state = parts[3];
                            
                            if let Ok(pid) = parts[4].parse::<u32>() {
                                // Only capture ESTABLISHED connections
                                if state == "ESTABLISHED" && pid > 0 {
                                    // Parse remote address (format: IP:PORT)
                                    if let Some((addr, port_str)) = remote.rsplit_once(':') {
                                        // Create unique key for this connection
                                        let key = format!("{}-{}-{}", pid, local, remote);
                                        
                                        if !seen_connections.contains(&key) {
                                            seen_connections.insert(key);
                                            
                                            let event = NetworkEvent {
                                                timestamp: chrono::Local::now().to_rfc3339(),
                                                pid,
                                                protocol: "TCP".to_string(),
                                                local_addr: local.to_string(),
                                                remote_addr: addr.to_string(),
                                                remote_port: port_str.parse().unwrap_or(0),
                                            };
                                            
                                            // Push network event
                                            if let Ok(mut list) = events.lock() {
                                                list.push(event.clone());
                                                if list.len() > 1000 {
                                                    list.remove(0);
                                                }
                                            }

                                            // Only print noisy network entries for public/external destinations
                                            if !is_private_or_local(&event.remote_addr) {
                                                println!("[Network] Connection: PID {} -> {}:{}", 
                                                    event.pid, event.remote_addr, event.remote_port);
                                            }

                                            // Ensure there's a matching ProcessEvent for this PID so detection can correlate quickly.
                                            // If the process monitor missed a short-lived process, this will create a lightweight record.
                                            if let Ok(procs) = proc_events.lock() {
                                                let exists = procs.iter().any(|p| p.pid == pid);
                                                drop(procs); // release lock before doing PS query

                                                if !exists {
                                                    // Query process info for the PID
                                                    let ps_cmd = format!("Get-CimInstance Win32_Process -Filter \"ProcessId={}\" | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress", pid);
                                                    if let Ok(output) = Command::new("powershell").args(&["-NoProfile", "-Command", &ps_cmd]).output() {
                                                        if output.status.success() {
                                                            if let Ok(json_str) = String::from_utf8(output.stdout) {
                                                                if !json_str.trim().is_empty() {
                                                                    if let Ok(processes) = serde_json::from_str::<serde_json::Value>(&json_str) {
                                                                        let proc_array = if processes.is_array() {
                                                                            processes.as_array().unwrap().clone()
                                                                        } else {
                                                                            vec![processes]
                                                                        };

                                                                        for proc in &proc_array {
                                                                            if let Some(found_pid) = proc["ProcessId"].as_u64() {
                                                                                let found_pid = found_pid as u32;
                                                                                let parent_pid = proc["ParentProcessId"].as_u64().unwrap_or(0) as u32;
                                                                                let image = proc["ExecutablePath"].as_str().unwrap_or("Unknown").to_string();
                                                                                let command_line = proc["CommandLine"].as_str().unwrap_or("").to_string();

                                                                                let pevent = ProcessEvent {
                                                                                    timestamp: chrono::Local::now().to_rfc3339(),
                                                                                    pid: found_pid,
                                                                                    parent_pid,
                                                                                    image: image.clone(),
                                                                                    parent_image: "Unknown".to_string(),
                                                                                    command_line: command_line.clone(),
                                                                                    is_signed: crate::etw::process::is_process_signed(&image),
                                                                                };

                                                                                if let Ok(mut procs) = proc_events.lock() {
                                                                                    // Only insert if still missing
                                                                                    if !procs.iter().any(|p| p.pid == found_pid) {
                                                                                        procs.push(pevent);
                                                                                        if procs.len() > 1000 {
                                                                                            procs.remove(0);
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                eprintln!("[Network Monitor] Failed to execute netstat command");
            }
            
            // Periodically clear old connections to prevent unbounded growth
            if seen_connections.len() > 5000 {
                seen_connections.clear();
            }
            
            thread::sleep(Duration::from_secs(2));
        }
    });
}