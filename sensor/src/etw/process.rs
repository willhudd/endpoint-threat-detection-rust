use shared::ProcessEvent;
use std::sync::{Arc, Mutex};
use std::process::Command;
use std::time::Duration;
use std::thread;
use std::collections::HashSet;

pub fn is_process_signed(path: &str) -> bool {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Get-AuthenticodeSignature '{}' | Select -ExpandProperty Status",
                path
            ),
        ])
        .output();

    matches!(
        output
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .as_deref(),
        Some("Valid")
    )
}

pub fn start_process_monitor(events: Arc<Mutex<Vec<ProcessEvent>>>) {
    println!("[Process Monitor] Starting process monitoring...");
    
    thread::spawn(move || {
        let mut seen_pids: HashSet<u32> = HashSet::new();
        
        loop {
            // Use PowerShell with JSON for reliable parsing
            let output = Command::new("powershell")
                .args(&[
                    "-NoProfile",
                    "-Command",
                    "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
                ])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    if let Ok(json_str) = String::from_utf8(output.stdout) {
                        if json_str.trim().is_empty() {
                            continue;
                        }
                        
                        // Parse JSON
                        if let Ok(processes) = serde_json::from_str::<serde_json::Value>(&json_str) {
                            let proc_array = if processes.is_array() {
                                processes.as_array().unwrap().clone()
                            } else {
                                vec![processes]
                            };
                            
                            for proc in &proc_array {
                                if let Some(pid) = proc["ProcessId"].as_u64() {
                                    let pid = pid as u32;
                                    let parent_pid = proc["ParentProcessId"].as_u64().unwrap_or(0) as u32;
                                    
                                    let image = proc["ExecutablePath"]
                                        .as_str()
                                        .unwrap_or("Unknown")
                                        .to_string();

                                    let command_line = proc["CommandLine"]
                                        .as_str()
                                        .unwrap_or("")
                                        .to_string();

                                    let mut event = ProcessEvent {
                                        timestamp: chrono::Local::now().to_rfc3339(),
                                        pid,
                                        parent_pid,
                                        image: image.clone(),
                                        parent_image: "Unknown".to_string(),
                                        command_line,
                                        is_signed: is_process_signed(&image),
                                    };

                                    if let Ok(mut list) = events.lock() {
                                        if let Some(parent) = list.iter().find(|p| p.pid == parent_pid) {
                                            event.parent_image = parent.image.clone();
                                        }

                                        list.push(event);

                                        if list.len() > 1000 {
                                            list.remove(0);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            if seen_pids.len() > 10000 {
                seen_pids.clear();
            }
            
            thread::sleep(Duration::from_secs(3));
        }
    });
}