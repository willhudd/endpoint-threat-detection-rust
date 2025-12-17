use winreg::enums::*;
use winreg::RegKey;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use std::collections::HashSet;
use std::process::Command;

// Monitor Run keys (auto-start) AND Windows Defender / security-related keys
const MONITORED_KEYS: &[(&str, &str)] = &[
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    // Defender policy keys
    ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows Defender"),
    ("HKLM", r"SYSTEM\CurrentControlSet\Services\WinDefend"),
];

type RegSnapshot = HashMap<String, HashMap<String, String>>;

pub fn start_registry_monitor() {
    println!("[Registry] Monitor started");
    
    let mut last_snapshot = take_registry_snapshot();
    
    loop {
        thread::sleep(Duration::from_secs(10));
        
        let current_snapshot = take_registry_snapshot();
        
        // Detect changes
        for (key_path, current_values) in &current_snapshot {
            if let Some(old_values) = last_snapshot.get(key_path) {
                // Check for new or modified values
                for (name, value) in current_values {
                    if let Some(old_value) = old_values.get(name) {
                        if old_value != value {
                            println!("[!] Registry Modified: {} -> {} = {}", key_path, name, value);
                            log_registry_change(key_path, name, value, "modified");
                        }
                    } else {
                        println!("[!] Registry Created: {} -> {} = {}", key_path, name, value);
                        log_registry_change(key_path, name, value, "created");
                    }
                }
                
                // Check for deleted values
                for (name, _) in old_values {
                    if !current_values.contains_key(name) {
                        println!("[!] Registry Deleted: {} -> {}", key_path, name);
                        log_registry_change(key_path, name, "<deleted>", "deleted");
                    }
                }
            }
        }
        
        last_snapshot = current_snapshot;
    }
}

fn take_registry_snapshot() -> RegSnapshot {
    let mut snapshot = HashMap::new();
    
    for (hive, subkey) in MONITORED_KEYS {
        let key = match *hive {
            "HKCU" => RegKey::predef(HKEY_CURRENT_USER),
            "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE),
            _ => continue,
        };
        
        if let Ok(run_key) = key.open_subkey(subkey) {
            let mut values = HashMap::new();
            
            for value_name in run_key.enum_values().filter_map(|v| v.ok()) {
                if let Ok(value_data) = run_key.get_raw_value(&value_name.0) {
                    let data_str = String::from_utf8_lossy(&value_data.bytes).to_string();
                    values.insert(value_name.0, data_str);
                }
            }
            
            let full_path = format!(r"{}\{}", hive, subkey);
            snapshot.insert(full_path, values);
        }
    }
    
    snapshot
}

fn log_registry_change(key_path: &str, name: &str, value: &str, change_type: &str) {
    let event = shared::RegistryEvent {
        timestamp: chrono::Local::now().to_rfc3339(),
        key_path: key_path.to_string(),
        value_name: name.to_string(),
        value_data: value.to_string(),
        event_type: change_type.to_string(),
    };
    
    if let Err(e) = crate::logger::log_registry_event(&event) {
        eprintln!("[!] Failed to log registry event: {}", e);
    }
}

/// Monitors for new USB keyboard devices (HID keyboards). This helps detect Rubber Ducky / Pico attacks
/// which enumerate as a new keyboard and then inject keystrokes.
pub fn start_usb_monitor() {
    println!("[USB Monitor] Started");

    thread::spawn(|| {
        let mut seen: HashSet<String> = HashSet::new();

        // Initial population: collect existing keyboards and mark them as seen without alerting
        if let Ok(output) = Command::new("powershell").args(&[
            "-NoProfile",
            "-Command",
            "Get-PnpDevice -Class Keyboard | Select-Object InstanceId,FriendlyName | ConvertTo-Json -Compress",
        ]).output() {
            if output.status.success() {
                if let Ok(json_str) = String::from_utf8(output.stdout) {
                    if !json_str.trim().is_empty() {
                        if let Ok(devs) = serde_json::from_str::<serde_json::Value>(&json_str) {
                            let arr = if devs.is_array() { devs.as_array().unwrap().clone() } else { vec![devs] };
                            for dev in &arr {
                                let id = dev["InstanceId"].as_str().unwrap_or("Unknown").to_string();
                                seen.insert(id);
                            }
                        }
                    }
                }
            }
        }

    let mut first_scan = true;
    loop {
            // Use PowerShell to list PnP devices of class Keyboard
            let output = Command::new("powershell")
                .args(&[
                    "-NoProfile",
                    "-Command",
                    "Get-PnpDevice -Class Keyboard | Select-Object InstanceId,FriendlyName | ConvertTo-Json -Compress",
                ])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    if let Ok(json_str) = String::from_utf8(output.stdout) {
                        if !json_str.trim().is_empty() {
                            if let Ok(devs) = serde_json::from_str::<serde_json::Value>(&json_str) {
                                let arr = if devs.is_array() { devs.as_array().unwrap().clone() } else { vec![devs] };

                                for dev in &arr {
                                    let id = dev["InstanceId"].as_str().unwrap_or("Unknown").to_string();
                                    let name = dev["FriendlyName"].as_str().unwrap_or("").to_string();

                                    if first_scan {
                                        // populate seen on first successful scan without alerting
                                        seen.insert(id.clone());
                                        continue;
                                    }

                                    if !seen.contains(&id) {
                                        seen.insert(id.clone());

                                        // Create an alert for new keyboard device
                                        let mut alert = shared::Alert::new(
                                            "MEDIUM",
                                            "New USB keyboard device detected",
                                            &id,
                                            "system",
                                        );
                                        alert.details = Some(format!("New keyboard: {} - {}", id, name));

                                        crate::logger::log_alert(&alert);
                                        println!("[!] ALERT: {} - {}", alert.rule, alert.details.as_deref().unwrap_or(""));
                                    }
                                }
                                // after first successful parse, mark that future findings should alert
                                first_scan = false;
                            }
                        }
                    }
                }
            }

            // Sleep a bit longer to reduce churn
            thread::sleep(Duration::from_secs(5));
        }
    });
}