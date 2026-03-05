use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub alert_rules: Vec<AlertRule>,
    pub trusted_processes: Vec<String>,
    pub suspicious_process_types: Vec<String>,
    pub network_baselines: NetworkBaselines,
    pub alert_cooldowns: AlertCooldowns,
    pub known_malicious_iocs: Option<MaliciousIOCs>,
    pub keylogger_detection: Option<KeyloggerDetection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub enabled: bool,
    pub conditions: Vec<Condition>,
    pub cooldown_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBaselines {
    pub max_connections_per_minute: HashMap<String, u32>,
    pub allowed_ports_per_process: HashMap<String, Vec<u16>>,
    pub suspicious_parent_child: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCooldowns {
    pub per_rule_minutes: u64,
    pub per_process_minutes: u64,
    pub global_minutes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousIOCs {
    pub ips: Vec<String>,
    pub domains: Vec<String>,
    pub ports: Vec<u16>,
    pub patterns: Vec<IoCPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoCPattern {
    pub name: String,
    pub pattern: String,
    pub pattern_type: String, // "regex", "substring", "yara"
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyloggerDetection {
    pub enabled: bool,
    pub indicators: Vec<String>,
    pub webhook_services: Vec<String>,
    pub suspicious_powershell_flags: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            alert_rules: vec![
                AlertRule {
                    name: "ImmediateC2Connection".to_string(),
                    description: "New process making immediate external connection".to_string(),
                    severity: "Critical".to_string(),
                    enabled: true,
                    cooldown_seconds: 300,
                    conditions: vec![
                        Condition {
                            field: "process_age".to_string(),
                            operator: "<".to_string(),
                            value: "2".to_string(),
                        },
                        Condition {
                            field: "connection_count".to_string(),
                            operator: "==".to_string(),
                            value: "1".to_string(),
                        },
                        Condition {
                            field: "is_external".to_string(),
                            operator: "==".to_string(),
                            value: "true".to_string(),
                        },
                    ],
                },
                AlertRule {
                    name: "SuspiciousProcessExternalConnection".to_string(),
                    description: "Suspicious process type making external connection".to_string(),
                    severity: "Medium".to_string(),
                    enabled: true,
                    cooldown_seconds: 600,
                    conditions: vec![
                        Condition {
                            field: "process_type".to_string(),
                            operator: "in".to_string(),
                            value: "suspicious".to_string(),
                        },
                        Condition {
                            field: "is_external".to_string(),
                            operator: "==".to_string(),
                            value: "true".to_string(),
                        },
                    ],
                },
            ],
            trusted_processes: vec![
                "svchost.exe".to_string(),
                "explorer.exe".to_string(),
                "dwm.exe".to_string(),
                "taskhostw.exe".to_string(),
                "runtimebroker.exe".to_string(),
                "conhost.exe".to_string(),
                "dllhost.exe".to_string(),
                "backgroundtaskhost.exe".to_string(),
            ],
            suspicious_process_types: vec![
                ".ps1".to_string(),
                ".vbs".to_string(),
                ".js".to_string(),
                ".hta".to_string(),
                "mshta.exe".to_string(),
                "regsvr32.exe".to_string(),
                "rundll32.exe".to_string(),
                "certutil.exe".to_string(),
                "bitsadmin.exe".to_string(),
            ],
            network_baselines: NetworkBaselines {
                max_connections_per_minute: [
                    ("chrome.exe".to_string(), 100),
                    ("firefox.exe".to_string(), 50),
                    ("msedge.exe".to_string(), 100),
                    ("powershell.exe".to_string(), 10),
                    ("cmd.exe".to_string(), 5),
                ].iter().cloned().collect(),
                allowed_ports_per_process: [
                    ("chrome.exe".to_string(), vec![80, 443, 53]),
                    ("firefox.exe".to_string(), vec![80, 443, 53]),
                    ("msedge.exe".to_string(), vec![80, 443, 53]),
                ].iter().cloned().collect(),
                suspicious_parent_child: vec![
                    ("explorer.exe".to_string(), "powershell.exe".to_string()),
                    ("svchost.exe".to_string(), "cmd.exe".to_string()),
                    ("services.exe".to_string(), "wscript.exe".to_string()),
                ],
            },
            alert_cooldowns: AlertCooldowns {
                per_rule_minutes: 15,
                per_process_minutes: 30,
                global_minutes: 5,
            },
            known_malicious_iocs: Some(MaliciousIOCs {
                ips: vec![
                    "41.47.145.151".to_string(),    // These IPs don't belong to normal residential users or major legitimate services.
                    "212.107.27.165".to_string(),   // They have been reported for network probing, brute-force attempts
                    "103.182.132.154".to_string(),  // (especially SSH), or other low-level attacks/scans.
                ],
                domains: vec![
                    "discord.com".to_string(), // Webhook service
                ],
                ports: vec![
                    4444, 31337, 6667, 6660, 9999, 5555, 8877, 1337, 8080, 8443, 1234, 4321, 6789, 9898, 9988, 2333, 2334,
                ],
                patterns: vec![
                    IoCPattern {
                        name: "PowerShell Hidden Execution".to_string(),
                        pattern: "-WindowStyle Hidden".to_string(),
                        pattern_type: "substring".to_string(),
                        severity: "Medium".to_string(),
                    },
                    IoCPattern {
                        name: "PowerShell Bypass Execution Policy".to_string(),
                        pattern: "-ExecutionPolicy Bypass".to_string(),
                        pattern_type: "substring".to_string(),
                        severity: "High".to_string(),
                    },
                ],
            }),
            keylogger_detection: Some(KeyloggerDetection {
                enabled: true,
                indicators: vec![
                    "GetAsyncKeyState".to_string(),
                    "keylog".to_string(),
                    "[BACKSPACE]".to_string(),
                    "[TAB]".to_string(),
                    "[ENTER]".to_string(),
                    "[SHIFT]".to_string(),
                    "[CTRL]".to_string(),
                ],
                webhook_services: vec![
                    "discord.com".to_string(),
                    "webhook.office.com".to_string(),
                    "hooks.slack.com".to_string(),
                ],
                suspicious_powershell_flags: vec![
                    "-WindowStyle Hidden".to_string(),
                    "-ExecutionPolicy Bypass".to_string(),
                    "-NoProfile".to_string(),
                    "-EncodedCommand".to_string(),
                    "-NonInteractive".to_string(),
                ],
            }),
        }
    }
}

pub fn load_rules() -> Config {
    let config_path = "config/edr_rules.json";
    
    if Path::new(config_path).exists() {
        match fs::read_to_string(config_path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(config) => {
                    log::info!("Loaded configuration from {}", config_path);
                    return config;
                }
                Err(e) => {
                    log::warn!("Failed to parse config file: {}. Using defaults.", e);
                }
            },
            Err(e) => {
                log::warn!("Failed to read config file: {}. Using defaults.", e);
            }
        }
    }
    Config::default()
}