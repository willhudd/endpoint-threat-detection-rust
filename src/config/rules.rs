use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub suspicious_process_patterns: Vec<String>,
    pub suspicious_network_patterns: Vec<String>,
    pub alert_thresholds: AlertThresholds,
    pub correlation_rules: Vec<CorrelationRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    pub max_connections_per_minute: usize,
    pub max_processes_per_minute: usize,
    pub suspicious_port_range: (u16, u16),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    pub operator: String,
    pub value: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            suspicious_process_patterns: vec![
                r"(?i).*\.(ps1|vbs|js|hta|bat|cmd)$".to_string(),
                r"(?i).*(powershell|cmd|wscript|cscript|mshta).*".to_string(),
            ],
            suspicious_network_patterns: vec![
                r"(?i).*(tor|proxy|vpn).*".to_string(),
                r"\d+\.\d+\.\d+\.\d+:\d{4,5}".to_string(),
            ],
            alert_thresholds: AlertThresholds {
                max_connections_per_minute: 100,
                max_processes_per_minute: 50,
                suspicious_port_range: (49152, 65535), // Dynamic/private ports
            },
            correlation_rules: vec![
                CorrelationRule {
                    name: "NewProcessNetworkActivity".to_string(),
                    description: "New process making network connections within 5 seconds".to_string(),
                    severity: "Medium".to_string(),
                    conditions: vec![
                        Condition {
                            field: "process_age".to_string(),
                            operator: "<".to_string(),
                            value: "5".to_string(),
                        },
                        Condition {
                            field: "network_connections".to_string(),
                            operator: ">".to_string(),
                            value: "0".to_string(),
                        },
                    ],
                },
            ],
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
    
    log::info!("Using default configuration");
    Config::default()
}

pub fn save_rules(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "config/edr_rules.json";
    let content = serde_json::to_string_pretty(config)?;
    fs::write(config_path, content)?;
    Ok(())
}