use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub timestamp: String,
    pub pid: u32,
    pub parent_pid: u32,
    pub image: String,
    pub parent_image: String,
    pub command_line: String,
    pub is_signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub timestamp: String,
    pub pid: u32,
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub remote_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub timestamp: String,
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub event_type: String, // "created", "modified", "deleted"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub time: String,
    pub severity: String,
    pub rule: String,
    pub process: String,
    pub parent: String,
    pub command_line: Option<String>,
    pub details: Option<String>,
}

impl Alert {
    pub fn new(severity: &str, rule: &str, process: &str, parent: &str) -> Self {
        Self {
            time: chrono::Local::now().to_rfc3339(),
            severity: severity.to_string(),
            rule: rule.to_string(),
            process: process.to_string(),
            parent: parent.to_string(),
            command_line: None,
            details: None,
        }
    }
}