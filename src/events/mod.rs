pub mod alert;
pub mod network;
pub mod process;

pub use alert::Alert;
pub use network::NetworkEvent;
pub use process::ProcessEvent;

use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub enum EventType {
    ProcessStart(ProcessEvent),
    ProcessEnd(ProcessEvent),
    NetworkConnection(NetworkEvent),
    Alert(Alert),
}

#[derive(Debug, Clone)]
pub struct BaseEvent {
    pub timestamp: DateTime<Utc>,
    pub event_id: String,
    pub machine_name: String,
    pub user_name: String,
    pub event_type: EventType,
}

impl BaseEvent {
    pub fn new(event_type: EventType) -> Self {
        Self {
            timestamp: Utc::now(),
            event_id: uuid::Uuid::new_v4().to_string(),
            machine_name: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
            user_name: whoami::fallible::username().unwrap_or_else(|_| "unknown".to_string()),
            event_type,
        }
    }
}