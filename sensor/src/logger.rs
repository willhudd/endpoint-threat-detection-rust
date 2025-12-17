use shared::{Alert, RegistryEvent};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use anyhow::Result;

const LOG_DIR: &str = r"C:\ProgramData\CustomEDR";
const ALERTS_FILE: &str = "alerts.jsonl";
const REGISTRY_FILE: &str = "registry.jsonl";

pub fn init_logger() -> Result<()> {
    fs::create_dir_all(LOG_DIR)?;
    println!("[Logger] Initialized: {}", LOG_DIR);
    Ok(())
}

pub fn log_alert(alert: &Alert) {
    if let Err(e) = write_json_line(ALERTS_FILE, alert) {
        eprintln!("[!] Failed to log alert: {}", e);
    }
}

pub fn log_registry_event(event: &RegistryEvent) -> Result<()> {
    write_json_line(REGISTRY_FILE, event)
}

fn write_json_line<T: serde::Serialize>(filename: &str, data: &T) -> Result<()> {
    let path = PathBuf::from(LOG_DIR).join(filename);
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    
    let json = serde_json::to_string(data)?;
    writeln!(file, "{}", json)?;
    
    Ok(())
}