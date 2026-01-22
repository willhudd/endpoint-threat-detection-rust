use crate::events::{BaseEvent, EventType};
use crate::events::process::ProcessEvent;
use crate::events::network::NetworkEvent;
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::error::Error;
use std::collections::{HashSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Mutex;

// Shared data structures
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub name: String,
    pub cached_at: u64,
    pub parent_pid: u32,
    pub command_line: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ConnectionAttempt {
    pub timestamp: u64,
    pub dest_addr: String,
    pub dest_port: u16,
    pub network_type: String,
}

// Global storage
lazy_static::lazy_static! {
    pub static ref GLOBAL_SENDER: Mutex<Option<Arc<Sender<BaseEvent>>>> = Mutex::new(None);
    pub static ref RECENT_CONNECTIONS: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    pub static ref PROCESS_NAME_CACHE: Mutex<HashMap<u32, ProcessInfo>> = Mutex::new(HashMap::new());
    pub static ref CONNECTION_TRACKER: Mutex<HashMap<u32, Vec<ConnectionAttempt>>> = Mutex::new(HashMap::new());
    pub static ref RECENT_PROCESS_STARTS: Mutex<HashMap<u32, ProcessInfo>> = Mutex::new(HashMap::new());
    pub static ref QUIC_CONNECTIONS: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    pub static ref DNS_CACHE: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

// Common utility functions
pub fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn get_process_name_cached(pid: u32) -> String {
    let now = get_timestamp();
    
    // Check recent process starts FIRST (catches fast-exiting Chrome processes)
    if let Ok(recent) = RECENT_PROCESS_STARTS.lock() {
        if let Some(info) = recent.get(&pid) {
            // Extended validity window for recent starts (60 seconds)
            if now - info.cached_at < 60 {
                return info.name.clone();
            }
        }
    }
    
    // Check main cache
    if let Ok(cache) = PROCESS_NAME_CACHE.lock() {
        if let Some(info) = cache.get(&pid) {
            if now - info.cached_at < 60 {
                return info.name.clone();
            }
        }
    }
    
    // Try to resolve NOW (process might still be running)
    if let Some(name) = resolve_process_name(pid) {
        // Cache in BOTH places for redundancy
        if let Ok(mut cache) = PROCESS_NAME_CACHE.lock() {
            cache.insert(pid, ProcessInfo {
                name: name.clone(),
                cached_at: now,
                parent_pid: 0,
                command_line: None,
            });
        }
        if let Ok(mut recent) = RECENT_PROCESS_STARTS.lock() {
            recent.insert(pid, ProcessInfo {
                name: name.clone(),
                cached_at: now,
                parent_pid: 0,
                command_line: None,
            });
        }
        return name;
    }
    
    // Last resort - check if we have ANY cached info
    if let Ok(recent) = RECENT_PROCESS_STARTS.lock() {
        if let Some(info) = recent.get(&pid) {
            // Use even expired cache for fast-exiting processes
            log::debug!("Using expired cache for PID {} (age: {}s)", pid, now - info.cached_at);
            return info.name.clone();
        }
    }
    
    if let Ok(cache) = PROCESS_NAME_CACHE.lock() {
        if let Some(info) = cache.get(&pid) {
            log::debug!("Using expired main cache for PID {} (age: {}s)", pid, now - info.cached_at);
            return info.name.clone();
        }
    }
    
    String::from("Unknown")
}

pub fn cache_process_start(pid: u32, parent_pid: u32, process_name: &str, command_line: Option<String>) {
    let now = get_timestamp();
    let info = ProcessInfo {
        name: process_name.to_string(),
        cached_at: now,
        parent_pid,
        command_line: command_line.clone(),
    };
    
    // Store in BOTH caches immediately
    if let Ok(mut recent) = RECENT_PROCESS_STARTS.lock() {
        recent.insert(pid, info.clone());
        
        // Cleanup old entries (keep last 2000)
        if recent.len() > 2000 {
            recent.retain(|_, info| now - info.cached_at < 120); // Keep for 2 minutes
        }
    }
    
    if let Ok(mut cache) = PROCESS_NAME_CACHE.lock() {
        cache.insert(pid, info);
    }
}

pub fn is_chrome_subprocess(pid: u32, process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    
    // Direct chrome indicators
    if lower.contains("chrome") {
        return true;
    }
    
    // Check if parent is chrome
    if let Ok(cache) = PROCESS_NAME_CACHE.lock() {
        if let Some(info) = cache.get(&pid) {
            if info.parent_pid != 0 {
                if let Some(parent_info) = cache.get(&info.parent_pid) {
                    return parent_info.name.to_lowercase().contains("chrome");
                }
            }
        }
    }
    
    // Check recent starts
    if let Ok(recent) = RECENT_PROCESS_STARTS.lock() {
        if let Some(info) = recent.get(&pid) {
            if info.parent_pid != 0 {
                if let Some(parent_info) = recent.get(&info.parent_pid) {
                    return parent_info.name.to_lowercase().contains("chrome");
                }
            }
        }
    }
    
    false
}

pub fn is_browser_related_process(pid: u32, process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    
    // Main browser executables
    let browsers = vec![
        "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", 
        "brave.exe", "vivaldi.exe", "iexplore.exe", "edge.exe"
    ];
    
    if browsers.iter().any(|&b| lower.contains(b)) {
        return true;
    }
    
    // Check if it's a chrome subprocess
    if is_chrome_subprocess(pid, process_name) {
        return true;
    }
    
    // Browser helper processes
    let helpers = vec![
        "gpu-process", "renderer", "utility", "network-service",
        "storage-service", "plugin", "extension", "web-helper",
        "browser_broker", "browser helper", "crashpad", "nacl",
    ];
    
    if helpers.iter().any(|&h| lower.contains(h)) {
        return true;
    }
    
    // Chrome subprocess indicator
    if lower.contains("--type=") {
        return true;
    }
    
    false
}

pub fn create_connection_signature(pid: u32, saddr: &str, sport: u16, daddr: &str, dport: u16) -> String {
    format!("{}:{}->{}:{}", pid, saddr, daddr, dport)
}

pub fn is_common_short_lived_process(process_name: &str) -> bool {
    let common_short_lived = vec![
        "conhost.exe", "dllhost.exe", "runtimebroker.exe",
        "taskhostw.exe", "backgroundtaskhost.exe",
    ];
    
    let lower = process_name.to_lowercase();
    common_short_lived.iter().any(|&name| lower.contains(name))
}

pub fn cleanup_tracking_data() {
    let now = get_timestamp();
    
    // Main cache: keep for 5 minutes
    if let Ok(mut cache) = PROCESS_NAME_CACHE.lock() {
        cache.retain(|_, info| {
            let age = now - info.cached_at;
            // Keep chrome processes longer (10 minutes vs 5 minutes)
            if info.name.to_lowercase().contains("chrome") {
                age < 600
            } else {
                age < 300
            }
        });
    }
    
    // Recent starts: keep for 2 minutes
    if let Ok(mut recent) = RECENT_PROCESS_STARTS.lock() {
        recent.retain(|_, info| {
            let age = now - info.cached_at;
            // Keep chrome subprocesses longer (5 minutes vs 2 minutes)
            if info.name.to_lowercase().contains("chrome") {
                age < 300
            } else {
                age < 120
            }
        });
    }
    
    // Connection tracker: keep for 10 minutes
    if let Ok(mut tracker) = CONNECTION_TRACKER.lock() {
        tracker.retain(|_, attempts| {
            attempts.retain(|a| now - a.timestamp < 600);
            !attempts.is_empty()
        });
    }
    
    // Recent connections: clear when too large
    if let Ok(mut recent) = RECENT_CONNECTIONS.lock() {
        if recent.len() > 5000 {
            recent.clear();
        }
    }
}

use windows::Win32::{
    Foundation::CloseHandle,
    System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION},
    System::ProcessStatus::GetModuleFileNameExW,
};

pub fn resolve_process_name(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if handle.is_err() {
            return None;
        }
        let h = handle.unwrap();
        let mut buffer = [0u16; 260];
        let len = GetModuleFileNameExW(Some(h), None, &mut buffer);
        let _ = CloseHandle(h);
        if len > 0 {
            let name = String::from_utf16_lossy(&buffer[..len as usize]);
            return std::path::Path::new(&name)
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());
        }
        None
    }
}