use crate::events::BaseEvent;
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::collections::{HashSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Mutex;
use windows::Win32::{
    System::ProcessStatus::GetModuleFileNameExW,
    System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    Foundation::CloseHandle,
};

// Shared data structures
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub name: String,
    pub cached_at: u64,
    pub parent_pid: u32,
    pub command_line: Option<String>,
    pub is_scripting_engine: bool,
    pub suspicious_flags: Vec<String>,
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
    pub static ref COMMAND_LINE_CACHE: Mutex<HashMap<u32, (String, u64)>> = Mutex::new(HashMap::new());
    pub static ref SCRIPTING_ENGINE_CACHE: Mutex<HashSet<u32>> = Mutex::new(HashSet::new());
    pub static ref WEBHOOK_DOMAINS: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

// Common utility functions
pub fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn get_command_line_cached(pid: u32) -> Option<String> {
    let now = get_timestamp();
    
    // Check cache first
    if let Ok(cache) = COMMAND_LINE_CACHE.lock() {
        if let Some((cmdline, cached_at)) = cache.get(&pid) {
            let age = now - cached_at;
            if age < 300 {
                return Some(cmdline.clone());
            }
        }
    }
    
    // Try FAST method first (Powershell Get-Process)
    if let Some(cmdline) = get_command_line_powershell(pid) {
        if let Ok(mut cache) = COMMAND_LINE_CACHE.lock() {
            cache.insert(pid, (cmdline.clone(), now));
        }
        return Some(cmdline);
    }
    
    // Try CIM (newer, works on Windows 8+)
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    if let Some(cmdline) = get_command_line_cim(pid) {
        if let Ok(mut cache) = COMMAND_LINE_CACHE.lock() {
            cache.insert(pid, (cmdline.clone(), now));
        }
        return Some(cmdline);
    }
    
    // Try tasklist as last resort
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    if let Some(cmdline) = get_command_line_tasklist(pid) {
        if let Ok(mut cache) = COMMAND_LINE_CACHE.lock() {
            cache.insert(pid, (cmdline.clone(), now));
        }
        return Some(cmdline);
    }
    None
}

pub fn get_parent_process_info(parent_pid: u32) -> (String, String) {
    if parent_pid == 0 {
        return ("".to_string(), "".to_string());
    }
    
    let parent_name = get_process_name_cached(parent_pid);
    let parent_cmdline = get_command_line_cached(parent_pid).unwrap_or_default();
    
    (parent_name, parent_cmdline)
}

pub fn is_scripting_engine(process_name: &str, command_line: &str) -> bool {
    let lower_name = process_name.to_lowercase();
    let lower_cmd = command_line.to_lowercase();
    
    // Primary scripting engines
    if lower_name.contains("powershell.exe") ||
       lower_name.contains("pwsh.exe") ||
       lower_name.contains("cmd.exe") ||
       lower_name.contains("wscript.exe") ||
       lower_name.contains("cscript.exe") ||
       lower_name.contains("mshta.exe") ||
       lower_name.ends_with(".ps1") ||
       lower_name.ends_with(".vbs") ||
       lower_name.ends_with(".js") ||
       lower_name.ends_with(".hta") {
        return true;
    }
    
    // Check for LOLBAS patterns
    if lower_name.contains("rundll32.exe") && lower_cmd.contains(".dll,") {
        return true;
    }
    
    if lower_name.contains("regsvr32.exe") && 
       (lower_cmd.contains(".dll") || lower_cmd.contains("/i:") || lower_cmd.contains("/s")) {
        return true;
    }
    
    // Check for certutil, bitsadmin, wmic with script-like arguments
    if (lower_name.contains("certutil.exe") || 
        lower_name.contains("bitsadmin.exe") || 
        lower_name.contains("wmic.exe")) &&
       (lower_cmd.contains("http://") || lower_cmd.contains("https://") || lower_cmd.contains(".xml")) {
        return true;
    }
    
    false
}

pub fn analyze_command_line(process_name: &str, command_line: &str) -> Vec<String> {
    let mut suspicious_flags = Vec::new();
    let lower_name = process_name.to_lowercase();
    let lower_cmd = command_line.to_lowercase();
    
    // PowerShell-specific suspicious flags
    if lower_name.contains("powershell") {
        if lower_cmd.contains("-windowstyle hidden") || lower_cmd.contains("-w hidden") {
            suspicious_flags.push("-WindowStyle Hidden".to_string());
        }
        if lower_cmd.contains("-executionpolicy bypass") || lower_cmd.contains("-ep bypass") {
            suspicious_flags.push("-ExecutionPolicy Bypass".to_string());
        }
        if lower_cmd.contains("-noprofile") || lower_cmd.contains("-nop") {
            suspicious_flags.push("-NoProfile".to_string());
        }
        if lower_cmd.contains("-encodedcommand") || lower_cmd.contains("-e ") {
            suspicious_flags.push("-EncodedCommand".to_string());
        }
        if lower_cmd.contains("-noninteractive") {
            suspicious_flags.push("-NonInteractive".to_string());
        }
        if lower_cmd.contains("iex ") || lower_cmd.contains("invoke-expression") {
            suspicious_flags.push("Invoke-Expression".to_string());
        }
        if lower_cmd.contains("downloadstring") || lower_cmd.contains("downloadfile") {
            suspicious_flags.push("Web Client Download".to_string());
        }
        if lower_cmd.contains("getasynckeystate") || lower_cmd.contains("keylog") {
            suspicious_flags.push("Keylogging API".to_string());
        }
    }
    
    // Generic suspicious patterns
    if lower_cmd.contains("webhook") || lower_cmd.contains("discord.com/api/webhooks") {
        suspicious_flags.push("Webhook URL".to_string());
    }
    
    if lower_cmd.contains("http://") || lower_cmd.contains("https://") {
        if lower_name.contains("powershell") || lower_name.contains("cmd") || 
           lower_name.contains("wscript") || lower_name.contains("cscript") {
            suspicious_flags.push("Network Download in Script".to_string());
        }
    }
    
    // Obfuscation patterns
    if lower_cmd.contains("frombase64string") || 
       lower_cmd.contains("[convert]::") ||
       lower_cmd.contains("-f ") && lower_cmd.contains("{0}") {
        suspicious_flags.push("Obfuscation Patterns".to_string());
    }
    
    suspicious_flags
}

pub fn cache_scripting_engine(pid: u32) {
    if let Ok(mut cache) = SCRIPTING_ENGINE_CACHE.lock() {
        cache.insert(pid);
    }
}

pub fn is_cached_scripting_engine(pid: u32) -> bool {
    if let Ok(cache) = SCRIPTING_ENGINE_CACHE.lock() {
        cache.contains(&pid)
    } else {
        false
    }
}

fn get_command_line_powershell(pid: u32) -> Option<String> {
    use std::process::Command;
    
    let ps_cmd = format!(
        "Get-Process -Id {} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CommandLine",
        pid
    );
    
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
        .output();
    
    match output {
        Ok(output) if output.status.success() => {
            let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !result.is_empty() && result != "null" {
                Some(result)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn get_command_line_cim(pid: u32) -> Option<String> {
    use std::process::Command;
    
    let cim_cmd = format!(
        "Get-CimInstance Win32_Process -Filter \"ProcessId = {}\" | Select-Object -ExpandProperty CommandLine",
        pid
    );
    
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", &cim_cmd])
        .output();
    
    match output {
        Ok(output) if output.status.success() => {
            let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !result.is_empty() && result != "null" {
                Some(result)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn get_command_line_tasklist(pid: u32) -> Option<String> {
    use std::process::Command;
    
    let output = Command::new("tasklist")
        .args(&["/fi", &format!("PID eq {}", pid), "/fo", "csv", "/v"])
        .output();
    
    match output {
        Ok(output) if output.status.success() => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = output_str.lines().collect();
            if lines.len() > 1 {
                // CSV format: "Image Name","PID","Session Name",...
                let parts: Vec<&str> = lines[1].split(',').collect();
                if !parts.is_empty() {
                    // Get image name (not full command line, but better than nothing)
                    let image_name = parts[0].trim_matches('"').to_string();
                    if !image_name.is_empty() {
                        return Some(image_name);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

pub fn does_process_exist(pid: u32) -> bool {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER};
    
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        match handle {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => {
                // Invalid parameter usually means process doesn't exist
                false
            }
            Err(_) => {
                // Other error - process might exist but we can't access it
                false
            }
        }
    }
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
                is_scripting_engine: false,
                suspicious_flags: Vec::new(),
            });
        }
        if let Ok(mut recent) = RECENT_PROCESS_STARTS.lock() {
            recent.insert(pid, ProcessInfo {
                name: name.clone(),
                cached_at: now,
                parent_pid: 0,
                command_line: None,
                is_scripting_engine: false,
                suspicious_flags: Vec::new(),
            });
        }
        return name;
    }
    
    // Last resort - check if we have ANY cached info
    if let Ok(recent) = RECENT_PROCESS_STARTS.lock() {
        if let Some(info) = recent.get(&pid) {
            // Use even expired cache for fast-exiting processes
            return info.name.clone();
        }
    }
    
    if let Ok(cache) = PROCESS_NAME_CACHE.lock() {
        if let Some(info) = cache.get(&pid) {
            return info.name.clone();
        }
    }
    
    String::from("Unknown")
}

pub fn cache_process_start(pid: u32, parent_pid: u32, process_name: &str, command_line: Option<String>) {
    let now = get_timestamp();
    let cmdline_str = command_line.clone().unwrap_or_default();
    
    let is_scripting = is_scripting_engine(process_name, &cmdline_str);
    let suspicious_flags = if is_scripting {
        analyze_command_line(process_name, &cmdline_str)
    } else {
        Vec::new()
    };
    
    let info = ProcessInfo {
        name: process_name.to_string(),
        cached_at: now,
        parent_pid,
        command_line: command_line.clone(),
        is_scripting_engine: is_scripting,
        suspicious_flags: suspicious_flags.clone(),
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
    
    // Cache command line separately
    if let Some(cmdline) = command_line {
        if let Ok(mut cmd_cache) = COMMAND_LINE_CACHE.lock() {
            cmd_cache.insert(pid, (cmdline, now));
        }
    }
    
    // Cache scripting engine status
    if is_scripting {
        cache_scripting_engine(pid);
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

pub fn resolve_process_name(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
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