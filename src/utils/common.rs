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

#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub name: String,
    pub cached_at: u64,
    pub parent_pid: u32,
}

#[derive(Clone, Debug)]
pub struct ConnectionAttempt {
    pub timestamp: u64,
    pub dest_addr: String,
    pub dest_port: u16,
}

pub struct CmdlineAnalysis {
    pub flags: Vec<String>,
    pub cmd_score: u8,
}

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
}

pub fn get_command_line_cached(pid: u32) -> Option<String> {
    let now = get_timestamp();

    if let Ok(cache) = COMMAND_LINE_CACHE.lock() {
        if let Some((cmdline, cached_at)) = cache.get(&pid) {
            if now - cached_at < 300 {
                return Some(cmdline.clone());
            }
        }
    }

    // Try PowerShell Get-Process first (fastest)
    if let Some(cmdline) = get_command_line_powershell(pid) {
        if let Ok(mut cache) = COMMAND_LINE_CACHE.lock() {
            cache.insert(pid, (cmdline.clone(), now));
        }
        return Some(cmdline);
    }

    // Fall back to CIM (Win32_Process)
    std::thread::sleep(std::time::Duration::from_millis(50));
    if let Some(cmdline) = get_command_line_cim(pid) {
        if let Ok(mut cache) = COMMAND_LINE_CACHE.lock() {
            cache.insert(pid, (cmdline.clone(), now));
        }
        return Some(cmdline);
    }

    None
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
            if !result.is_empty() && result != "null" { Some(result) } else { None }
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
            if !result.is_empty() && result != "null" { Some(result) } else { None }
        }
        _ => None,
    }
}

pub fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn get_parent_process_info(parent_pid: u32) -> (String, String) {
    if parent_pid == 0 {
        return (String::new(), String::new());
    }
    let parent_name = get_process_name_cached(parent_pid);
    let parent_cmdline = get_command_line_cached(parent_pid).unwrap_or_default();
    (parent_name, parent_cmdline)
}

pub fn get_process_name_cached(pid: u32) -> String {
    let now = get_timestamp();

    // Check recent starts first (catches fast-exiting processes)
    if let Ok(recent) = RECENT_PROCESS_STARTS.lock() {
        if let Some(info) = recent.get(&pid) {
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

    // Try to resolve now (process might still be running)
    if let Some(name) = resolve_process_name(pid) {
        let info = ProcessInfo { name: name.clone(), cached_at: now, parent_pid: 0 };
        if let Ok(mut cache) = PROCESS_NAME_CACHE.lock() {
            cache.insert(pid, info.clone());
        }
        if let Ok(mut recent) = RECENT_PROCESS_STARTS.lock() {
            recent.insert(pid, info);
        }
        return name;
    }

    // Last resort: return any stale cached value for fast-exiting processes
    if let Ok(recent) = RECENT_PROCESS_STARTS.lock() {
        if let Some(info) = recent.get(&pid) {
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

    let info = ProcessInfo {
        name: process_name.to_string(),
        cached_at: now,
        parent_pid,
    };

    if let Ok(mut recent) = RECENT_PROCESS_STARTS.lock() {
        recent.insert(pid, info.clone());
        if recent.len() > 2000 {
            recent.retain(|_, info| now - info.cached_at < 120);
        }
    }
    if let Ok(mut cache) = PROCESS_NAME_CACHE.lock() {
        cache.insert(pid, info);
    }

    if let Some(cmdline) = command_line {
        if is_scripting_engine(process_name, &cmdline) {
            cache_scripting_engine(pid);
        }
        if let Ok(mut cmd_cache) = COMMAND_LINE_CACHE.lock() {
            cmd_cache.insert(pid, (cmdline, now));
        }
    }
}

pub fn cache_scripting_engine(pid: u32) {
    if let Ok(mut cache) = SCRIPTING_ENGINE_CACHE.lock() {
        cache.insert(pid);
    }
}

pub fn resolve_process_name(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buffer = [0u16; 260];
        let len = GetModuleFileNameExW(Some(handle), None, &mut buffer);
        let _ = CloseHandle(handle);
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

pub fn cleanup_tracking_data() {
    let now = get_timestamp();

    if let Ok(mut cache) = PROCESS_NAME_CACHE.lock() {
        cache.retain(|_, info| {
            let age = now - info.cached_at;
            if info.name.to_lowercase().contains("chrome") { age < 600 } else { age < 300 }
        });
    }

    if let Ok(mut recent) = RECENT_PROCESS_STARTS.lock() {
        recent.retain(|_, info| {
            let age = now - info.cached_at;
            if info.name.to_lowercase().contains("chrome") { age < 300 } else { age < 120 }
        });
    }

    if let Ok(mut tracker) = CONNECTION_TRACKER.lock() {
        tracker.retain(|_, attempts| {
            attempts.retain(|a| now - a.timestamp < 600);
            !attempts.is_empty()
        });
    }

    if let Ok(mut recent) = RECENT_CONNECTIONS.lock() {
        if recent.len() > 5000 {
            recent.clear();
        }
    }
}

/// Returns true for OS processes that should be silently ignored by all monitors.
pub fn is_system_process(process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    lower.contains("svchost.exe") ||
    lower.contains("system") ||
    lower.contains("csrss.exe") ||
    lower.contains("wininit.exe") ||
    lower.contains("services.exe") ||
    lower.contains("lsass.exe") ||
    lower.contains("winlogon.exe") ||
    lower.contains("explorer.exe") ||
    lower.contains("dwm.exe") ||
    lower.contains("taskhostw.exe") ||
    lower.contains("endpoint-threat-detection")
}

pub fn is_network_aware_process(process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    lower.contains("chrome.exe") ||
    lower.contains("firefox.exe") ||
    lower.contains("msedge.exe") ||
    lower.contains("spotify.exe") ||
    lower.contains("teams.exe") ||
    lower.contains("slack.exe") ||
    lower.contains("zoom.exe") ||
    lower.contains("discord.exe") ||
    lower.contains("outlook.exe") ||
    lower.contains("thunderbird.exe")
}

pub fn is_scripting_engine(process_name: &str, command_line: &str) -> bool {
    let lower_name = process_name.to_lowercase();
    let lower_cmd = command_line.to_lowercase();

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

    // LOLBAS patterns
    if lower_name.contains("rundll32.exe") && lower_cmd.contains(".dll,") {
        return true;
    }
    if lower_name.contains("regsvr32.exe") &&
       (lower_cmd.contains(".dll") || lower_cmd.contains("/i:") || lower_cmd.contains("/s")) {
        return true;
    }
    if (lower_name.contains("certutil.exe") ||
        lower_name.contains("bitsadmin.exe") ||
        lower_name.contains("wmic.exe")) &&
       (lower_cmd.contains("http://") || lower_cmd.contains("https://") || lower_cmd.contains(".xml")) {
        return true;
    }

    false
}

/// Legitimate, well-known processes that are not expected to be involved in malicious activity.
/// NOTE: Being known-good suppresses beaconing/scoring heuristics but does NOT suppress IOC hits.
pub fn is_known_good_process(process_name: &str, command_line: &str) -> bool {
    const KNOWN_GOOD: &[&str] = &[
        // Browsers
        "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
        // Development tools
        "code.exe", "devenv.exe", "intellij.exe", "pycharm.exe", "webstorm.exe",
        // Communication
        "teams.exe", "slack.exe", "discord.exe", "zoom.exe", "skype.exe",
        // Cloud storage
        "onedrive.exe", "dropbox.exe", "googledrivesync.exe",
        // Music/Media
        "spotify.exe", "vlc.exe", "itunes.exe",
        // Gaming
        "steam.exe", "epicgameslauncher.exe", "battle.net.exe",
        // NVIDIA
        "nvidia overlay.exe", "nvsphelper64.exe",
        // Windows components
        "searchhost.exe", "backgroundtaskhost.exe", "runtimebroker.exe",
        // Creative / Office
        "adobe creative cloud.exe", "creative cloud.exe", "ccxprocess.exe",
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    ];
    const LEGIT_PS_PATTERNS: &[&str] = &[
        "get-process", "get-service", "get-eventlog", "import-module",
        "update-help", "get-help", "get-command", "start-service",
        "stop-service", "restart-service", "get-wmiobject", "get-ciminstance",
    ];

    let lower_name = process_name.to_lowercase();
    let lower_cmd = command_line.to_lowercase();

    if KNOWN_GOOD.iter().any(|&p| lower_name.contains(p)) {
        return true;
    }

    // PowerShell running common admin commands is considered known-good
    if lower_name.contains("powershell.exe") {
        if LEGIT_PS_PATTERNS.iter().any(|&p| lower_cmd.contains(p)) {
            return true;
        }
    }
    false
}

/// Returns true for suspicious parent→child process relationships that indicate
/// living-off-the-land or script-based lateral movement.
pub fn is_suspicious_parent_process(child_name: &str, parent_name: &str) -> bool {
    let child_lower = child_name.to_lowercase();
    let parent_lower = parent_name.to_lowercase();

    // PowerShell spawning PowerShell is the canonical spawn-and-exit evasion pattern.
    (parent_lower.contains("powershell") && child_lower.contains("powershell")) ||
    (parent_lower.contains("pwsh") && child_lower.contains("powershell")) ||
    (parent_lower.contains("powershell") && child_lower.contains("pwsh")) ||
    // Scripts/documents spawning shells
    (parent_lower.contains("explorer.exe") && child_lower.contains("powershell.exe")) ||
    (parent_lower.contains("svchost.exe") && child_lower.contains("cmd.exe")) ||
    (parent_lower.contains("services.exe") && child_lower.contains("wscript.exe")) ||
    (parent_lower.contains("winword.exe") && child_lower.contains("powershell.exe")) ||
    (parent_lower.contains("excel.exe") && child_lower.contains("cmd.exe")) ||
    (parent_lower.contains("outlook.exe") && child_lower.contains("powershell.exe")) ||
    // cmd/wscript spawning powershell
    (parent_lower.contains("cmd.exe") && child_lower.contains("powershell.exe")) ||
    (parent_lower.contains("wscript.exe") && child_lower.contains("powershell.exe")) ||
    (parent_lower.contains("cscript.exe") && child_lower.contains("powershell.exe"))
}

pub fn is_chrome_subprocess(pid: u32, process_name: &str) -> bool {
    if process_name.to_lowercase().contains("chrome") {
        return true;
    }
    // Check the parent in whichever cache has it
    if let Ok(locked) = PROCESS_NAME_CACHE.lock() {
        if let Some(info) = locked.get(&pid) {
            if info.parent_pid != 0 {
                if let Some(parent_info) = locked.get(&info.parent_pid) {
                    return parent_info.name.to_lowercase().contains("chrome");
                }
            }
        }
    }
    if let Ok(locked) = RECENT_PROCESS_STARTS.lock() {
        if let Some(info) = locked.get(&pid) {
            if info.parent_pid != 0 {
                if let Some(parent_info) = locked.get(&info.parent_pid) {
                    return parent_info.name.to_lowercase().contains("chrome");
                }
            }
        }
    }
    false
}

pub fn is_browser_related_process(pid: u32, process_name: &str) -> bool {
    const BROWSERS: &[&str] = &[
        "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
        "brave.exe", "vivaldi.exe", "iexplore.exe", "edge.exe",
    ];
    const BROWSER_HELPERS: &[&str] = &[
        "gpu-process", "renderer", "utility", "network-service",
        "storage-service", "plugin", "extension", "web-helper",
        "browser_broker", "browser helper", "crashpad", "nacl",
    ];

    let lower = process_name.to_lowercase();

    BROWSERS.iter().any(|&b| lower.contains(b))
        || is_chrome_subprocess(pid, process_name)
        || BROWSER_HELPERS.iter().any(|&h| lower.contains(h))
        || lower.contains("--type=")  // Chrome subprocess flag
}

pub fn analyze_command_line(command_line: &str) -> CmdlineAnalysis {
    let mut flags = Vec::new();
    let lower_cmd = command_line.to_lowercase();
    let mut cmd_score = 0u8;
    
    let has_bypass  = lower_cmd.contains("-executionpolicy bypass") || lower_cmd.contains("-ep bypass");
    let has_hidden  = lower_cmd.contains("-windowstyle hidden")     || lower_cmd.contains("-w hidden");
    let has_noprof  = lower_cmd.contains("-noprofile")              || lower_cmd.contains("-nop");
    let has_nointer = lower_cmd.contains("-noninteractive")         || lower_cmd.contains("-noni");
    let has_encoded = lower_cmd.contains("-encodedcommand")         || lower_cmd.contains("-enc ");
    let has_file    = lower_cmd.contains(" -file ")                 || lower_cmd.contains(" -f ");

    if has_bypass  { flags.push("-ExecutionPolicy Bypass".to_string());  cmd_score = cmd_score.saturating_add(1); }
    if has_hidden  { flags.push("-WindowStyle Hidden".to_string());      cmd_score = cmd_score.saturating_add(1); }
    if has_noprof  { flags.push("-NoProfile".to_string());               cmd_score = cmd_score.saturating_add(1); }
    if has_nointer { flags.push("-NonInteractive".to_string()); }

    if has_nointer && has_hidden {
        cmd_score = cmd_score.saturating_add(1);
    }
    if has_encoded {
        flags.push("-EncodedCommand".to_string());
        cmd_score = cmd_score.saturating_add(2);
    }
    if has_bypass && has_hidden && has_noprof {
        cmd_score = cmd_score.saturating_add(2);
    }
    if has_bypass && has_hidden && has_file {
        cmd_score = cmd_score.saturating_add(1);
    }
    if lower_cmd.contains("iex ") || lower_cmd.contains("invoke-expression") {
        flags.push("Invoke-Expression".to_string());
        cmd_score = cmd_score.saturating_add(1);
    }
    if lower_cmd.contains("-join") || lower_cmd.contains("`") {
        cmd_score = cmd_score.saturating_add(1);
    }
    if lower_cmd.contains("[char]") {
        cmd_score = cmd_score.saturating_add(1);
    }
    if lower_cmd.contains("getasynckeystate") {
        flags.push("Keylogging API".to_string());
        cmd_score = cmd_score.saturating_add(3);
    }
    if lower_cmd.contains("getkeystate") {
        cmd_score = cmd_score.saturating_add(3);
    }
    if lower_cmd.contains("setwindowshookex") || lower_cmd.contains("setkeyboardhook") {
        cmd_score = cmd_score.saturating_add(3);
    }
    if lower_cmd.contains("dllimport") && lower_cmd.contains("user32.dll") {
        cmd_score = cmd_score.saturating_add(3);
    }
    if lower_cmd.contains("system.runtime.interopservices") {
        cmd_score = cmd_score.saturating_add(2);
    }
    if lower_cmd.contains("add-type") && lower_cmd.contains("system.windows.forms") {
        cmd_score = cmd_score.saturating_add(2);
    }
    const SPECIAL_KEYS: &[&str] = &["[backspace]","[enter]","[tab]","[shift]","[ctrl]","[alt]"];
    let sk_count = SPECIAL_KEYS.iter().filter(|&&k| lower_cmd.contains(k)).count();
    if sk_count >= 2 {
        cmd_score = cmd_score.saturating_add(2);
    }
    if lower_cmd.contains("currentversion\\run") || lower_cmd.contains("currentversion/run") {
        cmd_score = cmd_score.saturating_add(2);
    }
    if (lower_cmd.contains("while ($true)") || lower_cmd.contains("while (1)"))
        && lower_cmd.contains("start-sleep")
    {
        cmd_score = cmd_score.saturating_add(2);
    }
    if lower_cmd.contains("$env:appdata") && lower_cmd.contains(".txt") {
        cmd_score = cmd_score.saturating_add(1);
    }
    if lower_cmd.contains("downloadstring") || lower_cmd.contains("downloadfile") {
        flags.push("Web Client Download".to_string());
        cmd_score = cmd_score.saturating_add(1);
    }
    if lower_cmd.contains("frombase64string") {
        cmd_score = cmd_score.saturating_add(2);
    }
    if lower_cmd.contains("frombase64string") ||
       lower_cmd.contains("[convert]::") ||
       (lower_cmd.contains("-f ") && lower_cmd.contains("{0}")) {
        flags.push("Obfuscation Patterns".to_string());
    }
    CmdlineAnalysis { flags, cmd_score }
}

/// Returns a label if the process and command line match a known LOLBAS abuse pattern,
/// or `None` if no match.
pub fn identify_lolbas_abuse(process_name: &str, command_line: &str) -> Option<&'static str> {
    let lower_name = process_name.to_lowercase();
    let lower_cmd = command_line.to_lowercase();

    match lower_name.as_str() {
        "rundll32.exe" => {
            if lower_cmd.contains(".dll,") &&
               (lower_cmd.contains("http://") || lower_cmd.contains("https://") ||
                lower_cmd.contains("regsvr") || lower_cmd.contains("javascript:"))
            {
                if lower_cmd.contains("javascript:") {
                    return Some("Rundll32 JavaScript Execution");
                }
                return Some("Rundll32 Remote DLL Load");
            }
        }
        "regsvr32.exe" => {
            if lower_cmd.contains("/s") &&
               (lower_cmd.contains("http://") || lower_cmd.contains("https://") ||
                lower_cmd.contains(".sct") || lower_cmd.contains(".scrobj"))
            {
                if lower_cmd.contains(".sct") {
                    return Some("Regsvr32 SCT Scriptlet Execution");
                }
                return Some("Regsvr32 Remote Script Execution");
            }
        }
        "mshta.exe" => {
            if lower_cmd.contains("http://") || lower_cmd.contains("https://") ||
               lower_cmd.contains("javascript:") || lower_cmd.contains("vbscript:")
            {
                return Some("Mshta Remote Script Execution");
            }
        }
        "certutil.exe" => {
            if lower_cmd.contains("-urlcache") || lower_cmd.contains("-split") ||
               lower_cmd.contains("-decode") || lower_cmd.contains("-encode")
            {
                if lower_cmd.contains("-urlcache") {
                    return Some("Certutil File Download");
                }
                return Some("Certutil Encode/Decode Abuse");
            }
        }
        "bitsadmin.exe" => {
            if lower_cmd.contains("/transfer") || lower_cmd.contains("/create") ||
               lower_cmd.contains("/addfile") || lower_cmd.contains("/setnotifycmdline")
            {
                return Some("Bitsadmin File Transfer");
            }
        }
        "wmic.exe" => {
            if lower_cmd.contains("process call create") ||
               (lower_cmd.contains("/node:") && lower_cmd.contains("process create"))
            {
                return Some("WMIC Remote Process Creation");
            }
        }
        _ => {}
    }
    None
}

/// Returns true if the address is a loopback, RFC-1918 private, link-local, or
/// unspecified address that should not be treated as an external connection.
pub fn is_private_or_local(addr: &str) -> bool {
    if addr.starts_with("127.") || addr.starts_with("192.168.") {
        return true;
    }
    if addr.starts_with("10.") {
        return true;
    }
    if addr.starts_with("172.") {
        // RFC-1918: 172.16.0.0 – 172.31.255.255
        let second_octet: Option<u8> = addr.split('.').nth(1).and_then(|o| o.parse().ok());
        if let Some(n) = second_octet {
            if (16..=31).contains(&n) {
                return true;
            }
        }
    }
    // IPv6 loopback
    if addr == "::1" || addr == "0:0:0:0:0:0:0:1" {
        return true;
    }
    // Unspecified / any-address
    if addr == "0.0.0.0" {
        return true;
    }
    false
}

pub fn is_suspicious_domain(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    // High digit count suggests DGA
    if lower.chars().filter(|c| c.is_ascii_digit()).count() > 5 {
        return true;
    }
    // Excessive subdomains
    if lower.matches('.').count() > 4 {
        return true;
    }
    // Suspicious TLDs
    const SUSPICIOUS_TLDS: &[&str] = &[".xyz", ".top", ".club", ".bid", ".win", ".gq", ".ml", ".cf"];
    SUSPICIOUS_TLDS.iter().any(|tld| lower.ends_with(tld))
}

const PORT_METADATA: &[(u16, bool, &str)] = &[
    (4444,  true,  "Metasploit default"),
    (31337, true,  "Back Orifice"),
    (6667,  true,  "IRC"),
    (6660,  true,  "IRC"),
    (9999,  true,  "Common malware"),
    (5555,  true,  "Common malware"),
    (8877,  true,  "Common malware"),
    (1337,  true,  "Elite/Leet port"),
    (1234,  true,  "Common malware / test port"),
    (4321,  true,  "Common malware / test port"),
    (6789,  true,  "Common malware"),
    (9898,  true,  "Common malware"),
    (9988,  true,  "Common malware"),
    (2333,  true,  "Common malware"),
    (2334,  true,  "Common malware"),
    (3389,  false, "RDP"),
    (22,    false, "SSH"),
    (23,    false, "Telnet"),
    (21,    false, "FTP"),
    (25,    false, "SMTP"),
    (110,   false, "POP3"),
    (143,   false, "IMAP"),
    (445,   false, "SMB"),
    (135,   false, "RPC"),
];

pub fn is_high_risk_port(port: u16) -> bool {
    PORT_METADATA.iter().any(|&(p, high_risk, _)| p == port && high_risk)
}

pub fn describe_port(port: u16) -> &'static str {
    PORT_METADATA.iter()
        .find(|&&(p, _, _)| p == port)
        .map(|&(_, _, desc)| desc)
        .unwrap_or("Unknown")
}

pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}