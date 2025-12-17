use shared::{ProcessEvent, NetworkEvent, Alert};
use std::collections::HashMap;
use std::sync::Mutex;
use std::fs;
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;

lazy_static! {
    static ref NET_COUNT: Mutex<HashMap<u32, u32>> = Mutex::new(HashMap::new());
}

/// Detects Office applications spawning PowerShell
pub fn detect_office_powershell(event: &ProcessEvent) -> Option<Alert> {
    let parent = event.parent_image.to_lowercase();
    let image = event.image.to_lowercase();
    
    let office_apps = ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"];
    
    let is_office_parent = office_apps.iter().any(|app| parent.ends_with(app));
    let is_powershell = image.ends_with("powershell.exe") || image.ends_with("pwsh.exe");

    // Only skip if BOTH signed AND no suspicious command line
    if event.is_signed && event.command_line == "Unknown" {
        return None;
    }
    
    if is_office_parent && is_powershell {
        let mut alert = Alert::new(
            "HIGH",
            "Office spawned PowerShell",
            &event.image,
            &event.parent_image,
        );
        alert.command_line = Some(event.command_line.clone());
        alert.details = Some(format!(
            "Office application spawned PowerShell. PID: {}, Parent PID: {}",
            event.pid, event.parent_pid
        ));
        return Some(alert);
    }
    
    None
}

/// Detects unsigned processes making network connections
/// WITH WHITELIST to reduce false positives
pub fn detect_unsigned_network(proc: &ProcessEvent, net: &NetworkEvent) -> Option<Alert> {
    if net.pid != proc.pid {
        return None;
    }

    if proc.is_signed {
        return None;
    }

    if proc.pid <= 10 {
        return None;
    }

    if net.remote_addr == "127.0.0.1" || net.remote_addr == "[::1]" {
        return None;
    }

    let start_time = DateTime::parse_from_rfc3339(&proc.timestamp).ok()?;
    let age = Utc::now().signed_duration_since(start_time.with_timezone(&Utc));
    if age.num_seconds() > 120 {
        return None;
    }

    let mut counts = NET_COUNT.lock().unwrap();
    let count = counts.entry(proc.pid).or_insert(0);
    *count += 1;

    if *count < 3 {
        return None;
    }

    let image_lower = proc.image.to_lowercase();

    let whitelist = [
        // Browsers 
        "chrome.exe",
        "firefox.exe",
        "msedge.exe",
        "msedgewebview2.exe",
        "iexplore.exe",
        // Communication
        "teams.exe",
        "slack.exe",
        "discord.exe",
        "zoom.exe",
        "skype.exe",
        // Microsoft
        "onedrive.exe",
        "outlook.exe",
        "svchost.exe",
        "backgroundtaskhost.exe",
        "runtimebroker.exe",
        "searchprotocolhost.exe",
        "systemsettings.exe",
        // Development
        "code.exe",
        "devenv.exe",
        "rider.exe",
        "idea.exe",
        // System
        "explorer.exe",
        "dwm.exe",
        "csrss.exe",
        "lsass.exe",
        "services.exe",
        "audiodg.exe",
        "conhost.exe",
        "taskhostw.exe",
        "spoolsv.exe",
        // Windows Store apps
        "applicationframehost.exe",
        "xaml.exe",
        "smartscreen.exe",
        // Other legitimate
        "steam.exe",
        "epic games launcher.exe",
        "spotify.exe",
        "dropbox.exe",
    ];
    
    for allowed in &whitelist {
        if image_lower.ends_with(allowed) || image_lower.contains(allowed) {
            return None;
        }
    }

    let suspicious_dirs = [
        "\\windows\\temp\\",
        "\\windows\\tasks\\",
        "\\windows\\debug\\",
        "\\users\\public\\",
    ];

    if !suspicious_dirs.iter().any(|d| image_lower.contains(d)) {
        return None;
    }

    counts.remove(&proc.pid); // reset counter

    let mut alert = Alert::new(
        "LOW",
        "Suspicious unsigned process with network activity",
        &proc.image,
        &proc.parent_image,
    );

    alert.details = Some(format!(
        "Unsigned process made repeated external connections to {}:{}",
        net.remote_addr, net.remote_port
    ));
    Some(alert)
}

/// Detects possible keylogger behavior
pub fn detect_possible_keylogger(proc: &ProcessEvent, net: &NetworkEvent) -> Option<Alert> {
    if net.pid != proc.pid {
        return None;
    }
    
    let image_lower = proc.image.to_lowercase();
    
    // Only alert for truly suspicious locations
    let suspicious_locations = [
        "\\temp\\",
        "\\appdata\\local\\temp\\",
        "\\downloads\\",
        "\\public\\",
        "\\users\\public\\",
    ];
    
    let is_suspicious_location = suspicious_locations.iter()
        .any(|loc| image_lower.contains(loc));
    
    if is_suspicious_location && !proc.is_signed {
        let mut alert = Alert::new(
            "HIGH",
            "Possible keylogger - unsigned process from suspicious location",
            &proc.image,
            &proc.parent_image,
        );
        alert.details = Some(format!(
            "Process from suspicious directory with network activity. Remote: {}:{}",
            net.remote_addr, net.remote_port
        ));
        return Some(alert);
    }
    
    None
}

/// Detects suspicious command line patterns
pub fn detect_suspicious_cmdline(event: &ProcessEvent) -> Option<Alert> {
    let cmdline_lower = event.command_line.to_lowercase();
    
    // LOLBin patterns
    let suspicious_patterns = [
        "iex",
        "invoke-expression",
        "downloadstring",
        "downloadfile",
        "-encodedcommand",
        "-enc ",
        "bypass",
        "invoke-webrequest",
        "certutil -decode",
        "certutil -urlcache",
        "bitsadmin /transfer",
        "regsvr32 /s /u /i:",
        "mshta http",
        "rundll32 javascript:",
    ];
    
    // Only escalate when the process is unsigned (more likely malicious)
    // or when the pattern is high-confidence (encoded commands, downloads, certutil, etc.)
    let high_confidence = ["-encodedcommand", "-enc ", "downloadstring", "downloadfile", "certutil -decode", "certutil -urlcache", "bitsadmin /transfer"];

    for pattern in &suspicious_patterns {
        if cmdline_lower.contains(pattern) {
            let is_high = high_confidence.iter().any(|h| cmdline_lower.contains(h));

            if event.is_signed && !is_high {
                // Signed binaries calling low-confidence patterns (like plain 'iex') are often benign
                continue;
            }

            let mut alert = Alert::new(
                "HIGH",
                "Suspicious command line detected",
                &event.image,
                &event.parent_image,
            );
            alert.command_line = Some(event.command_line.clone());
            alert.details = Some(format!("Detected suspicious pattern: {}", pattern));
            return Some(alert);
        }
    }
    
    None
}

/// Detects PowerShell or other commands attempting to disable Windows Defender or tamper with security
pub fn detect_defender_disable_by_cmdline(event: &ProcessEvent) -> Option<Alert> {
    let cmd = event.command_line.to_lowercase();

    let defender_disable_patterns = [
        "set-mppreference",
        "disablerealtimemonitoring",
        "disable-realtimemonitoring",
        "stop-service windefend",
        "sc stop windefend",
        "remove-mppreference",
        "mpcmdrun -disable",
        "tamper",
        "uninstall-windowsfeature windows-defender",
        "disable-windowsdefender",
    ];

    for p in &defender_disable_patterns {
        if cmd.contains(p) {
            let mut alert = Alert::new(
                "HIGH",
                "Attempt to disable Windows Defender detected",
                &event.image,
                &event.parent_image,
            );
            alert.command_line = Some(event.command_line.clone());
            alert.details = Some(format!("Command matched defender-disable pattern: {}", p));
            return Some(alert);
        }
    }

    None
}

/// Detects use of Discord webhooks (common exfiltration in scripts)
pub fn detect_discord_webhook_in_cmdline(event: &ProcessEvent) -> Option<Alert> {
    let cmd = event.command_line.to_lowercase();
    if cmd.contains("discord.com/api/webhooks") || cmd.contains("discordapp.com/api/webhooks") {
        let mut alert = Alert::new(
            "HIGH",
            "Discord webhook exfiltration detected",
            &event.image,
            &event.parent_image,
        );
        alert.command_line = Some(event.command_line.clone());
        alert.details = Some("Command line contains a Discord webhook URL (possible data exfiltration).".to_string());
        return Some(alert);
    }

    None
}

/// Detect PowerShell launched hidden from a non-system drive (likely removable/CIRCUITPY) with a script file.
/// Matches patterns like: powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File D:/keylogger.ps1
pub fn detect_powershell_hidden_from_removable(event: &ProcessEvent) -> Option<Alert> {
    let image_lower = event.image.to_lowercase();
    let cmd = event.command_line.to_lowercase();
    if !(image_lower.ends_with("powershell.exe") || image_lower.ends_with("pwsh.exe")) {
        return None;
    }

    if !cmd.contains("-windowstyle hidden") {
        return None;
    }

    // Find the token after -file (if any)
    if let Some(idx) = cmd.find("-file") {
        let after = &cmd[idx + 5..]; // substring after '-file'
        // split by whitespace to get the path token
        if let Some(path_token) = after.split_whitespace().next() {
            // Trim possible quotes/backticks
            let mut p = path_token.trim().trim_matches('"').trim_matches('\'');
            // Also remove leading backtick if present (PowerShell quoting)
            if p.starts_with('`') {
                p = &p[1..];
            }
            // Generalize suspicious locations: non-C: drive, CIRCUITPY, removable, appdata/temp paths
            let p_lower = p.to_lowercase();

            // 1) Drive letter not C (D:, E:, etc.)
            if p_lower.len() >= 2 {
                let chars: Vec<char> = p_lower.chars().collect();
                if chars[1] == ':' && chars[0].is_ascii_alphabetic() {
                    let drive = chars[0].to_ascii_lowercase();
                    if drive != 'c' {
                        let mut alert = Alert::new(
                            "HIGH",
                            "PowerShell executed hidden from non-system drive",
                            &event.image,
                            &event.parent_image,
                        );
                        alert.command_line = Some(event.command_line.clone());

                        // Attempt to read the script file to look for clear keylogger/exfiltration indicators
                        let path_candidate = p.replace('/', "\\");
                        if let Ok(content) = fs::read_to_string(&path_candidate) {
                            let content_lower = content.to_lowercase();
                            let indicators = [
                                "getasynckeystate",
                                "add-type",
                                "invoke-webrequest",
                                "discord.com/api/webhooks",
                                "send-todiscord",
                                "get-content",
                                "start-keylogger",
                            ];
                            for ind in &indicators {
                                if content_lower.contains(ind) {
                                    alert.details = Some(format!("Script {} contains indicator: {}", p, ind));
                                    return Some(alert);
                                }
                            }
                            // no specific indicator found, still flag the non-C: origin
                            alert.details = Some(format!("Hidden PowerShell -File from drive {} detected: {} (script scanned, no explicit indicator found)", drive, p));
                        } else {
                            alert.details = Some(format!("Hidden PowerShell -File from drive {} detected: {} (script unreadable)", drive, p));
                        }

                        return Some(alert);
                    }
                }
            }

            // 2) Suspicious path fragments (removable/internal storage, temp, appdata)
            let suspicious_fragments = ["circuitpy", "removable", "usb", "temp", "appdata", "downloads", "public"];
            for frag in &suspicious_fragments {
                if p_lower.contains(frag) {
                    let mut alert = Alert::new(
                        "HIGH",
                        "PowerShell executed hidden from suspicious path",
                        &event.image,
                        &event.parent_image,
                    );
                    alert.command_line = Some(event.command_line.clone());

                    // Attempt to scan script contents for strong indicators
                    let path_candidate = p.replace('/', "\\");
                    if let Ok(content) = fs::read_to_string(&path_candidate) {
                        let content_lower = content.to_lowercase();
                        let indicators = ["getasynckeystate", "add-type", "invoke-webrequest", "discord.com/api/webhooks", "send-todiscord"];
                        for ind in &indicators {
                            if content_lower.contains(ind) {
                                alert.details = Some(format!("Script {} contains indicator: {}", p, ind));
                                return Some(alert);
                            }
                        }
                        alert.details = Some(format!("Hidden PowerShell -File from suspicious path detected: {} (script scanned, no explicit indicator found)", p));
                    } else {
                        alert.details = Some(format!("Hidden PowerShell -File from suspicious path detected: {} (script unreadable)", p));
                    }

                    return Some(alert);
                }
            }
        }
    }

    None
}

/// Detect PowerShell processes that have associated external network activity shortly after launching a script.
/// This is a general exfiltration heuristic: a script-run PowerShell process that posts to external hosts.
pub fn detect_powershell_network_exfil(proc: &ProcessEvent, net: &NetworkEvent) -> Option<Alert> {
    let image_lower = proc.image.to_lowercase();
    let cmd = proc.command_line.to_lowercase();

    if !(image_lower.ends_with("powershell.exe") || image_lower.ends_with("pwsh.exe")) {
        return None;
    }

    // Only consider external addresses (skip localhost/loopback)
    if net.remote_addr == "127.0.0.1" || net.remote_addr == "[::1]" || net.remote_addr == "localhost" {
        return None;
    }

    // Must be a script invocation (using -File or -EncodedCommand) OR contain explicit web/exfil calls
    let looks_like_script = cmd.contains("-file") || cmd.contains("-encodedcommand") || cmd.contains("-enc ");
    let explicit_exfil = cmd.contains("invoke-webrequest") || cmd.contains("discord.com/api/webhooks") || cmd.contains("send-todiscord");

    // Reduce false positives: require either an explicit script invocation, explicit exfil command, or an unsigned process
    if !(looks_like_script || explicit_exfil || !proc.is_signed) {
        return None;
    }

    let mut alert = Alert::new(
        "HIGH",
        "PowerShell network exfiltration suspicion",
        &proc.image,
        &proc.parent_image,
    );
    alert.command_line = Some(proc.command_line.clone());
    alert.details = Some(format!("PowerShell PID {} connected to {}:{} shortly after script launch", proc.pid, net.remote_addr, net.remote_port));
    Some(alert)
}