use crate::config::rules::Config;
use crate::events::{Alert, BaseEvent, EventType};
use crate::events::network::NetworkDirection;
use crate::monitoring::common::{get_command_line_cached, get_parent_process_info};
use crossbeam_channel::{Receiver, Sender};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub fn start_correlation_engine(
    process_rx: Receiver<BaseEvent>,
    network_rx: Receiver<BaseEvent>,
    alert_tx: Sender<Alert>,
    config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        run_correlation_engine(process_rx, network_rx, alert_tx, config, shutdown);
    })
}

#[derive(Clone, Debug)]
struct ProcessContext {
    start_time: chrono::DateTime<chrono::Utc>,
    process_name: String,
    pid: u32,
    parent_pid: u32,
    parent_name: String,
    command_line: String,
    // Behavior tracking
    first_network_event_time: Option<chrono::DateTime<chrono::Utc>>,
    network_connections: Vec<NetworkConnection>,
    // Rate limiting and suppression
    last_alert_time: Option<chrono::DateTime<chrono::Utc>>,
    alert_count: u32,
    // Behavior patterns
    is_known_good: bool,
    is_browser_process: bool,
    is_system_process: bool,
    is_scripting_engine: bool,
    // Suspicious indicators
    suspicious_flags: Vec<String>,
    // Memory for behavior analysis
    keypress_count: u32,
    last_keypress_time: Option<chrono::DateTime<chrono::Utc>>,
    // Timing for correlation
    process_age_at_first_network: Option<Duration>,
    // Detected patterns
    detected_patterns: HashSet<String>,
}

#[derive(Clone, Debug)]
struct NetworkConnection {
    timestamp: chrono::DateTime<chrono::Utc>,
    direction: NetworkDirection,
    protocol: String,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    remote_domain: Option<String>,
    is_external: bool,
    is_private_destination: bool,
    data_size: Option<u64>,
}

struct AlertState {
    // Deduplication - track recently alerted patterns
    recent_alerts: HashMap<String, chrono::DateTime<chrono::Utc>>,
    // Known good processes that have been verified
    verified_processes: HashSet<u32>,
    // Process start times for correlation with delayed network events
    process_start_times: HashMap<u32, chrono::DateTime<chrono::Utc>>,
    // Track processes that have already been evaluated
    evaluated_processes: HashSet<u32>,
    // Behavioral patterns across processes
    global_suspicious_patterns: HashSet<String>,
    // IOC tracking
    known_malicious_ips: HashSet<String>,
    known_malicious_domains: HashSet<String>,
    known_malicious_ports: HashSet<u16>,
    // Aggregation of events for cross-process correlation
    recent_events: VecDeque<(chrono::DateTime<chrono::Utc>, u32, String, String)>,
}

pub fn run_correlation_engine(
    process_rx: Receiver<BaseEvent>,
    network_rx: Receiver<BaseEvent>,
    alert_tx: Sender<Alert>,
    config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
) {
    let mut process_contexts: HashMap<u32, ProcessContext> = HashMap::new();
    let mut alert_state = AlertState {
        recent_alerts: HashMap::new(),
        verified_processes: HashSet::new(),
        process_start_times: HashMap::new(),
        evaluated_processes: HashSet::new(),
        global_suspicious_patterns: HashSet::new(),
        known_malicious_ips: HashSet::new(),
        known_malicious_domains: HashSet::new(),
        known_malicious_ports: HashSet::new(),
        recent_events: VecDeque::with_capacity(1000),
    };
    
    // Load initial IOCs from config
    load_initial_iocs(&mut alert_state, &config);
    
    while shutdown.load(Ordering::Relaxed) {
        crossbeam_channel::select! {
            recv(process_rx) -> event => {
                if let Ok(event) = event {
                    process_event(&event, &mut process_contexts, &mut alert_state, &alert_tx, &config);
                }
            },
            recv(network_rx) -> event => {
                if let Ok(event) = event {
                    process_event(&event, &mut process_contexts, &mut alert_state, &alert_tx, &config);
                }
            },
            recv(crossbeam_channel::after(Duration::from_millis(100))) -> _ => {
                cleanup_old_contexts(&mut process_contexts, &mut alert_state);
                check_temporal_correlations(&mut process_contexts, &mut alert_state, &alert_tx, &config);
            }
        }
    }
}

fn process_event(
    event: &BaseEvent,
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_state: &mut AlertState,
    alert_tx: &Sender<Alert>,
    config: &Config,
) {
    // Store event for cross-correlation
    let (pid, process_name) = match &event.event_type {
        EventType::ProcessStart(process_event) => (process_event.pid, process_event.process_name.clone()),
        EventType::ProcessEnd(process_event) => (process_event.pid, process_event.process_name.clone()),
        EventType::NetworkConnection(network_event) => (network_event.pid, network_event.process_name.clone()),
        _ => (0, String::from("Unknown")),
    };
    alert_state.recent_events.push_back((
        chrono::Utc::now(),
        pid,
        process_name,
        format!("{:?}", event.event_type)
    ));
    
    match &event.event_type {
        EventType::ProcessStart(process_event) => {
            handle_process_start(process_event, process_contexts, alert_state, alert_tx, config);
        }
        EventType::ProcessEnd(process_event) => {
            handle_process_end(process_event, process_contexts, alert_state);
        }
        EventType::NetworkConnection(network_event) => {
            handle_network_connection(network_event, process_contexts, alert_state, alert_tx, config);
        }
        _ => {}
    }
}

fn handle_process_start(
    process_event: &crate::events::process::ProcessEvent,
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_state: &mut AlertState,
    alert_tx: &Sender<Alert>,
    config: &Config,
) {
    let process_name = &process_event.process_name;
    let pid = process_event.pid;
    let parent_pid = process_event.parent_pid;
    
    // CRITICAL: Get command line IMMEDIATELY on process start
    let command_line = get_command_line_cached(pid).unwrap_or_default();

    let parent_info = get_parent_process_info(parent_pid);
    let parent_name = parent_info.0;

    // Analyze command line for suspicious indicators
    let suspicious_flags = analyze_command_line(process_name, &command_line);
    
    // Enhanced process classification
    let is_known_good = is_known_good_process(process_name, &command_line);
    let is_browser_process = is_browser_related_process(process_name);
    let is_system_process = is_system_process(process_name);
    let is_scripting_engine = is_scripting_engine_process(process_name, &command_line);

    let keylogger_score = calculate_keylogger_score(process_name, &command_line);
    
    let context = ProcessContext {
        start_time: chrono::Utc::now(),
        process_name: process_name.clone(),
        pid,
        parent_pid,
        parent_name: parent_name.clone(),
        command_line: command_line.clone(),
        first_network_event_time: None,
        network_connections: Vec::new(),
        last_alert_time: None,
        alert_count: 0,
        is_known_good,
        is_browser_process,
        is_system_process,
        is_scripting_engine,
        suspicious_flags: suspicious_flags.clone(),
        keypress_count: 0,
        last_keypress_time: None,
        process_age_at_first_network: None,
        detected_patterns: HashSet::new(),
    };
    
    process_contexts.insert(pid, context);
    alert_state.process_start_times.insert(pid, chrono::Utc::now());
    
    // **IMMEDIATE KEYLOGGER ALERT** - Don't wait for network activity
    if keylogger_score >= 5 {
        let alert_key = format!("keylogger_immediate:{}", pid);
        if should_alert(&alert_key, alert_state, Duration::from_secs(60)) {
            generate_alert(
                crate::events::alert::AlertSeverity::Critical,
                "KeyloggerDetected",
                &format!("High-confidence keylogger detected: {}", process_name),
                &process_contexts[&pid],
                alert_tx,
                vec![
                    format!("Keylogger Score = {}/10", keylogger_score),
                    format!("Command Line = {}", truncate_string(&command_line, 200)),
                    format!("Indicators = {}", extract_keylogger_indicators(&command_line)),
                    format!("Parent = {} (PID: {})", parent_name, parent_pid),
                    format!("Suspicious Flags = {}", suspicious_flags.join(", ")),
                    format!("⚠️ IMMEDIATE THREAT - Process likely logging keystrokes"),
                ],
            );
        }
    }
    
    // Immediate alert for highly suspicious process starts
    if !suspicious_flags.is_empty() {
        let severity = if suspicious_flags.contains(&"-WindowStyle Hidden".to_string()) 
            && suspicious_flags.contains(&"-ExecutionPolicy Bypass".to_string()) {
            crate::events::alert::AlertSeverity::High
        } else {
            crate::events::alert::AlertSeverity::Medium
        };
        
        let alert_key = format!("suspicious_start:{}-{}", pid, process_name);
        if should_alert(&alert_key, alert_state, Duration::from_secs(300)) {
            generate_alert(
                severity,
                "SuspiciousProcessStart",
                &format!("Suspicious process '{}' started with unusual flags", process_name),
                &process_contexts[&pid],
                alert_tx,
                vec![
                    format!("Command Line = {}", truncate_string(&command_line, 100)),
                    format!("Suspicious Flags = {}", suspicious_flags.join(", ")),
                    format!("Parent = {} (PID: {})", parent_name, parent_pid),
                    format!("Is Scripting Engine = {}", is_scripting_engine),
                ],
            );
        }
    }
    
    // Check for LOLBAS patterns
    if is_lolbas_pattern(process_name, &command_line) {
        let alert_key = format!("lolbas_pattern:{}-{}", pid, process_name);
        if should_alert(&alert_key, alert_state, Duration::from_secs(600)) {
            generate_alert(
                crate::events::alert::AlertSeverity::High,
                "LOLBASPatternDetected",
                &format!("LOLBAS pattern detected for '{}'", process_name),
                &process_contexts[&pid],
                alert_tx,
                vec![
                    format!("Command Line = {}", truncate_string(&command_line, 100)),
                    format!("Pattern Type = {}", identify_lolbas_pattern(&command_line)),
                    format!("Parent = {} (PID: {})", parent_name, parent_pid),
                ],
            );
        }
    }
}

fn handle_process_end(
    process_event: &crate::events::process::ProcessEvent,
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_state: &mut AlertState,
) {
    if let Some(context) = process_contexts.get(&process_event.pid) {
        // Check for short-lived suspicious processes
        let lifetime = chrono::Utc::now() - context.start_time;
        if context.is_scripting_engine 
            && lifetime < chrono::Duration::seconds(10)
            && !context.network_connections.is_empty()
            && context.alert_count == 0 {
            
            // This could be a stealthy script - log for analysis
            log::warn!("Short-lived scripting process ended: {} (PID: {}) lifetime: {}s, connections: {}",
                context.process_name, context.pid, lifetime.num_seconds(), 
                context.network_connections.len());
        }
    }
    
    process_contexts.remove(&process_event.pid);
    alert_state.process_start_times.remove(&process_event.pid);
    alert_state.verified_processes.remove(&process_event.pid);
    alert_state.evaluated_processes.remove(&process_event.pid);
}

fn handle_network_connection(
    network_event: &crate::events::network::NetworkEvent,
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_state: &mut AlertState,
    alert_tx: &Sender<Alert>,
    config: &Config,
) {
    let pid = network_event.pid;
    let process_name = &network_event.process_name;
    
    // Skip if we've already marked this process as verified (but re-evaluate if suspicious)
    if alert_state.verified_processes.contains(&pid) {
        // Still check for highly suspicious connections even from "verified" processes
        if !is_highly_suspicious_connection(network_event) {
            return;
        }
    }
    
    // Get or create process context
    let context = if let Some(ctx) = process_contexts.get_mut(&pid) {
        ctx
    } else {
        
        let command_line = get_command_line_cached(pid).unwrap_or_default();
        let is_known_good = is_known_good_process(process_name, &command_line);
        let is_browser_process = is_browser_related_process(process_name);
        let is_system_process = is_system_process(process_name);
        let is_scripting_engine = is_scripting_engine_process(process_name, &command_line);
        let suspicious_flags = analyze_command_line(process_name, &command_line);
        
        let ctx = ProcessContext {
            start_time: chrono::Utc::now(), // Approximate
            process_name: process_name.clone(),
            pid,
            parent_pid: 0,
            parent_name: String::new(),
            command_line,
            first_network_event_time: Some(chrono::Utc::now()),
            network_connections: Vec::new(),
            last_alert_time: None,
            alert_count: 0,
            is_known_good,
            is_browser_process,
            is_system_process,
            is_scripting_engine,
            suspicious_flags,
            keypress_count: 0,
            last_keypress_time: None,
            process_age_at_first_network: None,
            detected_patterns: HashSet::new(),
        };
        
        process_contexts.insert(pid, ctx);
        process_contexts.get_mut(&pid).unwrap()
    };

    check_webhook_exfiltration(
        context,
        &network_event.remote_address,
        network_event.remote_port,
        network_event.domain.as_deref(),
        alert_tx,
    );
    
    // Update first network event time if not set
    if context.first_network_event_time.is_none() {
        context.first_network_event_time = Some(chrono::Utc::now());
        let time_delta = chrono::Utc::now() - context.start_time;
        context.process_age_at_first_network = time_delta.to_std().ok();
    }
    
    // Classify connection
    let is_private_destination = is_private_or_local(&network_event.remote_address);
    let is_external = !is_private_destination && network_event.remote_address != "0.0.0.0";
    
    // Try to resolve domain if available
    let remote_domain = network_event.domain.clone();
    
    let connection = NetworkConnection {
        timestamp: chrono::Utc::now(),
        direction: network_event.direction.clone(),
        protocol: match &network_event.protocol {
            crate::events::network::Protocol::TCP => "TCP".to_string(),
            crate::events::network::Protocol::UDP => "UDP".to_string(),
            crate::events::network::Protocol::QUIC => "QUIC".to_string(),
            crate::events::network::Protocol::Other(proto) => proto.clone(),
        },
        local_addr: network_event.local_address.clone(),
        local_port: network_event.local_port,
        remote_addr: network_event.remote_address.clone(),
        remote_port: network_event.remote_port,
        remote_domain,
        is_external,
        is_private_destination,
        data_size: network_event.data_size,
    };
    
    context.network_connections.push(connection.clone());
    
    // Immediate checks before evaluation
    if check_immediate_threats(&connection, context, alert_state, alert_tx) {
        alert_state.evaluated_processes.insert(pid);
        return;
    }
    
    // Evaluate for alerts
    if !context.is_known_good || context.is_scripting_engine {
        evaluate_network_alert(
            context,
            &connection,
            alert_state,
            alert_tx,
            config,
        );
    }
}

fn calculate_keylogger_score(process_name: &str, command_line: &str) -> u8 {
    let mut score = 0u8;
    let lower_name = process_name.to_lowercase();
    let lower_cmd = command_line.to_lowercase();
    
    // Only analyze scripting engines
    if !lower_name.contains("powershell") && 
       !lower_name.contains("pwsh") && 
       !lower_name.contains("python") &&
       !lower_name.contains("node") {
        return 0;
    }
    
    // ==== SMOKING GUN INDICATORS (3 points each) ====
    if lower_cmd.contains("getasynckeystate") { 
        score = score.saturating_add(3);
        log::warn!("🔴 GetAsyncKeyState API detected");
    }
    if lower_cmd.contains("getkeystate") { 
        score = score.saturating_add(3);
    }
    if lower_cmd.contains("setwindowshookex") || lower_cmd.contains("setkeyboardhook") { 
        score = score.saturating_add(3);
    }
    if lower_cmd.contains("[dllimport(\"user32.dll\")]") || lower_cmd.contains("[dllimport('user32.dll')]") { 
        score = score.saturating_add(3);
        log::warn!("🔴 user32.dll import detected");
    }
    if lower_cmd.contains("public static extern short getasynckeystate") {
        score = score.saturating_add(3);
    }
    
    // ==== HIGH CONFIDENCE (2 points each) ====
    if lower_cmd.contains("add-type -assemblyname system.windows.forms") { 
        score = score.saturating_add(2);
        log::warn!("🟠 System.Windows.Forms assembly");
    }
    if lower_cmd.contains("system.runtime.interopservices") { 
        score = score.saturating_add(2);
    }
    if lower_cmd.contains("keylog") || lower_cmd.contains("keystroke") { 
        score = score.saturating_add(2);
    }
    
    let special_keys = vec!["[backspace]", "[enter]", "[tab]", "[shift]", "[ctrl]", "[alt]"];
    let special_key_count = special_keys.iter().filter(|&&key| lower_cmd.contains(key)).count();
    if special_key_count >= 2 {
        score = score.saturating_add(2);
        log::warn!("🟠 Multiple special key patterns ({})", special_key_count);
    }
    
    if (lower_cmd.contains("invoke-webrequest") || lower_cmd.contains("invoke-restmethod")) 
       && (lower_cmd.contains("webhook") || lower_cmd.contains("discord.com/api/webhooks")) {
        score = score.saturating_add(2);
        log::warn!("🟠 Webhook exfiltration");
    }
    
    if lower_cmd.contains("discord.com/api/webhooks") || lower_cmd.contains("discordapp.com/api/webhooks") {
        score = score.saturating_add(2);
    }
    
    if (lower_cmd.contains("while ($true)") || lower_cmd.contains("while (1)"))
       && lower_cmd.contains("start-sleep") {
        score = score.saturating_add(2);
    }
    
    // ==== MEDIUM CONFIDENCE (1 point each) ====
    if lower_cmd.contains("-windowstyle hidden") || lower_cmd.contains("-w hidden") { 
        score = score.saturating_add(1);
    }
    if lower_cmd.contains("-executionpolicy bypass") || lower_cmd.contains("-ep bypass") { 
        score = score.saturating_add(1);
    }
    if lower_cmd.contains("-noprofile") || lower_cmd.contains("-nop") { 
        score = score.saturating_add(1);
    }
    if lower_cmd.contains("currentversion\\run") || lower_cmd.contains("currentversion/run") {
        score = score.saturating_add(1);
    }
    if lower_cmd.contains("$env:appdata") && lower_cmd.contains(".txt") {
        score = score.saturating_add(1);
    }
    if lower_cmd.contains("start-sleep -milliseconds") {
        score = score.saturating_add(1);
    }
    
    score
}

fn extract_keylogger_details(command_line: &str) -> String {
    let lower_cmd = command_line.to_lowercase();
    let mut indicators: Vec<String> = Vec::new();
    
    if lower_cmd.contains("getasynckeystate") {
        indicators.push("• GetAsyncKeyState API (Windows keyboard hook)".to_string());
    }
    if lower_cmd.contains("[dllimport(\"user32.dll\")]") || lower_cmd.contains("[dllimport('user32.dll')]") {
        indicators.push("• user32.dll DLL import".to_string());
    }
    if lower_cmd.contains("system.windows.forms") {
        indicators.push("• System.Windows.Forms assembly".to_string());
    }
    if lower_cmd.contains("discord.com/api/webhooks") || lower_cmd.contains("discordapp.com/api/webhooks") {
        indicators.push("• Discord webhook URL (exfiltration)".to_string());
    }
    if lower_cmd.contains("webhook.office.com") {
        indicators.push("• Microsoft Teams webhook URL (exfiltration)".to_string());
    }
    if lower_cmd.contains("hooks.slack.com") {
        indicators.push("• Slack webhook URL (exfiltration)".to_string());
    }
    if lower_cmd.contains("-windowstyle hidden") {
        indicators.push("• Hidden window execution".to_string());
    }
    if lower_cmd.contains("-executionpolicy bypass") {
        indicators.push("• Execution policy bypass".to_string());
    }
    if lower_cmd.contains("currentversion\\run") || lower_cmd.contains("currentversion/run") {
        indicators.push("• Registry persistence (Run key)".to_string());
    }
    if lower_cmd.contains("while ($true)") || lower_cmd.contains("while (1)") {
        indicators.push("• Infinite loop (continuous monitoring)".to_string());
    }
    if lower_cmd.contains("keylog") {
        indicators.push("• 'keylog' in filename/variable".to_string());
    }
    
    let special_keys = vec!["[backspace]", "[enter]", "[tab]", "[shift]", "[ctrl]", "[alt]"];
    let found_keys: Vec<&str> = special_keys.iter()
        .filter(|&&key| lower_cmd.contains(key))
        .copied()
        .collect();
    if !found_keys.is_empty() {
        indicators.push(format!("• Special key patterns: {}", found_keys.join(", ")));
    }
    
    if indicators.is_empty() {
        "No specific indicators extracted".to_string()
    } else {
        format!("Detected Indicators:\n{}", indicators.join("\n"))
    }
}

fn check_webhook_exfiltration(
    context: &ProcessContext,
    remote_addr: &str,
    remote_port: u16,
    remote_domain: Option<&str>,
    alert_tx: &Sender<Alert>,
) {
    // Only check PowerShell/scripting processes
    let lower_name = context.process_name.to_lowercase();
    if !lower_name.contains("powershell") && !lower_name.contains("pwsh") {
        return;
    }
    
    // Check for webhook domains
    if let Some(domain) = remote_domain {
        let domain_lower = domain.to_lowercase();
        
        // Known webhook services
        let webhook_services = vec![
            ("discord.com", "Discord"),
            ("discordapp.com", "Discord"),
            ("webhook.office.com", "Microsoft Teams"),
            ("hooks.slack.com", "Slack"),
            ("webhook.site", "Webhook.site"),
            ("webhooks.mongodb-realm.com", "MongoDB"),
        ];
        
        for (service_domain, service_name) in webhook_services {
            if domain_lower.contains(service_domain) {
                let mut alert_message = format!(
                    "🚨 POWERSHELL WEBHOOK EXFILTRATION DETECTED!\n\
                    \n\
                    Process: {} (PID: {})\n\
                    Parent: {} (PID: {})\n\
                    Destination: {}:{}\n\
                    Service: {} webhook\n\
                    Risk Level: HIGH",
                    context.process_name,
                    context.pid,
                    context.parent_name,
                    context.parent_pid,
                    remote_addr,
                    remote_port,
                    service_name
                );
                
                // Check if command line also has keylogger indicators
                if !context.command_line.is_empty() {
                    let keylogger_score = calculate_keylogger_score(&context.process_name, &context.command_line);
                    if keylogger_score >= 3 {
                        alert_message.push_str(&format!(
                            "\n\n⚠️  KEYLOGGER INDICATORS DETECTED (Score: {})\n\
                            This PowerShell process likely contains keylogging code!",
                            keylogger_score
                        ));
                    }
                    
                    // Add command line snippet
                    alert_message.push_str(&format!(
                        "\n\nCommand Line:\n{}",
                        if context.command_line.len() > 200 {
                            format!("{}...", &context.command_line[..200])
                        } else {
                            context.command_line.clone()
                        }
                    ));
                }
                
                generate_alert(
                    crate::events::alert::AlertSeverity::High,
                    "PowerShellWebhookExfiltration",
                    &format!("PowerShell process exfiltrating data via {} webhook", service_name),
                    context,
                    alert_tx,
                    vec![
                        format!("Destination = {}:{}", remote_addr, remote_port),
                        format!("Service = {} webhook", service_name),
                        format!("Command Line = {}", truncate_string(&context.command_line, 200)),
                        format!("Suspicious Flags = {}", context.suspicious_flags.join(", ")),
                    ],
                );
                
                log::warn!("{}", "=".repeat(80));
                log::warn!("🚨 WEBHOOK EXFILTRATION: {} -> {} webhook", context.process_name, service_name);
                log::warn!("{}", "=".repeat(80));
                
                return; // Only alert once per connection
            }
        }
    }
    
    // Also check for hidden PowerShell making external HTTPS connections
    if remote_port == 443 {
        let lower_cmd = context.command_line.to_lowercase();
        if lower_cmd.contains("-windowstyle hidden") && context.network_connections.len() <= 3 {
            let alert_message = format!(
                "⚠️  SUSPICIOUS NETWORK ACTIVITY\n\
                \n\
                Hidden PowerShell making external HTTPS connection\n\
                Process: {} (PID: {})\n\
                Destination: {}:{}\n\
                Pattern: Typical of data exfiltration",
                context.process_name,
                context.pid,
                remote_addr,
                remote_port
            );
            
            generate_alert(
                crate::events::alert::AlertSeverity::Medium,
                "HiddenPowerShellHTTPSConnection",
                &format!("Hidden PowerShell process making external HTTPS connection"),
                context,
                alert_tx,
                vec![
                    format!("Destination = {}:{}", remote_addr, remote_port),
                    format!("Command Line = {}", truncate_string(&context.command_line, 200)),
                    format!("Suspicious Flags = {}", context.suspicious_flags.join(", ")),
                ],
            );
        }
    }
}

fn check_immediate_threats(
    connection: &NetworkConnection,
    context: &ProcessContext,
    alert_state: &mut AlertState,
    alert_tx: &Sender<Alert>,
) -> bool {
    let mut threat_detected = false;
    
    // Check against known malicious IOCs
    if alert_state.known_malicious_ips.contains(&connection.remote_addr) {
        generate_alert(
            crate::events::alert::AlertSeverity::Critical,
            "KnownMaliciousIP",
            &format!("Process connecting to known malicious IP: {}", connection.remote_addr),
            context,
            alert_tx,
            vec![
                format!("Destination IP = {}", connection.remote_addr),
                format!("Port = {}", connection.remote_port),
                format!("Process = {} (PID: {})", context.process_name, context.pid),
                format!("Command Line = {}", truncate_string(&context.command_line, 100)),
            ],
        );
        threat_detected = true;
    }
    
    if let Some(domain) = &connection.remote_domain {
        if alert_state.known_malicious_domains.contains(domain) 
            || is_suspicious_domain(domain) {
            generate_alert(
                crate::events::alert::AlertSeverity::Critical,
                "SuspiciousDomain",
                &format!("Process connecting to suspicious domain: {}", domain),
                context,
                alert_tx,
                vec![
                    format!("Domain = {}", domain),
                    format!("IP = {}", connection.remote_addr),
                    format!("Process = {} (PID: {})", context.process_name, context.pid),
                    format!("Is Scripting Engine = {}", context.is_scripting_engine),
                ],
            );
            threat_detected = true;
        }
    }
    
    // Check for data exfiltration patterns
    if context.is_scripting_engine 
        && connection.is_external 
        && connection.remote_port == 443
        && connection.data_size.unwrap_or(0) > 1024 {
        
        let alert_key = format!("exfil_script:{}-{}", context.pid, connection.remote_addr);
        if should_alert(&alert_key, alert_state, Duration::from_secs(300)) {
            generate_alert(
                crate::events::alert::AlertSeverity::High,
                "PossibleDataExfiltration",
                &format!("Scripting engine sending large amount of data to external host"),
                context,
                alert_tx,
                vec![
                    format!("Destination = {}:{}", connection.remote_addr, connection.remote_port),
                    format!("Data Size = {} bytes", connection.data_size.unwrap_or(0)),
                    format!("Command Line = {}", truncate_string(&context.command_line, 100)),
                    format!("Suspicious Flags = {}", context.suspicious_flags.join(", ")),
                ],
            );
            threat_detected = true;
        }
    }
    
    threat_detected
}

fn evaluate_network_alert(
    context: &mut ProcessContext,
    connection: &NetworkConnection,
    alert_state: &mut AlertState,
    alert_tx: &Sender<Alert>,
    config: &Config,
) {
    let now = chrono::Utc::now();
    
    // Don't alert on loopback or private network connections for non-scripting processes
    if !connection.is_external && !context.is_scripting_engine {
        return;
    }
    
    // Calculate actual process age for correlation
    let process_age = if let Some(first_network_time) = context.first_network_event_time {
        // For processes we didn't see start, use first network time as reference
        now - first_network_time
    } else {
        now - context.start_time
    };
    
    // ========= DETECTION RULES ==========
    
    // Rule 1: Scripting engine making external connections (KEYLOGGER DETECTION)
    if context.is_scripting_engine && connection.is_external {
        // Check for keylogger patterns in command line
        if is_keylogger_pattern(&context.command_line) {
            let alert_key = format!("keylogger:{}-{}", context.pid, connection.remote_addr);
            if should_alert(&alert_key, alert_state, Duration::from_secs(60)) {
                generate_alert(
                    crate::events::alert::AlertSeverity::Critical,
                    "KeyloggerDetected",
                    &format!("Keylogger behavior detected in PowerShell process"),
                    context,
                    alert_tx,
                    vec![
                        format!("Command Line Indicators = {}", extract_keylogger_indicators(&context.command_line)),
                        format!("Destination = {}:{}", connection.remote_addr, connection.remote_port),
                        format!("Parent Process = {} (PID: {})", context.parent_name, context.parent_pid),
                        format!("Suspicious Flags = {}", context.suspicious_flags.join(", ")),
                    ],
                );
                context.alert_count += 1;
                context.last_alert_time = Some(now);
                alert_state.evaluated_processes.insert(context.pid);
                return;
            }
        }
        
        // Generic scripting engine external connection
        let alert_key = format!("script_ext:{}-{}", context.pid, connection.remote_addr);
        if should_alert(&alert_key, alert_state, Duration::from_secs(300)) {
            generate_alert(
                crate::events::alert::AlertSeverity::Medium,
                "ScriptingEngineExternalConnection",
                &format!("Scripting engine '{}' making external connection", context.process_name),
                context,
                alert_tx,
                vec![
                    format!("Destination = {}:{}", connection.remote_addr, connection.remote_port),
                    format!("Protocol = {}", connection.protocol),
                    format!("Command Line = {}", truncate_string(&context.command_line, 100)),
                    format!("Process Age = {} seconds", process_age.num_seconds()),
                ],
            );
            context.alert_count += 1;
            context.last_alert_time = Some(now);
            alert_state.evaluated_processes.insert(context.pid);
            return;
        }
    }
    
    // Rule 2: Unexpected process making multiple rapid connections (possible scanning)
    if context.network_connections.len() >= 5 {
        let connections_last_10s = context.network_connections
            .iter()
            .filter(|c| now - c.timestamp < chrono::Duration::seconds(10))
            .count();
        
        if connections_last_10s >= 5 && !is_network_aware_process(&context.process_name) {
            let alert_key = format!("rapid_connections:{}-{}", context.pid, connections_last_10s);
            if should_alert(&alert_key, alert_state, Duration::from_secs(300)) {
                generate_alert(
                    crate::events::alert::AlertSeverity::Medium,
                    "RapidExternalConnections",
                    &format!("Process '{}' made {} external connections in 10 seconds", 
                        context.process_name, connections_last_10s),
                    context,
                    alert_tx,
                    vec![
                        format!("Connection Count = {}", connections_last_10s),
                        format!("Process Type = {}", categorize_process(&context.process_name)),
                        format!("Expected Behavior = {}", if is_network_aware_process(&context.process_name) { "Network-aware" } else { "Not network-aware" }),
                    ],
                );
                context.alert_count += 1;
                context.last_alert_time = Some(now);
                alert_state.evaluated_processes.insert(context.pid);
                return;
            }
        }
    }
    
    // Rule 3: Connection to known malicious infrastructure (would require threat intel)
    // This is we can integrate with threat intelligence feeds
    
    // Rule 4: Very suspicious patterns (e.g., process starts and immediately connects to high-risk port)
    if process_age < chrono::Duration::seconds(3) && 
       context.network_connections.len() == 1 &&
       is_high_risk_port(connection.remote_port) &&
       is_suspicious_parent_process(context.parent_pid, &context.process_name, &context.parent_name) {
        
        let alert_key = format!("immediate_highrisk:{}-{}", context.pid, connection.remote_port);
        if should_alert(&alert_key, alert_state, Duration::from_secs(600)) {
            generate_alert(
                crate::events::alert::AlertSeverity::Critical,
                "ImmediateHighRiskConnection",
                &format!("New process '{}' immediately connected to high-risk port {}", 
                    context.process_name, connection.remote_port),
                context,
                alert_tx,
                vec![
                    format!("Process Age = {} seconds", process_age.num_seconds()),
                    format!("Destination Port = {} ({})", connection.remote_port, describe_port(connection.remote_port)),
                    format!("Parent Process = {} (PID: {})", context.parent_name, context.parent_pid),
                    format!("Risk = Possible malware C2 or exploitation"),
                ],
            );
            context.alert_count += 1;
            context.last_alert_time = Some(now);
            alert_state.evaluated_processes.insert(context.pid);
            return;
        }
    }
    
    // Rule 5: Webhook exfiltration pattern detection
    if connection.is_external && connection.remote_port == 443 {
        if let Some(domain) = &connection.remote_domain {
            if is_webhook_service(domain) && context.is_scripting_engine {
                // Check if this is likely keylogger exfiltration
                let is_likely_keylogger = !context.suspicious_flags.is_empty() 
                    && (context.command_line.to_lowercase().contains("getasynckeystate")
                        || context.command_line.to_lowercase().contains("keylog")
                        || context.command_line.to_lowercase().contains("[backspace]"));
                
                let severity = if is_likely_keylogger {
                    crate::events::alert::AlertSeverity::Critical
                } else {
                    crate::events::alert::AlertSeverity::High
                };
                
                let alert_key = format!("webhook_exfil:{}-{}", context.pid, domain);
                if should_alert(&alert_key, alert_state, Duration::from_secs(60)) {
                    generate_alert(
                        severity,
                        if is_likely_keylogger { "KeyloggerWebhookExfiltration" } else { "WebhookDataExfiltration" },
                        &format!("Scripting process exfiltrating to webhook: {}", domain),
                        context,
                        alert_tx,
                        vec![
                            format!("Webhook Service = {}", domain),
                            format!("Destination IP = {}", connection.remote_addr),
                            format!("Process Age = {} seconds", (now - context.start_time).num_seconds()),
                            format!("Command Line = {}", truncate_string(&context.command_line, 150)),
                            format!("Suspicious Flags = {}", context.suspicious_flags.join(", ")),
                            if is_likely_keylogger { 
                                "⚠️ HIGH CONFIDENCE KEYLOGGER".to_string() 
                            } else { 
                                "Possible data exfiltration".to_string() 
                            },
                        ],
                    );
                    context.alert_count += 1;
                    context.last_alert_time = Some(now);
                    alert_state.evaluated_processes.insert(context.pid);
                    return;
                }
            }
        }
    }
    
    // Rule 6: DNS over HTTPS/QUIC pattern (common in C2)
    if connection.protocol == "QUIC" && context.is_scripting_engine {
        let alert_key = format!("doh_script:{}-{}", context.pid, connection.remote_addr);
        if should_alert(&alert_key, alert_state, Duration::from_secs(600)) {
            generate_alert(
                crate::events::alert::AlertSeverity::Medium,
                "ScriptingEngineUsingDoH",
                &format!("Scripting engine using QUIC/HTTP3 protocol"),
                context,
                alert_tx,
                vec![
                    format!("Protocol = {}", connection.protocol),
                    format!("Destination = {}:{}", connection.remote_addr, connection.remote_port),
                    format!("Command Line = {}", truncate_string(&context.command_line, 100)),
                ],
            );
            context.alert_count += 1;
            context.last_alert_time = Some(now);
            alert_state.evaluated_processes.insert(context.pid);
            return;
        }
    }
    
    // Mark as evaluated to prevent repeated alerts for normal processes
    alert_state.evaluated_processes.insert(context.pid);
}

// ========== ENHANCED HELPER FUNCTIONS ==========

fn is_known_good_process(process_name: &str, command_line: &str) -> bool {
    let lower_name = process_name.to_lowercase();
    let lower_cmd = command_line.to_lowercase();
    
    // Common legitimate processes that shouldn't trigger alerts
    let known_good_names = vec![
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
        // Other common legitimate software
        "adobe creative cloud.exe", "creative cloud.exe", "ccxprocess.exe",
        // Microsoft Office
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    ];
    
    // Check if process name is in known good list
    let name_match = known_good_names.iter().any(|&p| lower_name.contains(p));
    
    // Additional check: PowerShell with common admin/management commands
    if lower_name.contains("powershell.exe") {
        // Whitelist common PowerShell management patterns
        let legit_patterns = vec![
            "get-process",
            "get-service",
            "get-eventlog",
            "import-module",
            "update-help",
            "get-help",
            "get-command",
            "start-service",
            "stop-service",
            "restart-service",
            "get-wmiobject",
            "get-ciminstance",
        ];
        
        // If it's PowerShell with legitimate patterns, consider it known good
        if legit_patterns.iter().any(|p| lower_cmd.contains(p)) {
            return true;
        }
    }
    
    name_match
}

fn is_scripting_engine_process(process_name: &str, command_line: &str) -> bool {
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
    
    // Check for script execution via rundll32, regsvr32, etc.
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

fn analyze_command_line(process_name: &str, command_line: &str) -> Vec<String> {
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

fn is_keylogger_pattern(command_line: &str) -> bool {
    let lower_cmd = command_line.to_lowercase();
    
    // Keylogger specific patterns from the provided script
    let keylogger_indicators = vec![
        "getasynckeystate",
        "keylog",
        "[backspace]",
        "[tab]",
        "[enter]",
        "[shift]",
        "[ctrl]",
        "[alt]",
        "add-type -assemblyname system.windows.forms",
        "dllimport(\"user32.dll\")",
        "public static extern short getasynckeystate",
        "$webhookurl",
        "discord.com/api/webhooks",
        "send-todiscord",
        "invoke-webrequest -uri",
        "payload = @{ content =",
    ];
    
    // Count matches for better accuracy
    let match_count = keylogger_indicators.iter()
        .filter(|&indicator| lower_cmd.contains(indicator))
        .count();
    
    // If we find 3 or more keylogger indicators, consider it a keylogger
    match_count >= 3
}

fn extract_keylogger_indicators(command_line: &str) -> String {
    let lower_cmd = command_line.to_lowercase();
    let mut indicators = Vec::new();
    
    if lower_cmd.contains("getasynckeystate") {
        indicators.push("✓ Win32 GetAsyncKeyState API");
    }
    if lower_cmd.contains("dllimport") && lower_cmd.contains("user32.dll") {
        indicators.push("✓ User32.dll Import");
    }
    if lower_cmd.contains("discord.com/api/webhooks") {
        indicators.push("✓ Discord Webhook Exfiltration");
    }
    if lower_cmd.contains("add-type -assemblyname system.windows.forms") {
        indicators.push("✓ Windows.Forms Assembly");
    }
    if lower_cmd.contains("-windowstyle hidden") || lower_cmd.contains("-w hidden") {
        indicators.push("✓ Hidden Window");
    }
    if lower_cmd.contains("-executionpolicy bypass") {
        indicators.push("✓ Execution Policy Bypass");
    }
    if lower_cmd.contains("hkcu:\\software\\microsoft\\windows\\currentversion\\run") {
        indicators.push("✓ Registry Persistence");
    }
    if lower_cmd.contains("[backspace]") || lower_cmd.contains("[tab]") || lower_cmd.contains("[enter]") {
        indicators.push("✓ Keystroke Pattern Logging");
    }
    if lower_cmd.contains("$env:appdata") && (lower_cmd.contains("keylog") || lower_cmd.contains(".txt")) {
        indicators.push("✓ AppData File Logging");
    }
    if lower_cmd.contains("while ($true)") || lower_cmd.contains("while (1)") {
        indicators.push("✓ Infinite Loop (Background)");
    }
    
    if indicators.is_empty() {
        "None detected".to_string()
    } else {
        indicators.join(", ")
    }
}

fn is_webhook_service(domain: &str) -> bool {
    let lower_domain = domain.to_lowercase();
    
    lower_domain.contains("discord.com") ||
    lower_domain.contains("webhook.office.com") ||
    lower_domain.contains("hooks.slack.com") ||
    lower_domain.contains("webhooks.mongodb-realm.com") ||
    lower_domain.contains("webhook.site") ||
    lower_domain.ends_with(".webhook.app")
}

fn is_suspicious_domain(domain: &str) -> bool {
    let lower_domain = domain.to_lowercase();
    
    // Check for domain generation algorithm (DGA) patterns
    if lower_domain.chars().filter(|c| c.is_ascii_digit()).count() > 5 {
        return true;
    }
    
    // Check for excessive subdomains
    if lower_domain.matches('.').count() > 4 {
        return true;
    }
    
    // Check for suspicious TLDs
    let suspicious_tlds = vec![".xyz", ".top", ".club", ".bid", ".win", ".gq", ".ml", ".cf"];
    if suspicious_tlds.iter().any(|tld| lower_domain.ends_with(tld)) {
        return true;
    }
    
    false
}

fn is_lolbas_pattern(process_name: &str, command_line: &str) -> bool {
    let lower_name = process_name.to_lowercase();
    let lower_cmd = command_line.to_lowercase();
    
    match lower_name.as_str() {
        "rundll32.exe" => {
            lower_cmd.contains(".dll,") && 
            (lower_cmd.contains("http://") || lower_cmd.contains("https://") ||
             lower_cmd.contains("regsvr") || lower_cmd.contains("javascript:"))
        }
        "regsvr32.exe" => {
            lower_cmd.contains("/s") && 
            (lower_cmd.contains("http://") || lower_cmd.contains("https://") ||
             lower_cmd.contains(".sct") || lower_cmd.contains(".scrobj"))
        }
        "mshta.exe" => {
            lower_cmd.contains("http://") || lower_cmd.contains("https://") ||
            lower_cmd.contains("javascript:") || lower_cmd.contains("vbscript:")
        }
        "certutil.exe" => {
            lower_cmd.contains("-urlcache") || lower_cmd.contains("-split") ||
            lower_cmd.contains("-decode") || lower_cmd.contains("-encode")
        }
        "bitsadmin.exe" => {
            lower_cmd.contains("/transfer") || lower_cmd.contains("/create") ||
            lower_cmd.contains("/addfile") || lower_cmd.contains("/setnotifycmdline")
        }
        "wmic.exe" => {
            lower_cmd.contains("process call create") ||
            lower_cmd.contains("/node:") && lower_cmd.contains("process create")
        }
        _ => false
    }
}

fn identify_lolbas_pattern(command_line: &str) -> &'static str {
    let lower_cmd = command_line.to_lowercase();
    
    if lower_cmd.contains("rundll32.exe") && lower_cmd.contains("javascript:") {
        "Rundll32 JavaScript Execution"
    } else if lower_cmd.contains("regsvr32.exe") && lower_cmd.contains(".sct") {
        "Regsvr32 SCT Scriptlet Execution"
    } else if lower_cmd.contains("mshta.exe") && (lower_cmd.contains("http://") || lower_cmd.contains("https://")) {
        "Mshta Remote Script Execution"
    } else if lower_cmd.contains("certutil.exe") && lower_cmd.contains("-urlcache") {
        "Certutil File Download"
    } else if lower_cmd.contains("bitsadmin.exe") && lower_cmd.contains("/transfer") {
        "Bitsadmin File Transfer"
    } else if lower_cmd.contains("wmic.exe") && lower_cmd.contains("process call create") {
        "WMIC Remote Process Creation"
    } else {
        "Unknown LOLBAS Pattern"
    }
}

fn is_highly_suspicious_connection(network_event: &crate::events::network::NetworkEvent) -> bool {
    // Even "verified" processes can do suspicious things
    is_high_risk_port(network_event.remote_port) ||
    network_event.remote_address.starts_with("192.168.56.") && network_event.process_name.to_lowercase().contains("powershell")
}

fn is_suspicious_parent_process(parent_pid: u32, child_name: &str, parent_name: &str) -> bool {
    let child_lower = child_name.to_lowercase();
    let parent_lower = parent_name.to_lowercase();
    
    // Suspicious parent-child combinations
    (parent_lower.contains("explorer.exe") && child_lower.contains("powershell.exe")) ||
    (parent_lower.contains("svchost.exe") && child_lower.contains("cmd.exe")) ||
    (parent_lower.contains("services.exe") && child_lower.contains("wscript.exe")) ||
    (parent_lower.contains("winword.exe") && child_lower.contains("powershell.exe")) ||
    (parent_lower.contains("excel.exe") && child_lower.contains("cmd.exe")) ||
    (parent_lower.contains("outlook.exe") && child_lower.contains("powershell.exe"))
}

fn check_temporal_correlations(
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_state: &mut AlertState,
    alert_tx: &Sender<Alert>,
    config: &Config,
) {
    let now = chrono::Utc::now();
    
    // Check for processes that started around the same time
    let recent_starts: Vec<_> = alert_state.process_start_times
        .iter()
        .filter(|(_, time)| now - **time < chrono::Duration::seconds(30))
        .collect();
    
    if recent_starts.len() > 3 {
        // Multiple processes started within 30 seconds - could be attack chain
        let pids: Vec<u32> = recent_starts.iter().map(|(pid, _)| **pid).collect();
        
        // Check if any are scripting engines
        let scripting_count = pids.iter()
            .filter(|&&pid| process_contexts.get(&pid)
                .map(|ctx| ctx.is_scripting_engine)
                .unwrap_or(false))
            .count();
        
        if scripting_count >= 2 {
            let alert_key = format!("multiple_scripts:{}", now.timestamp());
            if should_alert(&alert_key, alert_state, Duration::from_secs(600)) {
                let processes: Vec<String> = pids.iter()
                    .filter_map(|&pid| process_contexts.get(&pid))
                    .map(|ctx| format!("{} (PID: {})", ctx.process_name, ctx.pid))
                    .collect();
                
                generate_alert(
                    crate::events::alert::AlertSeverity::Medium,
                    "MultipleScriptingProcesses",
                    "Multiple scripting processes started within short timeframe",
                    &ProcessContext {
                        start_time: now,
                        process_name: "System".to_string(),
                        pid: 0,
                        parent_pid: 0,
                        parent_name: String::new(),
                        command_line: String::new(),
                        first_network_event_time: None,
                        network_connections: Vec::new(),
                        last_alert_time: None,
                        alert_count: 0,
                        is_known_good: false,
                        is_browser_process: false,
                        is_system_process: true,
                        is_scripting_engine: false,
                        suspicious_flags: Vec::new(),
                        keypress_count: 0,
                        last_keypress_time: None,
                        process_age_at_first_network: None,
                        detected_patterns: HashSet::new(),
                    },
                    alert_tx,
                    vec![
                        format!("Process Count = {}", processes.len()),
                        format!("Scripting Count = {}", scripting_count),
                        format!("Processes = {}", processes.join("; ")),
                        format!("Timeframe = 30 seconds"),
                    ],
                );
            }
        }
    }
}

// Existing helper functions with minor enhancements...

fn should_alert(alert_key: &str, alert_state: &mut AlertState, cooldown: Duration) -> bool {
    let now = chrono::Utc::now();
    
    if let Some(last_alert) = alert_state.recent_alerts.get(alert_key) {
        if now - *last_alert < chrono::Duration::from_std(cooldown).unwrap() {
            return false; // Still in cooldown
        }
    }
    
    // Update last alert time
    alert_state.recent_alerts.insert(alert_key.to_string(), now);
    
    // Clean up old alerts (keep for 24 hours)
    alert_state.recent_alerts.retain(|_, time| {
        now - *time < chrono::Duration::hours(24)
    });
    
    true
}

fn generate_alert(
    severity: crate::events::alert::AlertSeverity,
    rule_name: &str,
    description: &str,
    context: &ProcessContext,
    alert_tx: &Sender<Alert>,
    details: Vec<String>,
) {
    let alert = Alert::new(
        &severity,
        rule_name,
        description,
        &context.process_name,
        context.pid,
        &details,
    );
    
    let _ = alert_tx.send(alert);
    
    log::warn!(
        "\n\
        ╔══════════════════════════════════════════════\n\
        ║ 🚨 ALERT: {}\n\
        ╠══════════════════════════════════════════════\n\
        ║ Severity = {:?}\n\
        ║ Process  = {} (PID: {})\n\
        ║ Rule     = {}\n\
        ║ Details  = {}\n\
        ╚══════════════════════════════════════════════",
        description,
        severity,
        context.process_name,
        context.pid,
        rule_name,
        details.join(", ")
    );
}

fn is_private_or_local(addr: &str) -> bool {
    addr.starts_with("127.") ||
    addr.starts_with("10.") ||
    (addr.starts_with("172.") && {
        if let Some(dot1) = addr.find('.') {
            if let Some(dot2) = addr[dot1+1..].find('.') {
                let second_octet = &addr[dot1+1..dot1+1+dot2];
                if let Ok(num) = second_octet.parse::<u8>() {
                    return num >= 16 && num <= 31;
                }
            }
        }
        false
    }) ||
    addr.starts_with("192.168.") ||
    addr == "::1" ||
    addr == "0:0:0:0:0:0:0:1" ||
    addr == "0.0.0.0"
}

fn cleanup_old_contexts(
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_state: &mut AlertState,
) {
    let now = chrono::Utc::now();
    
    // Remove old process contexts (older than 1 hour)
    let old_pids: Vec<u32> = process_contexts
        .iter()
        .filter(|(_, context)| now - context.start_time > chrono::Duration::hours(1))
        .map(|(&pid, _)| pid)
        .collect();
    
    for pid in old_pids {
        process_contexts.remove(&pid);
    }
    
    // Clean up old start times
    alert_state.process_start_times.retain(|_, time| {
        now - *time < chrono::Duration::hours(1)
    });
    
    // Clean up old evaluated processes
    alert_state.evaluated_processes.retain(|&pid| {
        process_contexts.contains_key(&pid)
    });
    
    // Clean up old events (keep last 1000)
    while alert_state.recent_events.len() > 1000 {
        alert_state.recent_events.pop_front();
    }
}

fn load_initial_iocs(alert_state: &mut AlertState, config: &Config) {
    // Load from config file
    if let Some(iocs) = &config.known_malicious_iocs {
        alert_state.known_malicious_ips.extend(iocs.ips.iter().cloned());
        alert_state.known_malicious_domains.extend(iocs.domains.iter().cloned());
        alert_state.known_malicious_ports.extend(iocs.ports.iter().cloned());
    }
    
    // Add common malicious ports
    alert_state.known_malicious_ports.extend(vec![
        4444, 31337, 6667, 6660, 9999, 5555, 8877, 1337,
        1234, 4321, 6789, 9898, 9988, 2333, 2334,
    ]);
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

// Keep existing functions that are still relevant...
fn is_browser_related_process(process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    lower.contains("chrome") || 
    lower.contains("firefox") || 
    lower.contains("msedge") || 
    lower.contains("opera") || 
    lower.contains("brave") || 
    lower.contains("safari")
}

fn is_system_process(process_name: &str) -> bool {
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
    lower.contains("taskhostw.exe")
}

fn is_network_aware_process(process_name: &str) -> bool {
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

fn is_common_legitimate_connection(process_name: &str, port: u16) -> bool {
    let lower = process_name.to_lowercase();
    
    // Common legitimate ports for common applications
    match port {
        // Web traffic (HTTPS)
        443 => {
            lower.contains("chrome.exe") ||
            lower.contains("firefox.exe") ||
            lower.contains("msedge.exe") ||
            lower.contains("spotify.exe") ||
            lower.contains("code.exe") ||
            lower.contains("teams.exe") ||
            lower.contains("slack.exe") ||
            lower.contains("zoom.exe") ||
            lower.contains("discord.exe") ||
            lower.contains("onedrive.exe") ||
            lower.contains("dropbox.exe")
        },
        // HTTP
        80 => {
            lower.contains("chrome.exe") ||
            lower.contains("firefox.exe") ||
            lower.contains("msedge.exe") ||
            lower.contains("spotify.exe")
        },
        // DNS
        53 => true, // DNS is always legitimate
        // NTP
        123 => true,
        // Common update/cloud ports
        8080 | 8443 => {
            lower.contains("code.exe") ||
            lower.contains("spotify.exe") ||
            lower.contains("steam.exe")
        },
        _ => false,
    }
}

fn is_suspicious_port(port: u16) -> bool {
    // Only truly suspicious/malware ports
    match port {
        4444 => true,  // Metasploit
        31337 => true, // Back Orifice
        6667 => true,  // IRC
        6660 => true,  // IRC
        9999 => true,  // Common malware
        5555 => true,  // Common malware
        8877 => true,  // Common malware
        1337 => true,  // Common malware
        8443 => false, // Often legitimate (HTTPS alternative)
        8080 => false, // Often legitimate (HTTP alternative)
        _ => port >= 49152 && port <= 65535, // Dynamic/private ports are usually ok
    }
}

fn is_high_risk_port(port: u16) -> bool {
    // Ports commonly associated with malware/C2
    matches!(port, 
        4444 | 31337 | 6667 | 6660 | 9999 | 5555 | 8877 | 1337 | 
        1234 | 4321 | 6789 | 9898 | 9988 | 2333 | 2334
    )
}

fn describe_port(port: u16) -> &'static str {
    match port {
        4444 => "Metasploit default",
        31337 => "Back Orifice",
        6667 => "IRC",
        6660 => "IRC",
        9999 => "Common malware",
        5555 => "Common malware",
        8877 => "Common malware",
        1337 => "Elite/Leet port",
        3389 => "RDP",
        22 => "SSH",
        23 => "Telnet",
        21 => "FTP",
        25 => "SMTP",
        110 => "POP3",
        143 => "IMAP",
        445 => "SMB",
        135 => "RPC",
        _ => "Unknown",
    }
}

fn categorize_process(process_name: &str) -> &'static str {
    let lower = process_name.to_lowercase();
    if lower.contains("powershell") || lower.contains("pwsh") {
        "PowerShell"
    } else if lower.contains("cmd.exe") {
        "Command Prompt"
    } else if lower.contains("wscript.exe") || lower.contains("cscript.exe") {
        "Windows Script Host"
    } else if lower.contains("mshta.exe") {
        "HTML Application"
    } else if lower.contains("regsvr32.exe") {
        "DLL Registration"
    } else if lower.contains("rundll32.exe") {
        "DLL Execution"
    } else if lower.contains("certutil.exe") {
        "Certificate Utility"
    } else if lower.contains("bitsadmin.exe") {
        "Background Intelligent Transfer"
    } else if lower.ends_with(".ps1") {
        "PowerShell Script"
    } else if lower.ends_with(".vbs") {
        "VBScript"
    } else if lower.ends_with(".js") {
        "JavaScript"
    } else if lower.ends_with(".hta") {
        "HTML Application"
    } else if lower.contains("chrome.exe") {
        "Chrome Browser"
    } else if lower.contains("firefox.exe") {
        "Firefox Browser"
    } else if lower.contains("msedge.exe") {
        "Edge Browser"
    } else if lower.contains("code.exe") {
        "VS Code"
    } else if lower.contains("spotify.exe") {
        "Spotify"
    } else if lower.contains("nvidia") {
        "NVIDIA"
    } else if lower.contains("searchhost.exe") {
        "Windows Search"
    } else {
        "Application"
    }
}