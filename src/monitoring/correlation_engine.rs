use crate::config::rules::Config;
use crate::events::{Alert, BaseEvent, EventType};
use crate::utils::common::{get_command_line_cached, get_parent_process_info, analyze_command_line, is_suspicious_domain, is_high_risk_port, describe_port, is_network_aware_process, is_scripting_engine, truncate_string};
use crossbeam_channel::{Receiver, Sender};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

// Suspicion scoring weights
const SUSPICION_THRESHOLD: u32 = 5;               // Adjust based on your environment
const WEIGHT_SUSPICIOUS_FLAG: u32 = 1;
const WEIGHT_KEYLOGGER_API: u32 = 2;
const WEIGHT_WEBHOOK: u32 = 3;
const WEIGHT_MALICIOUS_IP: u32 = 5;
const WEIGHT_SUSPICIOUS_DOMAIN: u32 = 3;
const WEIGHT_HIGH_RISK_PORT: u32 = 2;
const WEIGHT_RAPID_CONNECTIONS: u32 = 2;
const WEIGHT_IMMEDIATE_C2: u32 = 4;
const WEIGHT_LOLBAS: u32 = 2;

#[derive(Clone, Debug)]
struct ProcessContext {
    start_time: chrono::DateTime<chrono::Utc>,
    process_name: String,
    pid: u32,
    parent_pid: u32,
    parent_name: String,
    command_line: String,
    first_network_event_time: Option<chrono::DateTime<chrono::Utc>>,
    network_connections: Vec<NetworkConnection>,
    last_alert_time: Option<chrono::DateTime<chrono::Utc>>,
    is_known_good: bool,
    is_scripting_engine: bool,
    suspicious_flags: Vec<String>,
    process_age_at_first_network: Option<Duration>,
    suspicion_score: u32,
    alert_reasons: Vec<String>,
    alerted: bool,
    webhook_alerted: bool,
}

#[derive(Clone, Debug)]
struct NetworkConnection {
    timestamp: chrono::DateTime<chrono::Utc>,
    protocol: String,
    remote_addr: String,
    remote_port: u16,
    remote_domain: Option<String>,
    is_external: bool,
    data_size: Option<u64>,
}

struct AlertState {
    recent_alerts: HashMap<String, chrono::DateTime<chrono::Utc>>,
    verified_processes: HashSet<u32>,
    process_start_times: HashMap<u32, chrono::DateTime<chrono::Utc>>,
    evaluated_processes: HashSet<u32>,
    known_malicious_ips: HashSet<String>,
    known_malicious_domains: HashSet<String>,
    known_malicious_ports: HashSet<u16>,
    dns_webhook_observations: HashMap<String, (&'static str, chrono::DateTime<chrono::Utc>, u32)>, // Recorded webhook domain DNS queries for correlation.
    recent_events: VecDeque<(chrono::DateTime<chrono::Utc>, u32, String, String)>,
}

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
        known_malicious_ips: HashSet::new(),
        known_malicious_domains: HashSet::new(),
        known_malicious_ports: HashSet::new(),
        recent_events: VecDeque::with_capacity(1000),
        dns_webhook_observations: HashMap::new(),
    };
    
    // Load initial IOCs from config
    load_initial_iocs(&mut alert_state, &config);
    
    while shutdown.load(Ordering::Relaxed) {
        crossbeam_channel::select! {
            recv(process_rx) -> event => {
                if let Ok(event) = event {
                    process_event(&event, &mut process_contexts, &mut alert_state, &alert_tx);
                }
            },
            recv(network_rx) -> event => {
                if let Ok(event) = event {
                    process_event(&event, &mut process_contexts, &mut alert_state, &alert_tx);
                }
            },
            recv(crossbeam_channel::after(Duration::from_millis(100))) -> _ => {
                cleanup_old_contexts(&mut process_contexts, &mut alert_state);
                check_temporal_correlations(&mut process_contexts, &mut alert_state, &alert_tx);
            }
        }
    }
}

fn process_event(
    event: &BaseEvent,
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_state: &mut AlertState,
    alert_tx: &Sender<Alert>,
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
            handle_process_start(process_event, process_contexts, alert_state, alert_tx);
        }
        EventType::ProcessEnd(process_event) => {
            handle_process_end(process_event, process_contexts, alert_state, alert_tx);
        }
        EventType::NetworkConnection(network_event) => {
            // If this is a DNS event carrying a resolved domain, record it in the
            // webhook observation cache so TCP events from other PIDs can correlate.
            if let Some(ref domain) = network_event.domain {
                if let Some(service) = identify_webhook_service_by_domain(domain) {
                    let resolved_ip = &network_event.remote_address;
                    if !resolved_ip.is_empty() && resolved_ip != "0.0.0.0" {
                        log::info!(
                            "🌐 [DNS cache] Recorded webhook DNS: {} → {} ({}) queried by PID {}",
                            domain, resolved_ip, service, network_event.pid
                        );
                        alert_state.dns_webhook_observations.insert(
                            resolved_ip.clone(),
                            (service, chrono::Utc::now(), network_event.pid),
                        );
                    }
                }
            }
            handle_network_connection(network_event, process_contexts, alert_state, alert_tx);
        }
        _ => {}
    }
}

fn handle_process_start(
    process_event: &crate::events::process::ProcessEvent,
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_state: &mut AlertState,
    alert_tx: &Sender<Alert>,
) {
    let process_name = &process_event.process_name;
    let pid = process_event.pid;
    let parent_pid = process_event.parent_pid;

    // ETW sometimes fires the process-start event twice for the same PID.
    // Guard first to avoid any work or double-scoring.
    if process_contexts.contains_key(&pid) {
        return;
    }

    // Get command line immediately — it may disappear when the process exits.
    let command_line = get_command_line_cached(pid).unwrap_or_default();
    let (parent_name, _) = get_parent_process_info(parent_pid);
    let suspicious_flags = analyze_command_line(process_name, &command_line);
    let keylogger_score = calculate_keylogger_score(process_name, &command_line);

    process_contexts.insert(pid, ProcessContext {
        start_time: chrono::Utc::now(),
        process_name: process_name.clone(),
        pid,
        parent_pid,
        parent_name,
        command_line: command_line.clone(),
        first_network_event_time: None,
        network_connections: Vec::new(),
        last_alert_time: None,
        is_known_good: is_known_good_process(process_name, &command_line),
        is_scripting_engine: is_scripting_engine(process_name, &command_line),
        suspicious_flags: suspicious_flags.clone(),
        process_age_at_first_network: None,
        suspicion_score: 0,
        alert_reasons: Vec::new(),
        alerted: false,
        webhook_alerted: false,
    });
    alert_state.process_start_times.insert(pid, chrono::Utc::now());

    let context = process_contexts.get_mut(&pid).unwrap();

    // Score each suspicious command-line flag
    for flag in &suspicious_flags {
        context.suspicion_score += WEIGHT_SUSPICIOUS_FLAG;
        context.alert_reasons.push(format!("Suspicious flag: {}", flag));
        log::info!(
            "🟡 [process_start +{}] Flag '{}' for '{}' (PID: {}) → score {}",
            WEIGHT_SUSPICIOUS_FLAG, flag, process_name, pid, context.suspicion_score
        );
    }

    // Apply keylogger score
    if keylogger_score >= 3 {
        let added = WEIGHT_KEYLOGGER_API * 2;
        context.suspicion_score += added;
        context.alert_reasons.push(format!(
            "Keylogging API indicators (score {}/5)", keylogger_score
        ));
        log::warn!(
            "🔑 [process_start +{}] High-confidence keylogger indicators for '{}' (PID: {})",
            added, process_name, pid
        );
    } else if keylogger_score >= 1 {
        context.suspicion_score += WEIGHT_SUSPICIOUS_FLAG;
        context.alert_reasons.push(format!(
            "Suspicious PowerShell invocation flags (keylogger score {}/5)", keylogger_score
        ));
        log::info!(
            "🟡 [process_start +{}] Low-confidence keylogger flags for '{}' (PID: {})",
            WEIGHT_SUSPICIOUS_FLAG, process_name, pid
        );
    }

    check_webhook_exfiltration(
        context,
        "",
        0,
        None,
        alert_state
    );

    // Check for LOLBAS abuse patterns
    if is_lolbas_pattern(process_name, &command_line) {
        let pattern = identify_lolbas_pattern(&command_line);
        context.suspicion_score += WEIGHT_LOLBAS;
        context.alert_reasons.push(format!("LOLBAS pattern: {}", pattern));
        log::warn!(
            "🟠 [process_start +{}] LOLBAS '{}' for '{}' (PID: {}) → score {}",
            WEIGHT_LOLBAS, pattern, process_name, pid, context.suspicion_score
        );
    }

    maybe_alert(context, alert_tx);
}

fn handle_process_end(
    process_event: &crate::events::process::ProcessEvent,
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_state: &mut AlertState,
    alert_tx: &Sender<Alert>,
) {
    let exiting_pid = process_event.pid;

    let exit_time = chrono::Utc::now();

    // ── Evasion pattern: spawn-and-exit ─────────────────────────────────────
    // The parent process is often still "Unknown" if it quickly exits because ETW name
    // resolution races the exit event — so `is_scripting_engine` on the parent
    // is unreliable. Instead we use TWO independent child-detection signals:
    // Signal A – parent_pid match (works when name resolved in time)
    // Signal B – time-window match: any scripting engine that started within 3 s of this exit (catches the unresolved-name race)
    // Both paths require the exiting process to be short-lived (≤ 5 s) AND the
    // candidate child to carry at least one evasion flag, to limit FPs.

    let parent_lifetime = process_contexts
        .get(&exiting_pid)
        .map(|ctx| exit_time - ctx.start_time);

    let is_short_lived = parent_lifetime
        .map(|lt| lt <= chrono::Duration::seconds(5))
        .unwrap_or(true); // unknown start time → treat conservatively as short-lived

    if is_short_lived {
        let parent_name = process_contexts
            .get(&exiting_pid)
            .map(|ctx| ctx.process_name.clone())
            .unwrap_or_else(|| process_event.process_name.clone());

        let lifetime_ms = parent_lifetime
            .map(|lt| lt.num_milliseconds())
            .unwrap_or(0);

        // Signal A: explicit parent_pid linkage
        let children_by_parent: Vec<u32> = process_contexts
            .iter()
            .filter(|(pid, ctx)| **pid != exiting_pid && ctx.parent_pid == exiting_pid)
            .map(|(pid, _)| *pid)
            .collect();

        // Signal B: scripting engines that started within 3 s of this exit event
        // and haven't been alerted yet — catches the unresolved-name race.
        let children_by_time: Vec<u32> = process_contexts
            .iter()
            .filter(|(pid, ctx)| {
                **pid != exiting_pid
                    && ctx.is_scripting_engine
                    && !ctx.alerted
                    && exit_time - ctx.start_time <= chrono::Duration::seconds(3)
            })
            .map(|(pid, _)| *pid)
            .collect();

        // Merge and deduplicate
        let mut candidate_pids = children_by_parent;
        for pid in children_by_time {
            if !candidate_pids.contains(&pid) {
                candidate_pids.push(pid);
            }
        }

        for child_pid in candidate_pids {
            if let Some(child_ctx) = process_contexts.get_mut(&child_pid) {
                let child_cmd = child_ctx.command_line.to_lowercase();

                let has_hidden = child_cmd.contains("-windowstyle hidden")
                    || child_cmd.contains("-w hidden");
                let has_bypass = child_cmd.contains("-executionpolicy bypass")
                    || child_cmd.contains("-ep bypass");

                // Require at least one evasion flag to avoid false positives
                // from unrelated processes that started in the same window.
                if !has_hidden && !has_bypass {
                    continue;
                }

                child_ctx.suspicion_score += WEIGHT_SUSPICIOUS_FLAG * 2;
                child_ctx.alert_reasons.push(format!(
                    "Spawned by short-lived process '{}' (PID: {}, lived {}ms) \
                     — spawn-and-exit evasion pattern",
                    parent_name, exiting_pid, lifetime_ms
                ));

                // If the child's parent fields are still 0/empty (ETW race),
                // backfill them now that we've positively identified the parent.
                if child_ctx.parent_pid == 0 {
                    child_ctx.parent_pid = exiting_pid;
                }
                if child_ctx.parent_name.is_empty() || child_ctx.parent_name == "Unknown" {
                    child_ctx.parent_name = parent_name.clone();
                }

                if has_hidden && has_bypass {
                    child_ctx.suspicion_score += WEIGHT_LOLBAS;
                    child_ctx.alert_reasons.push(
                        "Child carries -WindowStyle Hidden + -ExecutionPolicy Bypass \
                         (spawn-and-exit evasion)"
                            .to_string(),
                    );
                    log::warn!(
                        "🚨 SPAWN-AND-EXIT EVASION: parent '{}' (PID: {}) lived {}ms \
                         → child '{}' (PID: {}) has Hidden+Bypass flags. Score: +{}",
                        parent_name, exiting_pid, lifetime_ms,
                        child_ctx.process_name, child_pid,
                        WEIGHT_SUSPICIOUS_FLAG * 2 + WEIGHT_LOLBAS,
                    );
                }

                maybe_alert(child_ctx, alert_tx);
            }
        }
    }

    process_contexts.remove(&exiting_pid);
    alert_state.process_start_times.remove(&exiting_pid);
    alert_state.verified_processes.remove(&exiting_pid);
    alert_state.evaluated_processes.remove(&exiting_pid);
}

fn handle_network_connection(
    network_event: &crate::events::network::NetworkEvent,
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_state: &mut AlertState,
    alert_tx: &Sender<Alert>,
) {
    let pid = network_event.pid;
    let process_name = &network_event.process_name;
    let remote_addr = &network_event.remote_address;
    let remote_port = network_event.remote_port;

    // ── Orphaned / misattributed external connection scanner ─────────────────
    // ETW attributes TCP events to whichever thread/process it can resolve at
    // event time.  For keylogger payloads this is often:
    //   - A ghost PID (no process-start event, name = "Unknown")
    //   - A non-scripting process like Discord.exe that happens to share the
    //     network stack context (WinSock helper threads, etc.)
    //
    // Condition: any external TCP/443 where the *connecting process is not itself
    // a scripting engine with evasion flags* but the destination IP matches a
    // known webhook service — we scan for a recently-alerted scripting candidate
    // and attribute the connection to it.
    //
    // We deliberately do NOT limit this to "Unknown" PIDs: as seen in practice,
    // Discord.exe (a real named process) can appear as the ETW owner of
    // keylogger-originated connections.
    let is_external_https = remote_port == 443
        && !is_private_or_local(remote_addr)
        && remote_addr != "0.0.0.0";

    // Connecting process is not itself a scripting engine
    let connecting_is_scripting = process_contexts
        .get(&pid)
        .map(|ctx| ctx.is_scripting_engine)
        .unwrap_or(false);

    if is_external_https && !connecting_is_scripting {
        if let Some(service) = identify_webhook_service_by_ip(remote_addr) {
            log::info!(
                "🔎 [Orphan] External TCP/443 from non-scripting PID {} ('{}') → {} ({}) \
                 — scanning for scripting candidate to attribute to",
                pid, process_name, remote_addr, service
            );

            // Find the most recently alerted scripting context that hasn't
            // received a webhook escalation yet, alerted within the last 90 s.
            let now = chrono::Utc::now();
            let candidate_pid = process_contexts
                .iter()
                .filter(|(_, ctx)| {
                    ctx.is_scripting_engine
                        && ctx.alerted
                        && !ctx.webhook_alerted
                        && ctx.last_alert_time
                            .map(|t| now - t < chrono::Duration::seconds(90))
                            .unwrap_or(false)
                })
                .max_by_key(|(_, ctx)| ctx.last_alert_time)
                .map(|(p, _)| *p);

            if let Some(cpid) = candidate_pid {
                // Build a NetworkConnection record so the count is accurate
                let attributed_conn = NetworkConnection {
                    timestamp: chrono::Utc::now(),
                    protocol: "TCP".to_string(),
                    remote_addr: remote_addr.to_string(),
                    remote_port,
                    remote_domain: network_event.domain.clone(),
                    is_external: true,
                    data_size: network_event.data_size,
                };

                log::warn!(
                    "🔗 [Orphan] Attributing {}:{} ({}) to '{}' (PID: {}) \
                     — actual ETW owner was PID {} ('{}')",
                    remote_addr, remote_port, service,
                    process_contexts.get(&cpid).map(|c| c.process_name.as_str()).unwrap_or("?"),
                    cpid, pid, process_name
                );

                if let Some(ctx) = process_contexts.get_mut(&cpid) {
                    // Always record the connection so network count stays accurate
                    ctx.network_connections.push(attributed_conn);

                    let already = ctx.alert_reasons.iter()
                        .any(|r| r.to_lowercase().contains("webhook"));
                    if !already {
                        ctx.suspicion_score += WEIGHT_WEBHOOK;
                        ctx.alert_reasons.push(format!(
                            "Webhook exfiltration confirmed (attributed from ETW owner PID {} '{}'): \
                             {} → {} (IP: {})",
                            pid, process_name, ctx.process_name, service, remote_addr
                        ));
                        log::warn!(
                            "🚨 [Orphan +{}] Webhook confirmed for '{}' (PID: {}) \
                             via connection attributed from PID {} → {} score→{}",
                            WEIGHT_WEBHOOK, ctx.process_name, cpid,
                            pid, remote_addr, ctx.suspicion_score
                        );
                        maybe_alert(ctx, alert_tx);
                    } else {
                        // Webhook already scored but keep counting connections;
                        // re-run maybe_alert in case score crossed a new threshold
                        maybe_alert(ctx, alert_tx);
                    }
                }
            } else {
                log::info!(
                    "🔎 [Orphan] No recently-alerted scripting candidate for PID {} → {}",
                    pid, remote_addr
                );
            }
        }
    }

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
        let is_scripting_engine = is_scripting_engine(process_name, &command_line);
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
            is_known_good,
            is_scripting_engine,
            suspicious_flags,
            process_age_at_first_network: None,
            suspicion_score: 0,
            alert_reasons: Vec::new(),
            alerted: false,
            webhook_alerted: false,
        };
        
        process_contexts.insert(pid, ctx);
        process_contexts.get_mut(&pid).unwrap()
    };
    
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
        protocol: match &network_event.protocol {
            crate::events::network::Protocol::TCP => "TCP".to_string(),
            crate::events::network::Protocol::UDP => "UDP".to_string(),
            crate::events::network::Protocol::QUIC => "QUIC".to_string(),
            crate::events::network::Protocol::Other(proto) => proto.clone(),
        },
        remote_addr: network_event.remote_address.clone(),
        remote_port: network_event.remote_port,
        remote_domain,
        is_external,
        data_size: network_event.data_size,
    };
    
    context.network_connections.push(connection.clone());
    
    // Run detection functions in order of importance
    // 1. Check for webhook exfiltration (highest priority for scripting engines)
    check_webhook_exfiltration(
        context,
        &network_event.remote_address,
        network_event.remote_port,
        network_event.domain.as_deref(),
        alert_state,
    );
    
    // 2. Check for immediate threats (IOCs, malicious IPs/domains, high-risk ports)
    check_immediate_threats(&connection, context, alert_state);
    
    // 3. Evaluate network behavior patterns
    evaluate_network_alert(context, &connection, alert_state);
    
    // 4. Check if we've reached the threshold to alert
    maybe_alert(context, alert_tx);
    
    // Mark as evaluated to prevent repeated processing
    alert_state.evaluated_processes.insert(pid);
}

/// The score feeds into the process suspicion score; it is not itself the threshold.
/// TODO: REDO THIS FUNCTION
fn calculate_keylogger_score(process_name: &str, command_line: &str) -> u8 {
    let lower_name = process_name.to_lowercase();
    if !lower_name.contains("powershell") && !lower_name.contains("pwsh") {
        return 0;
    }

    let lower_cmd = command_line.to_lowercase();
    let mut score = 0u8;

    // ══════════════════════════════════════════════════════════════════════════
    // TIER 1 — Invocation flag combinations
    // Score the *how*, not the *what*.  Works with -File, -Command, -Encoded.
    // ══════════════════════════════════════════════════════════════════════════

    let has_bypass  = lower_cmd.contains("-executionpolicy bypass") || lower_cmd.contains("-ep bypass");
    let has_hidden  = lower_cmd.contains("-windowstyle hidden") || lower_cmd.contains("-w hidden");
    let has_noprof  = lower_cmd.contains("-noprofile") || lower_cmd.contains("-nop");
    let has_nointer = lower_cmd.contains("-noninteractive") || lower_cmd.contains("-noni");
    let has_encoded = lower_cmd.contains("-encodedcommand") || lower_cmd.contains("-enc ");
    let has_file    = lower_cmd.contains(" -file ") || lower_cmd.contains(" -f ");

    if has_bypass  { score = score.saturating_add(1); log::info!("🟡 [KLScore +1] -ExecutionPolicy Bypass"); }
    if has_hidden  { score = score.saturating_add(1); log::info!("🟡 [KLScore +1] -WindowStyle Hidden"); }
    if has_noprof  { score = score.saturating_add(1); log::info!("🟡 [KLScore +1] -NoProfile"); }

    // -NonInteractive + -WindowStyle Hidden = fully headless, common in stagers
    if has_nointer && has_hidden {
        score = score.saturating_add(1);
        log::info!("🟡 [KLScore +1] -NonInteractive + -WindowStyle Hidden combo");
    }

    // -EncodedCommand = base64 payload, strong obfuscation signal
    if has_encoded {
        score = score.saturating_add(2);
        log::warn!("🟠 [KLScore +2] -EncodedCommand (base64 payload)");
    }

    // Evasion trifecta: Bypass + Hidden + NoProfile
    if has_bypass && has_hidden && has_noprof {
        score = score.saturating_add(2);
        log::warn!("🟠 [KLScore +2] Evasion trifecta: Bypass + Hidden + NoProfile");
    }

    // Covert file delivery: Bypass + Hidden + -File
    if has_bypass && has_hidden && has_file {
        score = score.saturating_add(1);
        log::warn!("🟡 [KLScore +1] Covert file delivery: Bypass + Hidden + -File");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TIER 2 — Obfuscation patterns
    // ══════════════════════════════════════════════════════════════════════════

    if lower_cmd.contains("frombase64string") {
        score = score.saturating_add(2);
        log::warn!("🟠 [KLScore +2] [Convert]::FromBase64String");
    }
    if lower_cmd.contains("iex") || lower_cmd.contains("invoke-expression") {
        score = score.saturating_add(1);
        log::warn!("🟡 [KLScore +1] Invoke-Expression / IEX");
    }
    if lower_cmd.contains("-join") || lower_cmd.contains("`") {
        score = score.saturating_add(1);
        log::info!("🟡 [KLScore +1] String obfuscation (-join / backtick)");
    }
    if lower_cmd.contains("[char]") {
        score = score.saturating_add(1);
        log::info!("🟡 [KLScore +1] [char] assembly obfuscation");
    }
    if lower_cmd.contains("downloadstring") || lower_cmd.contains("downloadfile")
        || lower_cmd.contains("net.webclient")
    {
        score = score.saturating_add(1);
        log::warn!("🟡 [KLScore +1] Download-cradle (WebClient / DownloadString)");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TIER 3 — Inline payload artefacts (smoking-gun if present)
    // Only visible when payload is in -Command or -EncodedCommand.
    // ══════════════════════════════════════════════════════════════════════════

    if lower_cmd.contains("getasynckeystate") {
        score = score.saturating_add(3);
        log::warn!("🔴 [KLScore +3] GetAsyncKeyState Win32 API");
    }
    if lower_cmd.contains("getkeystate") {
        score = score.saturating_add(3);
        log::warn!("🔴 [KLScore +3] GetKeyState Win32 API");
    }
    if lower_cmd.contains("setwindowshookex") || lower_cmd.contains("setkeyboardhook") {
        score = score.saturating_add(3);
        log::warn!("🔴 [KLScore +3] SetWindowsHookEx / SetKeyboardHook");
    }
    if lower_cmd.contains("dllimport") && lower_cmd.contains("user32.dll") {
        score = score.saturating_add(3);
        log::warn!("🔴 [KLScore +3] user32.dll P/Invoke DllImport");
    }
    if lower_cmd.contains("system.runtime.interopservices") {
        score = score.saturating_add(2);
        log::warn!("🟠 [KLScore +2] System.Runtime.InteropServices (P/Invoke)");
    }
    if lower_cmd.contains("add-type") && lower_cmd.contains("system.windows.forms") {
        score = score.saturating_add(2);
        log::warn!("🟠 [KLScore +2] Add-Type System.Windows.Forms (key capture)");
    }
    // Special-key logging tokens
    const SPECIAL_KEYS: &[&str] = &["[backspace]","[enter]","[tab]","[shift]","[ctrl]","[alt]"];
    let sk_count = SPECIAL_KEYS.iter().filter(|&&k| lower_cmd.contains(k)).count();
    if sk_count >= 2 {
        score = score.saturating_add(2);
        log::warn!("🟠 [KLScore +2] {} special-key logging tokens", sk_count);
    }
    if lower_cmd.contains("currentversion\\run") || lower_cmd.contains("currentversion/run") {
        score = score.saturating_add(2);
        log::warn!("🟠 [KLScore +2] Registry Run-key persistence");
    }
    if (lower_cmd.contains("while ($true)") || lower_cmd.contains("while (1)"))
        && lower_cmd.contains("start-sleep")
    {
        score = score.saturating_add(2);
        log::warn!("🟠 [KLScore +2] Infinite polling loop (while + Start-Sleep)");
    }
    if lower_cmd.contains("$env:appdata") && lower_cmd.contains(".txt") {
        score = score.saturating_add(1);
        log::info!("🟡 [KLScore +1] AppData .txt log-file reference");
    }

    if score > 0 {
        log::warn!("📊 [KLScore] TOTAL for '{}': {}/5 threshold", process_name, score);
    }
    score
}

fn identify_webhook_service_by_domain(domain: &str) -> Option<&'static str> {
    let d = domain.to_lowercase();
    if d.contains("discord.com") || d.contains("discordapp.com") {
        Some("Discord")
    } else if d.contains("webhook.office.com") {
        Some("Microsoft Teams")
    } else if d.contains("hooks.slack.com") {
        Some("Slack")
    } else if d.contains("webhook.site") {
        Some("Webhook.site")
    } else if d.contains("webhooks.mongodb-realm.com") {
        Some("MongoDB Realm")
    } else if d.contains("hooks.zapier.com") {
        Some("Zapier")
    } else {
        None
    }
}

fn identify_webhook_service_by_ip(ip: &str) -> Option<&'static str> {

    // ── Cloudflare (Discord API / CDN) ───────────────────────────────────────
    if ip.starts_with("104.") {
        let second: u8 = ip.split('.').nth(1).and_then(|o| o.parse().ok()).unwrap_or(0);
        if second >= 16 && second <= 31 {
            return Some("Discord/Cloudflare CDN (104.16-31.x.x)");
        }
    }
    if ip.starts_with("162.159.") {
        return Some("Discord/Cloudflare anycast (162.159.x.x)");
    }
    if ip.starts_with("172.") {
        let second: u8 = ip.split('.').nth(1).and_then(|o| o.parse().ok()).unwrap_or(0);
        if second >= 64 && second <= 71 {
            return Some("Discord/Cloudflare (172.64-71.x.x)");
        }
    }
    if ip.starts_with("66.22.") {
        return Some("Discord (own ASN 36459, 66.22.x.x)");
    }

    // ── Azure Front Door / Azure CDN (Discord webhook delivery in some regions) ─
    // 52.191.x.x — Azure East US (seen in live captures of Discord webhook exfil)
    if ip.starts_with("52.191.") {
        return Some("Discord webhook via Azure CDN East US (52.191.x.x)");
    }
    // 20.49.x.x — Azure Front Door global PoP
    if ip.starts_with("20.49.") {
        return Some("Webhook via Azure Front Door (20.49.x.x)");
    }
    // 20.42.x.x — Azure Front Door
    if ip.starts_with("20.42.") {
        return Some("Webhook via Azure Front Door (20.42.x.x)");
    }
    // 20.150.x.x and 20.60.x.x — Azure CDN
    if ip.starts_with("20.150.") || ip.starts_with("20.60.") {
        return Some("Webhook via Azure CDN (20.150/60.x.x)");
    }

    // ── Microsoft Teams webhooks (Azure / O365 front-door) ───────────────────
    let teams_prefixes = [
        "52.96.", "52.97.", "52.112.", "52.113.", "52.114.", "52.115.",
        "13.107.", "40.96.", "40.97.",
    ];
    if teams_prefixes.iter().any(|&p| ip.starts_with(p)) {
        return Some("Microsoft Teams/O365 webhook (Azure)");
    }

    // ── Slack (AWS us-east-1) ────────────────────────────────────────────────
    let slack_prefixes = [
        "3.89.", "3.90.", "3.93.", "3.94.", "3.95.",
        "52.2.", "52.3.", "52.4.", "52.5.",
        "34.196.", "34.197.", "34.198.", "34.199.", "34.200.",
    ];
    if slack_prefixes.iter().any(|&p| ip.starts_with(p)) {
        return Some("Slack webhook (AWS us-east-1)");
    }
    None
}

fn check_webhook_exfiltration(
    context: &mut ProcessContext,
    remote_addr: &str,
    remote_port: u16,
    remote_domain: Option<&str>,
    alert_state: &AlertState,
) {
    let lower_name = context.process_name.to_lowercase();
    if !lower_name.contains("powershell") && !lower_name.contains("pwsh") {
        return;
    }

    let lower_cmd = context.command_line.to_lowercase();

    let already_webhook_scored = context.alert_reasons.iter()
        .any(|r| r.to_lowercase().contains("webhook"));

    let inline_webhook =
           lower_cmd.contains("discord.com/api/webhooks")
        || lower_cmd.contains("discordapp.com/api/webhooks")
        || lower_cmd.contains("hooks.slack.com")
        || lower_cmd.contains("webhook.office.com")
        || lower_cmd.contains("webhook.site")
        || lower_cmd.contains("hooks.zapier.com")
        || lower_cmd.contains("ntfy.sh")                         // common lightweight exfil
        || (lower_cmd.contains("invoke-webrequest")  && lower_cmd.contains("webhook"))
        || (lower_cmd.contains("invoke-restmethod")  && lower_cmd.contains("webhook"))
        || (lower_cmd.contains("irm ")               && lower_cmd.contains("webhook"))
        || (lower_cmd.contains("iwr ")               && lower_cmd.contains("webhook"));

    if inline_webhook && !already_webhook_scored {
        context.suspicion_score += WEIGHT_WEBHOOK;
        context.alert_reasons.push(
            "Webhook exfiltration URL/cmdlet present in command line".to_string(),
        );
        log::warn!(
            "🚨 [Webhook +{}] Inline webhook indicator for '{}' (PID: {}) score→{}",
            WEIGHT_WEBHOOK, context.process_name, context.pid, context.suspicion_score
        );
    }

    if remote_port == 0 {
        return;
    }

    // ── Path A: Domain resolved and it is a known webhook service ────────────
    if let Some(domain) = remote_domain {
        if let Some(service) = identify_webhook_service_by_domain(domain) {
            if !already_webhook_scored {
                context.suspicion_score += WEIGHT_WEBHOOK;
                context.alert_reasons.push(format!(
                    "Webhook exfiltration detected: PowerShell → {} (domain: {})",
                    service, domain
                ));
                log::warn!(
                    "🚨 [Webhook +{}] Domain match '{}' → {} for '{}' (PID: {}) score→{}",
                    WEIGHT_WEBHOOK, domain, service,
                    context.process_name, context.pid, context.suspicion_score
                );
            }
            return;
        }
    }

    // ── Path B: DNS cache correlation ────────────────────────────────────────
    // We recorded recent webhook-domain DNS resolutions in alert_state.dns_webhook_observations.
    // If the destination IP of this TCP/443 event was resolved as a webhook
    // domain within the last 60 s, treat it as a confirmed webhook connection.
    if remote_port == 443 {
        if let Some((service, obs_time, _obs_pid)) =
            alert_state.dns_webhook_observations.get(remote_addr)
        {
            let age = chrono::Utc::now() - *obs_time;
            if age < chrono::Duration::seconds(60) {
                if !already_webhook_scored {
                    context.suspicion_score += WEIGHT_WEBHOOK;
                    context.alert_reasons.push(format!(
                        "Webhook exfiltration confirmed via DNS correlation: PowerShell → {} (IP: {}, \
                         DNS observed {}s ago)",
                        service, remote_addr, age.num_seconds()
                    ));
                    log::warn!(
                        "🚨 [Webhook +{}] DNS-correlated webhook: '{}' (PID: {}) → {} at {} \
                         (DNS seen {}s ago) score→{}",
                        WEIGHT_WEBHOOK, context.process_name, context.pid,
                        service, remote_addr, age.num_seconds(), context.suspicion_score
                    );
                }
                return;
            }
        }
    }

    // ── Path C: IP-range heuristics ──────────────────────────────────────────
    // Last resort when DNS hasn't been correlated yet.  Only fires for TCP/443.
    if remote_port == 443 {
        if let Some(service) = identify_webhook_service_by_ip(remote_addr) {
            if !already_webhook_scored {
                context.suspicion_score += WEIGHT_WEBHOOK;
                context.alert_reasons.push(format!(
                    "Probable webhook exfiltration (IP-range heuristic): PowerShell → {} (IP: {})",
                    service, remote_addr
                ));
                log::warn!(
                    "🚨 [Webhook +{}] IP-heuristic webhook: '{}' (PID: {}) → {} at {} score→{}",
                    WEIGHT_WEBHOOK, context.process_name, context.pid,
                    service, remote_addr, context.suspicion_score
                );
            }
            return;
        }

        // ── Path D: Catch-all — hidden/bypass PS making any external HTTPS call ─
        // Only score once; weight intentionally low — needs other indicators to alert.
        let has_evasion_flags = lower_cmd.contains("-windowstyle hidden")
            || lower_cmd.contains("-w hidden")
            || lower_cmd.contains("-executionpolicy bypass")
            || lower_cmd.contains("-ep bypass");

        if has_evasion_flags && context.network_connections.len() <= 5 {
            let already_exfil = context.alert_reasons.iter()
                .any(|r| r.contains("external HTTPS") || r.to_lowercase().contains("webhook"));
            if !already_exfil {
                context.suspicion_score += WEIGHT_SUSPICIOUS_FLAG;
                context.alert_reasons.push(format!(
                    "Evasion-flagged PowerShell making external HTTPS connection ({}:{})",
                    remote_addr, remote_port
                ));
                log::info!(
                    "🟡 [Webhook catch-all +{}] Evasion-PS → HTTPS {}:{} for '{}' (PID: {}) score→{}",
                    WEIGHT_SUSPICIOUS_FLAG, remote_addr, remote_port,
                    context.process_name, context.pid, context.suspicion_score
                );
            }
        }
    }
}

fn check_immediate_threats(
    connection: &NetworkConnection,
    context: &mut ProcessContext,
    alert_state: &mut AlertState,
) {
    if alert_state.known_malicious_ips.contains(&connection.remote_addr) {
        context.suspicion_score += WEIGHT_MALICIOUS_IP;
        context.alert_reasons.push(format!("Connection to known malicious IP: {}", connection.remote_addr));
        log::warn!("⚠️ MALICIOUS IP: {} (Score: +{})", connection.remote_addr, WEIGHT_MALICIOUS_IP);
    }

    if let Some(domain) = &connection.remote_domain {
        if alert_state.known_malicious_domains.contains(domain) {
            context.suspicion_score += WEIGHT_MALICIOUS_IP;
            context.alert_reasons.push(format!("Connection to known malicious domain: {}", domain));
            log::warn!("⚠️ MALICIOUS DOMAIN: {} (Score: +{})", domain, WEIGHT_MALICIOUS_IP);
        } else if is_suspicious_domain(domain) {
            context.suspicion_score += WEIGHT_SUSPICIOUS_DOMAIN;
            context.alert_reasons.push(format!("Connection to suspicious domain: {}", domain));
            log::warn!("⚠️ SUSPICIOUS DOMAIN: {} (Score: +{})", domain, WEIGHT_SUSPICIOUS_DOMAIN);
        }
    }

    if is_high_risk_port(connection.remote_port) {
        context.suspicion_score += WEIGHT_HIGH_RISK_PORT;
        context.alert_reasons.push(format!("Connection to high-risk port {} ({})",
            connection.remote_port, describe_port(connection.remote_port)));
        log::warn!("⚠️ HIGH-RISK PORT: {} ({}) (Score: +{})",
            connection.remote_port, describe_port(connection.remote_port), WEIGHT_HIGH_RISK_PORT);
    }

    if context.is_scripting_engine
        && connection.is_external
        && connection.remote_port == 443
        && connection.data_size.unwrap_or(0) > 1024 * 100
    {
        context.suspicion_score += WEIGHT_WEBHOOK;
        context.alert_reasons.push(format!("Large data exfiltration ({} bytes) to external host",
            connection.data_size.unwrap_or(0)));
        log::warn!("⚠️ LARGE DATA EXFIL: {} bytes (Score: +{})",
            connection.data_size.unwrap_or(0), WEIGHT_WEBHOOK);
    }
}

fn evaluate_network_alert(
    context: &mut ProcessContext,
    connection: &NetworkConnection,
    alert_state: &mut AlertState,
) {
    let now = chrono::Utc::now();
    
    // Don't evaluate non-external connections for non-scripting processes
    if !connection.is_external && !context.is_scripting_engine {
        return;
    }
    
    // Calculate actual process age for correlation
    let process_age = if let Some(first_network_time) = context.first_network_event_time {
        now - first_network_time
    } else {
        now - context.start_time
    };
    
    // ========= DETECTION RULES ==========
    
    // ── Rule 1: Scripting engine obfuscation ────────────────────────────────
    if context.is_scripting_engine && connection.is_external {
        let lower_cmd = context.command_line.to_lowercase();
        if lower_cmd.contains("frombase64string") || lower_cmd.contains("[convert]::") {
            context.suspicion_score += WEIGHT_SUSPICIOUS_FLAG;
            context.alert_reasons.push("PowerShell obfuscation patterns detected".to_string());
        }
    }
    
    // Rule 2: Unexpected process making multiple rapid connections (possible scanning)
    if context.network_connections.len() >= 5 {
        let connections_last_10s = context.network_connections
            .iter()
            .filter(|c| now - c.timestamp < chrono::Duration::seconds(10))
            .count();
        
        if connections_last_10s >= 5 {
            // Check if this is normal for this process type
            let is_normal = match context.process_name.to_lowercase().as_str() {
                name if name.contains("chrome") => connections_last_10s < 50,
                name if name.contains("firefox") => connections_last_10s < 30,
                name if name.contains("msedge") => connections_last_10s < 50,
                _ => connections_last_10s < 10  // Stricter for non-browsers
            };
            
            if !is_normal {
                context.suspicion_score += WEIGHT_RAPID_CONNECTIONS;
                context.alert_reasons.push(format!("Rapid connections: {} in 10 seconds", connections_last_10s));
                log::warn!("⚡ RAPID CONNECTIONS: {} in 10s by {} (Score: +{})", 
                    connections_last_10s, context.process_name, WEIGHT_RAPID_CONNECTIONS);
            }
        }
    }
    
    // Rule 3: Process starts and immediately makes an external connection.
    // Loopback and LAN IPC are normal — only external destinations are suspicious here.
    if connection.is_external
        && process_age < chrono::Duration::seconds(3)
        && context.network_connections.len() == 1
    {
        let mut immediate_risk_score = 0;

        if is_high_risk_port(connection.remote_port) {
            immediate_risk_score += 1;
        }
        if is_suspicious_parent_process(&context.process_name, &context.parent_name) {
            immediate_risk_score += 1;
        }
        if connection.remote_addr.starts_with("192.168.56.") { // VirtualBox host-only network
            immediate_risk_score += 1;
        }

        if immediate_risk_score >= 2 {
            context.suspicion_score += WEIGHT_IMMEDIATE_C2;
            context.alert_reasons.push(format!(
                "Immediate external connection after start (age: {}s, risk factors: {})",
                process_age.num_seconds(), immediate_risk_score
            ));
            log::warn!("🚨 IMMEDIATE HIGH-RISK CONNECTION: {}:{} (Risk factors: {}) (Score: +{})",
                connection.remote_addr, connection.remote_port, immediate_risk_score, WEIGHT_IMMEDIATE_C2);
        }
    }
    
    // Rule 4: DNS over HTTPS/QUIC pattern (common in C2)
    if connection.protocol == "QUIC" {
        if context.is_scripting_engine {
            context.suspicion_score += WEIGHT_SUSPICIOUS_FLAG;
            context.alert_reasons.push("Scripting engine using QUIC/HTTP3 protocol".to_string());
            log::warn!("🌐 SCRIPT USING QUIC: {} (Score: +{})", 
                context.process_name, WEIGHT_SUSPICIOUS_FLAG);
        } else if !is_network_aware_process(&context.process_name) {
            // Non-network process using QUIC is suspicious
            context.suspicion_score += WEIGHT_SUSPICIOUS_FLAG;
            context.alert_reasons.push("Non-network process using QUIC protocol".to_string());
        }
    }
    
    // Rule 5: Re-analyze command line flags if we missed them at process-start time.
    // Guard with a flag to prevent double-counting on every subsequent network event.
    if context.suspicious_flags.is_empty() && context.is_scripting_engine {
        let new_flags = analyze_command_line(&context.process_name, &context.command_line);
        if !new_flags.is_empty() {
            log::info!(
                "🔍 [Rule5] Late command-line analysis found {} new flags for '{}' (PID: {}): {:?}",
                new_flags.len(), context.process_name, context.pid, new_flags
            );
            // Populate suspicious_flags so this block never runs again for this process
            context.suspicious_flags = new_flags.clone();
            for flag in &new_flags {
                context.suspicion_score += WEIGHT_SUSPICIOUS_FLAG;
                context.alert_reasons.push(format!("Suspicious flag (late-detected): {}", flag));
                log::warn!(
                    "🟡 [Rule5 +{}] Late-detected flag '{}' for '{}' (PID: {})",
                    WEIGHT_SUSPICIOUS_FLAG, flag, context.process_name, context.pid
                );
            }
        }
    }
    
    // Rule 6: Connection pattern analysis
    if context.network_connections.len() >= 3 {
        // Check if all connections are to the same IP/domain (possible beaconing)
        let first_remote = &context.network_connections[0].remote_addr;
        let same_target_count = context.network_connections
            .iter()
            .filter(|c| &c.remote_addr == first_remote)
            .count();
        
        if same_target_count >= 3 && context.network_connections.len() <= 5 {
            // Initial connections all to same target - possible C2 beacon
            if !is_known_good_process(&context.process_name, &context.command_line) {
                context.suspicion_score += WEIGHT_RAPID_CONNECTIONS;
                context.alert_reasons.push(format!("Beaconing pattern: {} connections to same target", same_target_count));
                log::warn!("📡 BEACONING PATTERN: {} connections to {}", same_target_count, first_remote);
            }
        }
    }
    
    // Mark as evaluated
    alert_state.evaluated_processes.insert(context.pid);
}

fn is_known_good_process(process_name: &str, command_line: &str) -> bool {
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

fn is_suspicious_parent_process(child_name: &str, parent_name: &str) -> bool {
    let child_lower = child_name.to_lowercase();
    let parent_lower = parent_name.to_lowercase();

    // Suspicious parent-child combinations
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

fn check_temporal_correlations(
    process_contexts: &mut HashMap<u32, ProcessContext>,
    alert_state: &mut AlertState,
    alert_tx: &Sender<Alert>,
) {
    let now = chrono::Utc::now();

    // ── Check 1: multiple scripting processes in a short window ─────────────
    let recent_starts: Vec<_> = alert_state.process_start_times
        .iter()
        .filter(|(_, time)| now - **time < chrono::Duration::seconds(30))
        .collect();

    if recent_starts.len() > 3 {
        let pids: Vec<u32> = recent_starts.iter().map(|(pid, _)| **pid).collect();

        let scripting_count = pids.iter()
            .filter(|&&pid| process_contexts.get(&pid)
                .map(|ctx| ctx.is_scripting_engine)
                .unwrap_or(false))
            .count();

        if scripting_count >= 2 {
            // Bucket into 10-minute windows so the should_alert cooldown is respected
            let window = now.timestamp() / 600;
            let alert_key = format!("multiple_scripts:{}", window);
            if should_alert(&alert_key, alert_state, Duration::from_secs(600)) {
                let processes: Vec<String> = pids.iter()
                    .filter_map(|&pid| process_contexts.get(&pid))
                    .map(|ctx| format!("{} (PID: {})", ctx.process_name, ctx.pid))
                    .collect();

                generate_alert(
                    crate::events::alert::AlertSeverity::Medium,
                    "MultipleScriptingProcesses",
                    "Multiple scripting processes started within short timeframe",
                    "System",
                    0,
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

    // ── Check 2: evasion-flagged scripting engine with no alerted parent ─────
    // Safety-net for the spawn-and-exit pattern. By the time this runs (every
    // 100 ms), the parent may already be gone from process_contexts. We score
    // any scripting engine that:
    //   • started ≤ 10 s ago
    //   • carries -WindowStyle Hidden AND -ExecutionPolicy Bypass
    //   • hasn't been alerted yet
    //   • whose parent PID is NOT present in process_contexts (already exited)
    let living_pids: HashSet<u32> = process_contexts.keys().copied().collect();

    let evasion_candidates: Vec<u32> = process_contexts
        .iter()
        .filter(|(_, ctx)| {
            let age = now - ctx.start_time;
            let cmd = ctx.command_line.to_lowercase();
            let has_hidden = cmd.contains("-windowstyle hidden") || cmd.contains("-w hidden");
            let has_bypass = cmd.contains("-executionpolicy bypass") || cmd.contains("-ep bypass");
            let parent_gone = ctx.parent_pid == 0 || !living_pids.contains(&ctx.parent_pid);

            ctx.is_scripting_engine
                && !ctx.alerted
                && has_hidden
                && has_bypass
                && parent_gone
                && age <= chrono::Duration::seconds(10)
                && age >= chrono::Duration::seconds(1) // give handle_process_end a chance first
        })
        .map(|(pid, _)| *pid)
        .collect();

    for pid in evasion_candidates {
        if let Some(ctx) = process_contexts.get_mut(&pid) {
            // Only add score if spawn-and-exit reason not already recorded
            let already_scored = ctx.alert_reasons.iter()
                .any(|r| r.contains("spawn-and-exit") || r.contains("short-lived process"));

            if !already_scored {
                ctx.suspicion_score += WEIGHT_SUSPICIOUS_FLAG * 2 + WEIGHT_LOLBAS;
                ctx.alert_reasons.push(
                    "Scripting engine with Hidden+Bypass flags whose parent has already exited \
                     — likely spawn-and-exit evasion (temporal correlation)"
                        .to_string(),
                );
                log::warn!(
                    "🚨 TEMPORAL CORRELATION: scripting engine '{}' (PID: {}) has \
                     Hidden+Bypass flags and orphaned parent — spawn-and-exit evasion",
                    ctx.process_name, pid
                );
            }

            maybe_alert(ctx, alert_tx);
        }
    }
}

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

fn maybe_alert(context: &mut ProcessContext, alert_tx: &Sender<Alert>) {
    if context.suspicion_score < SUSPICION_THRESHOLD {
        return;
    }

    if !context.alerted {
        context.last_alert_time = Some(chrono::Utc::now());
        fire_alert(context, alert_tx);
        context.alerted = true;
        return;
    }

    // After the first alert fires, we keep accumulating score from late-arriving network events.
    let new_webhook_reason = context.alert_reasons.iter()
        .any(|r| r.to_lowercase().contains("webhook"));
    let already_webhook_alerted = context.webhook_alerted;

    if new_webhook_reason && !already_webhook_alerted {
        context.webhook_alerted = true;
        fire_alert(context, alert_tx);
    }
}

fn fire_alert(context: &mut ProcessContext, alert_tx: &Sender<Alert>) {
    let severity = if context.suspicion_score >= SUSPICION_THRESHOLD * 2 {
        crate::events::alert::AlertSeverity::Critical
    } else if context.suspicion_score >= SUSPICION_THRESHOLD + 2 {
        crate::events::alert::AlertSeverity::High
    } else {
        crate::events::alert::AlertSeverity::Medium
    };

    // Build reason list
    let mut reasons = context.alert_reasons.clone();
    reasons.sort();
    reasons.dedup();

    let is_escalation = context.alerted;
    let rule_name = if is_escalation {
        "WebhookExfiltrationConfirmed"
    } else {
        "MultiFactorThreatDetection"
    };
    let description = if is_escalation {
        format!(
            "⬆️  ESCALATION — Webhook exfiltration confirmed for '{}' (Score: {}/{})",
            context.process_name, context.suspicion_score, SUSPICION_THRESHOLD
        )
    } else {
        format!(
            "Multi-factor threat detected for '{}' (Score: {}/{})",
            context.process_name, context.suspicion_score, SUSPICION_THRESHOLD
        )
    };

    let mut all_details = vec![
        format!("Total Suspicion Score = {}/{}", context.suspicion_score, SUSPICION_THRESHOLD),
        format!("Indicators Detected ({}):", reasons.len()),
    ];
    for (i, reason) in reasons.iter().take(10).enumerate() {
        all_details.push(format!("  {}. {}", i + 1, reason));
    }
    if reasons.len() > 10 {
        all_details.push(format!("  ... and {} more", reasons.len() - 10));
    }

    all_details.push(format!("Process = {} (PID: {})", context.process_name, context.pid));

    let parent_display = if context.parent_pid == 0 {
        "Unknown (exited before ETW name resolution)".to_string()
    } else if context.parent_name.is_empty() || context.parent_name == "Unknown" {
        format!("Unknown (PID: {} — exited before name resolved)", context.parent_pid)
    } else {
        format!("{} (PID: {})", context.parent_name, context.parent_pid)
    };
    all_details.push(format!("Parent = {}", parent_display));

    let total_conns = context.network_connections.len();
    let external_conns: Vec<_> = context.network_connections.iter()
        .filter(|c| c.is_external)
        .collect();
    let total_bytes: u64 = context.network_connections.iter()
        .filter_map(|c| c.data_size)
        .sum();
    let quic_conns = context.network_connections.iter()
        .filter(|c| c.protocol == "QUIC")
        .count();
    let unique_dests: std::collections::HashSet<_> = context.network_connections.iter()
        .filter(|c| c.is_external)
        .map(|c| &c.remote_addr)
        .collect();

    let mut net_summary = format!(
        "Network Events = {} total ({} external, {} unique destinations",
        total_conns, external_conns.len(), unique_dests.len()
    );
    if quic_conns > 0 {
        net_summary.push_str(&format!(
            ", {} QUIC/HTTP3 — note: QUIC sessions carry multiple requests per ETW event",
            quic_conns
        ));
    }
    if total_bytes > 0 {
        net_summary.push_str(&format!(", ~{} bytes transferred", total_bytes));
    }
    net_summary.push(')');
    all_details.push(net_summary);

    for conn in &external_conns {
        let proto_label = if conn.protocol == "QUIC" { "QUIC/HTTP3" } else { &conn.protocol };
        let size_label = conn.data_size
            .map(|b| format!(" [{} bytes]", b))
            .unwrap_or_default();
        let domain_label = conn.remote_domain.as_deref()
            .map(|d| format!(" ({})", d))
            .unwrap_or_default();
        all_details.push(format!(
            "  → {}:{}{}{} via {}",
            conn.remote_addr, conn.remote_port, domain_label, size_label, proto_label
        ));
    }

    if !context.command_line.is_empty() {
        all_details.push(format!(
            "Command Line = {}",
            truncate_string(&context.command_line, 200)
        ));
    }

    generate_alert(
        severity,
        rule_name,
        &description,
        &context.process_name,
        context.pid,
        alert_tx,
        all_details,
    );
}

fn generate_alert(
    severity: crate::events::alert::AlertSeverity,
    rule_name: &str,
    description: &str,
    process_name: &str,
    pid: u32,
    alert_tx: &Sender<Alert>,
    details: Vec<String>,
) {
    let alert = Alert::new(
        &severity,
        rule_name,
        description,
        process_name,
        pid,
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
        ║ Details:\n\
        {}\n\
        ╚══════════════════════════════════════════════",
        description,
        severity,
        process_name,
        pid,
        rule_name,
        details.iter().map(|d| format!("║   {}", d)).collect::<Vec<_>>().join("\n")
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

    // Clean up stale DNS webhook observations (older than 120 s)
    alert_state.dns_webhook_observations.retain(|_, (_, obs_time, _)| {
        now - *obs_time < chrono::Duration::seconds(120)
    });
}

fn load_initial_iocs(alert_state: &mut AlertState, config: &Config) {
    // Load from config file
    if let Some(iocs) = &config.known_malicious_iocs {
        alert_state.known_malicious_ips.extend(iocs.ips.iter().cloned());
        alert_state.known_malicious_domains.extend(iocs.domains.iter().cloned());
        alert_state.known_malicious_ports.extend(iocs.ports.iter().cloned());
    }
}