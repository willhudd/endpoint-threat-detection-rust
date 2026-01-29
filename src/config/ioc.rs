use std::collections::{HashSet, HashMap};
use std::sync::Mutex;
use regex::Regex;
use lazy_static::lazy_static;
use crate::config::rules::{MaliciousIOCs, IoCPattern};

lazy_static! {
    pub static ref IOC_MANAGER: Mutex<IOCManager> = Mutex::new(IOCManager::new());
}

pub struct IOCManager {
    malicious_ips: HashSet<String>,
    malicious_domains: HashSet<String>,
    malicious_ports: HashSet<u16>,
    patterns: Vec<PatternMatcher>,
    webhook_domains: HashSet<String>,
}

struct PatternMatcher {
    name: String,
    pattern: Regex,
    pattern_type: String,
    severity: String,
}

impl IOCManager {
    pub fn new() -> Self {
        Self {
            malicious_ips: HashSet::new(),
            malicious_domains: HashSet::new(),
            malicious_ports: HashSet::new(),
            patterns: Vec::new(),
            webhook_domains: HashSet::new(),
        }
    }
    
    pub fn load_from_config(&mut self, iocs: &MaliciousIOCs) {
        // Clear existing IOCs
        self.malicious_ips.clear();
        self.malicious_domains.clear();
        self.malicious_ports.clear();
        self.patterns.clear();
        
        // Load new IOCs
        for ip in &iocs.ips {
            self.malicious_ips.insert(ip.clone());
        }
        
        for domain in &iocs.domains {
            self.malicious_domains.insert(domain.clone());
        }
        
        for port in &iocs.ports {
            self.malicious_ports.insert(*port);
        }
        
        for pattern in &iocs.patterns {
            if let Ok(regex) = Regex::new(&pattern.pattern) {
                self.patterns.push(PatternMatcher {
                    name: pattern.name.clone(),
                    pattern: regex,
                    pattern_type: pattern.pattern_type.clone(),
                    severity: pattern.severity.clone(),
                });
            }
        }
    }
    
    pub fn add_webhook_domains(&mut self, domains: &[String]) {
        for domain in domains {
            self.webhook_domains.insert(domain.clone());
        }
    }
    
    pub fn is_malicious_ip(&self, ip: &str) -> bool {
        self.malicious_ips.contains(ip)
    }
    
    pub fn is_malicious_domain(&self, domain: &str) -> bool {
        self.malicious_domains.contains(domain)
    }
    
    pub fn is_malicious_port(&self, port: u16) -> bool {
        self.malicious_ports.contains(&port)
    }
    
    pub fn is_webhook_domain(&self, domain: &str) -> bool {
        self.webhook_domains.contains(domain)
    }
    
    pub fn match_patterns(&self, text: &str) -> Vec<(String, String)> {
        let mut matches = Vec::new();
        for pattern in &self.patterns {
            if pattern.pattern.is_match(text) {
                matches.push((pattern.name.clone(), pattern.severity.clone()));
            }
        }
        matches
    }
    
    pub fn check_for_suspicious_domain(&self, domain: &str) -> bool {
        // Check for DGA patterns
        if domain.chars().filter(|c| c.is_ascii_digit()).count() > 5 {
            return true;
        }
        
        // Check for excessive subdomains
        if domain.matches('.').count() > 4 {
            return true;
        }
        
        // Check for suspicious TLDs
        let suspicious_tlds = vec![".xyz", ".top", ".club", ".bid", ".win", ".gq", ".ml", ".cf"];
        if suspicious_tlds.iter().any(|tld| domain.ends_with(tld)) {
            return true;
        }
        
        false
    }
}

// Helper functions
pub fn is_keylogger_pattern(command_line: &str) -> bool {
    let lower_cmd = command_line.to_lowercase();
    
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

pub fn extract_keylogger_indicators(command_line: &str) -> String {
    let lower_cmd = command_line.to_lowercase();
    let mut indicators = Vec::new();
    
    if lower_cmd.contains("getasynckeystate") {
        indicators.push("GetAsyncKeyState API");
    }
    if lower_cmd.contains("discord.com/api/webhooks") {
        indicators.push("Discord Webhook");
    }
    if lower_cmd.contains("-windowstyle hidden") {
        indicators.push("Hidden Window");
    }
    if lower_cmd.contains("-executionpolicy bypass") {
        indicators.push("Execution Policy Bypass");
    }
    if lower_cmd.contains("webhookurl") {
        indicators.push("Webhook Variable");
    }
    
    indicators.join(", ")
}