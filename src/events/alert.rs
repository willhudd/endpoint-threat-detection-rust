use std::fmt;

#[derive(Debug, Clone)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub rule_name: String,
    pub description: String,
    pub process_name: String,
    pub pid: u32,
    pub evidence: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} - PID: {} - {} - Evidence: {:?}",
            self.severity_str(),
            self.rule_name,
            self.pid,
            self.description,
            self.evidence
        )
    }
}

impl Alert {
    pub fn new(
        severity: AlertSeverity,
        rule_name: &str,
        description: &str,
        process_name: &str,
        pid: u32,
        evidence: Vec<String>,
    ) -> Self {
        Self {
            severity,
            rule_name: rule_name.to_string(),
            description: description.to_string(),
            process_name: process_name.to_string(),
            pid,
            evidence,
            timestamp: chrono::Utc::now(),
        }
    }

    fn severity_str(&self) -> &str {
        match self.severity {
            AlertSeverity::Low => "LOW",
            AlertSeverity::Medium => "MEDIUM",
            AlertSeverity::High => "HIGH",
            AlertSeverity::Critical => "CRITICAL",
        }
    }
}