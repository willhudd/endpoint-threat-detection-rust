use clap::{Parser, Subcommand};
use colored::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use anyhow::Result;
use chrono::{DateTime, Duration, Local};
use shared::Alert;

const LOG_DIR: &str = r"C:\ProgramData\CustomEDR";
const ALERTS_FILE: &str = "alerts.jsonl";

#[derive(Parser)]
#[command(name = "edr-cli")]
#[command(about = "CustomEDR Command Line Interface", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display all alerts
    Alerts {
        /// Filter by severity (HIGH, MEDIUM, LOW)
        #[arg(short, long)]
        severity: Option<String>,
        
        /// Show only the last N alerts
        #[arg(short, long)]
        last: Option<usize>,
    },
    
    /// Show timeline of events
    Timeline {
        /// Time window (e.g., "1h", "24h", "7d")
        #[arg(short, long, default_value = "24h")]
        last: String,
    },
    
    /// Show statistics
    Stats,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Alerts { severity, last } => show_alerts(severity, last)?,
        Commands::Timeline { last } => show_timeline(&last)?,
        Commands::Stats => show_stats()?,
    }
    
    Ok(())
}

fn show_alerts(severity_filter: Option<String>, last_n: Option<usize>) -> Result<()> {
    let alerts_path = PathBuf::from(LOG_DIR).join(ALERTS_FILE);
    
    if !alerts_path.exists() {
        println!("{}", "No alerts found.".yellow());
        return Ok(());
    }
    
    let file = File::open(&alerts_path)?;
    let reader = BufReader::new(file);
    
    let mut alerts: Vec<Alert> = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        if let Ok(alert) = serde_json::from_str::<Alert>(&line) {
            if let Some(ref sev) = severity_filter {
                if alert.severity.to_uppercase() != sev.to_uppercase() {
                    continue;
                }
            }
            alerts.push(alert);
        }
    }
    
    if let Some(n) = last_n {
        let start = alerts.len().saturating_sub(n);
        alerts = alerts[start..].to_vec();
    }
    
    println!("\n{}", "═══════════════════════════════════════════════════════".cyan());
    println!("{} {}", "CustomEDR".bright_cyan().bold(), "Alerts".white());
    println!("{}\n", "═══════════════════════════════════════════════════════".cyan());
    
    if alerts.is_empty() {
        println!("{}", "No alerts matching criteria.".yellow());
        return Ok(());
    }
    
    for alert in alerts {
        print_alert(&alert);
    }
    
    Ok(())
}

fn print_alert(alert: &Alert) {
    let severity_colored = match alert.severity.as_str() {
        "HIGH" => alert.severity.red().bold(),
        "MEDIUM" => alert.severity.yellow().bold(),
        "LOW" => alert.severity.green().bold(),
        _ => alert.severity.white().bold(),
    };
    
    println!("[{}] {} {}", alert.time.bright_black(), severity_colored, alert.rule.bright_white().bold());
    println!("  {} {}", "Process:".bright_blue(), alert.process);
    println!("  {} {}", "Parent:".bright_blue(), alert.parent);
    
    if let Some(ref cmd) = alert.command_line {
        println!("  {} {}", "Command:".bright_blue(), cmd.bright_black());
    }
    
    if let Some(ref details) = alert.details {
        println!("  {} {}", "Details:".bright_blue(), details);
    }
    
    println!();
}

fn show_timeline(window: &str) -> Result<()> {
    let duration = parse_duration(window)?;
    let cutoff = Local::now() - duration;
    
    let alerts_path = PathBuf::from(LOG_DIR).join(ALERTS_FILE);
    
    if !alerts_path.exists() {
        println!("{}", "No timeline data found.".yellow());
        return Ok(());
    }
    
    let file = File::open(&alerts_path)?;
    let reader = BufReader::new(file);
    
    println!("\n{}", "═══════════════════════════════════════════════════════".cyan());
    println!("{} {} {}", "Timeline".bright_cyan().bold(), "- Last".white(), window.bright_white());
    println!("{}\n", "═══════════════════════════════════════════════════════".cyan());
    
    let mut count = 0;
    
    for line in reader.lines() {
        let line = line?;
        if let Ok(alert) = serde_json::from_str::<Alert>(&line) {
            if let Ok(alert_time) = DateTime::parse_from_rfc3339(&alert.time) {
                if alert_time.with_timezone(&Local) >= cutoff {
                    print_alert(&alert);
                    count += 1;
                }
            }
        }
    }
    
    if count == 0 {
        println!("{}", "No events in this time window.".yellow());
    }
    
    Ok(())
}

fn show_stats() -> Result<()> {
    let alerts_path = PathBuf::from(LOG_DIR).join(ALERTS_FILE);
    
    if !alerts_path.exists() {
        println!("{}", "No statistics available.".yellow());
        return Ok(());
    }
    
    let file = File::open(&alerts_path)?;
    let reader = BufReader::new(file);
    
    let mut total = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    
    for line in reader.lines() {
        let line = line?;
        if let Ok(alert) = serde_json::from_str::<Alert>(&line) {
            total += 1;
            match alert.severity.as_str() {
                "HIGH" => high += 1,
                "MEDIUM" => medium += 1,
                "LOW" => low += 1,
                _ => {}
            }
        }
    }
    
    println!("\n{}", "═══════════════════════════════════════════════════════".cyan());
    println!("{}", "CustomEDR Statistics".bright_cyan().bold());
    println!("{}\n", "═══════════════════════════════════════════════════════".cyan());
    
    println!("{} {}", "Total Alerts:".bright_blue(), total.to_string().bright_white().bold());
    println!("{} {}", "HIGH:".red().bold(), high);
    println!("{} {}", "MEDIUM:".yellow().bold(), medium);
    println!("{} {}", "LOW:".green().bold(), low);
    println!();
    
    Ok(())
}

fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let num: i64 = s[..s.len()-1].parse()?;
    let unit = &s[s.len()-1..];
    
    match unit {
        "h" => Ok(Duration::hours(num)),
        "d" => Ok(Duration::days(num)),
        "m" => Ok(Duration::minutes(num)),
        _ => Err(anyhow::anyhow!("Invalid duration format")),
    }
}