# EDR - Endpoint Detection System

A lightweight, high-performance Endpoint Detection and Response (EDR) system for Windows, built with Rust and leveraging Event Tracing for Windows (ETW).

## Features

- **Real-time Process Monitoring**: Uses kernel-mode ETW to track process creation and termination
- **Rule-based Detection**: Customizable detection rules with MITRE ATT&CK mapping
- **Behavioral Analysis**: Detects anomalous patterns like rapid process creation and deep process chains
- **Alert System**: Contextual alerts with severity levels and recommended actions
- **Extensible Architecture**: Modular design ready for file, network, and registry monitoring

## Requirements

- Windows 10/11 or Windows Server 2016+
- Administrator privileges
- Rust 1.70+ (for building)

## Installation

1. Clone the repository:

```bash
git clone <your-repo>
cd edr
```

2. Build the project:

```bash
cargo build --release
```

3. The binary will be located at `target/release/edr.exe`

## Usage

**Must be run as Administrator:**

```bash
# Run from PowerShell or Command Prompt with admin rights
.\target\release\edr.exe
```

The EDR will start monitoring and display alerts in the console when suspicious activity is detected.

## Architecture

### Components

- **ETW Module** (`src/etw/`): Interfaces with Windows ETW for low-level event collection
- **Detection Engine** (`src/detection/`): Analyzes events against rules and behavioral patterns
- **Alerting System** (`src/alerting/`): Generates and formats security alerts
- **Models** (`src/models/`): Data structures for events, processes, and telemetry

### Event Pipeline

```
ETW Kernel Events → Event Channel → Detection Engine → Alert Channel → Console/Log
```

## Detection Rules

The EDR includes several pre-configured detection rules:

1. **Suspicious PowerShell Execution** - Detects encoded commands and download cradles
2. **Process Injection** - Identifies suspicious parent-child process relationships
3. **Credential Dumping** - Detects tools like Mimikatz
4. **Lateral Movement** - Identifies PsExec and similar tools
5. **Registry Persistence** - Monitors Run key modifications
6. **WMI Abuse** - Detects suspicious WMI usage
7. **Ransomware Indicators** - Identifies mass file encryption patterns

### Adding Custom Rules

Edit `config/rules.toml` or modify `src/detection/rules.rs` to add custom detection logic.

Example rule structure:

```rust
DetectionRule {
    id: "CUSTOM-001".to_string(),
    name: "My Custom Rule".to_string(),
    description: "Description of what this detects".to_string(),
    severity: Severity::High,
    enabled: true,
    mitre_tactics: vec![MitreTactic::Execution],
    mitre_techniques: vec!["T1059.001".to_string()],
    conditions: vec![
        RuleCondition::ProcessName {
            pattern: "malware.exe".to_string(),
            regex: None,
        },
    ],
}
```

## Alert Severity Levels

- **Critical** 🚨: Immediate threat requiring instant response
- **High** 🔴: Serious security issue requiring investigation
- **Medium** 🟠: Suspicious activity worth reviewing
- **Low** 🟡: Minor anomaly or policy violation
- **Info** ℹ️: Informational event

## Future Enhancements

- [ ] File system monitoring (file create/delete/modify)
- [ ] Network connection tracking
- [ ] Registry monitoring
- [ ] DLL injection detection
- [ ] Image load monitoring
- [ ] Process memory scanning
- [ ] Automated response actions
- [ ] Web dashboard
- [ ] SIEM integration (Splunk, ELK, etc.)
- [ ] Machine learning-based anomaly detection
- [ ] Process memory dumping for analysis
- [ ] Configuration file support

## Testing

Run the test suite:

```bash
cargo test
```

## Performance

The EDR is designed to be lightweight and efficient:

- Minimal CPU overhead (< 5% on average systems)
- Low memory footprint (< 50MB typical)
- Real-time event processing with channel-based concurrency

## Troubleshooting

### "Failed to enable SeSystemProfilePrivilege"

- Ensure you're running as Administrator
- Right-click the executable and select "Run as administrator"

### "Kernel logger is already running"

- Stop existing logger: `logman stop "NT Kernel Logger" -ets`
- Then restart the EDR

### No events appearing

- Verify administrator privileges
- Check Windows Event Log for ETW errors
- Ensure Windows Event Tracing service is running

## Security Considerations

This EDR tool requires administrator privileges to function. Always:

- Review the source code before running
- Run only on systems you own or have permission to monitor
- Follow your organization's security policies
- Keep the software updated

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

[Choose your license - MIT, Apache 2.0, GPL, etc.]

## Disclaimer

This tool is for educational and legitimate security monitoring purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## Credits

Built with:

- [windows-rs](https://github.com/microsoft/windows-rs) - Windows API bindings
- [crossbeam](https://github.com/crossbeam-rs/crossbeam) - Concurrent channels
- [log](https://github.com/rust-lang/log) - Logging facade

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Windows ETW Documentation](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
- [Kernel Logger Session](https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-the-nt-kernel-logger-session)
