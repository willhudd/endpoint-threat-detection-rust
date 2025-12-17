# CustomEDR - Detection-Only Endpoint Detection and Response

A lightweight Windows EDR system written in Rust that focuses on detection.

## 🎯 Features

- Process Monitoring (ETW)
- Network Monitoring (ETW)
- Registry Monitoring
- 4 Detection Rules
- JSON Logging
- CLI Tool

## 🛠️ Building

```bash
cargo build --release
```

## 🚀 Usage

### Run Sensor (Administrator required)

```bash
.\target\release\sensor.exe
```

### View Alerts

```bash
.\target\release\edr-cli.exe alerts
.\target\release\edr-cli.exe alerts --severity HIGH
.\target\release\edr-cli.exe timeline --last 24h
.\target\release\edr-cli.exe stats
```

## 🔍 Detection Rules

1. **Office → PowerShell** (HIGH)
2. **Unsigned Network Process** (MEDIUM)
3. **Suspicious Command Lines** (HIGH)
4. **Possible Keylogger** (MEDIUM)

## 📝 Logs

Alerts: `C:\ProgramData\CustomEDR\alerts.jsonl`

## ⚠️ Note

ETW modules are placeholder implementations. Full Windows API integration needed for production.
