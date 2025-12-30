<p align="center">
  <img src="assets/banner.png" alt="EDR System Banner" width="100%">
</p>

# Lightweight Endpoint Detection System - Rust

---

## 📌 Project Purpose

This is a **prototype endpoint detection system** written in Rust, implementing real-time monitoring, behavioral analysis, and threat correlation for Windows endpoints.

**Key Capabilities:**
- Real-time process creation/termination monitoring via ETW
- Network connection tracking with TCP/IP ETW integration
- Configurable detection rules with JSON-based configuration
- Cross-event correlation with severity-based alerting

---

## 🔵🛡️ Blue Team Perspective (This Repo)

### Detection Capabilities

1. **Process Monitoring**
   - Real-time process creation/termination via kernel ETW
   - Suspicious process pattern matching (PowerShell, scripting engines)
   - Parent-child process relationship tracking

2. **Network Monitoring**
   - TCP/UDP connection tracking via ETW and Windows APIs
   - Suspicious destination detection (TOR, VPNs, malicious IPs)
   - Rapid connection attempt detection

3. **Behavioral Correlation**
   - New process making immediate network connections
   - Process-to-network activity correlation
   - Temporal analysis of suspicious patterns

4. **Alerting System**
   - Four-tier severity system (Low → Critical)
   - Evidence collection and timestamping
   - Configurable correlation rules

---

## 🔴🗡️ Red Team Perspective (Companion Project)

👉 **Offensive USB Repository:**  [usb-keylogger-threat-emulation](https://github.com/willhudd/usb-keylogger-threat-emulation)

The companion USB HID attack simulation tests this EDR's detection capabilities for:

- **PowerShell execution chain detection**
- **Suspicious process behavior correlation**
- **Rapid network activity alerts**
- **Persistence mechanism detection**

This EDR is specifically tuned to detect:
- Scripting engine abuse (PowerShell, CScript, WScript)
- Living-off-the-land binaries (LOLBins)
- Beaconing and command & control traffic
- Process injection and code execution patterns

---

## 🚀 Getting Started

### Prerequisites
- **Windows 10/11** (Windows API dependencies)
- **Rust 1.70+** with nightly toolchain
- **Administrator privileges** (required for ETW monitoring)
- **Visual Studio Build Tools** (for Windows crate dependencies)

### Installation
```bash
# Clone the repository
git clone https://github.com/willhudd/endpoint-threat-detection-rust.git
cd rust-edr-system

# Build in release mode
cargo build --release

# Run with administrator privileges
./target/release/endpoint-threat-detection-rust.exe
