# 🛡️ PyShield-SIEM: Lightweight Security Event Correlation Engine

A modular, file-driven **Security Information and Event Management (SIEM)** emulation center built from scratch in Python. This project demonstrates enterprise Security Operations Center (SOC) architectural patterns, including distributed log parsing, RSA-based continuous file integrity monitoring, multi-threaded network reconnaissance, and multi-source threat correlation.

---

## 🏗️ System Architecture & Data Flow

Instead of single-point detection, this system utilizes independent security tools acting as "agents/sensors" that dump telemetry into normalized JSON reports. The central SIEM core aggregates, scores, and correlates these inputs to generate a live dashboard.


  [ Log Analyzer Agent ]     --->  log_analysis_report.json  ---\
  [ RSA FIM Monitor Agent ]  --->  fim_report.json           ----> [ Core SIEM Engine ] ---> Live Terminal Dashboard
  [ Multi-Threaded Scan ]    --->  port_scan_report.json     ---/

  ## 🚨 Threat Scoring Rules & Advanced Correlation
The SIEM ranks infrastructure risk dynamically into five tiers (CLEAN, LOW, MEDIUM, HIGH, CRITICAL) using customized rule weights:
 * Failed Login Attempt: +1 Risk Points
 * Medium-Alert Brute-Force: +5 Risk Points
 * High/Critical Brute-Force: +10 Risk Points
 * Critical Monitored File Modification: +7 Risk Points
 * Untracked File Created in Secure Dir: +4 Risk Points
 * Sensitive Management Port Exposed (e.g., 21, 22, 23): +5 Risk Points
### 🔥 Smart Correlation Logic (The SOC Edge)
A single open port is a vulnerability; a brute-force log is an event. But **when they happen together, it's an incident**.
If the engine detects a **Brute-Force Attack** *simultaneously* with an **Exposed Management Port (e.g., SSH/Telnet)**, it triggers an advanced CORRELATION_ALERT and injects a +15 risk multiplier to instantly flag a targeted breach attempt.
## 📦 Project Structure
mini_siem/
│
├── log_analyzer_v1.py       # Log Parser Agent (Regex auth log analysis)
├── secure_monitor.py        # RSA Digital Signature File Integrity Monitor
├── port_scanner.py          # Multi-threaded Socket-based Recon Agent
├── siem_center.py           # Core Correlation Engine & Live Dashboard Loop
└── README.md                # Project Documentation

## 🖥️ Live SOC Dashboard Preview

When running, the engine automatically clears the screen and refreshes every 5 seconds to show the current threat landscape:
==================================================
🛡️  MINI SIEM DASHBOARD | 2026-06-19 14:01:41
==================================================
RISK SCORE : 20
RISK LEVEL : CRITICAL
--------------------------------------------------
EVENTS SUMMARY:
  • 5 failed login attempts detected.
  • Open ports found: [21, 23, 80]
==================================================
<img width="572" height="287" alt="image" src="https://github.com/user-attachments/assets/5f85f928-2088-4aa2-a5e3-35f28ce23690" />


## 🚀 Getting Started & Execution
 1. **Generate Keys & Run FIM Agent:**
   
```bash
   python secure_monitor.py generate-keys
   python secure_monitor.py save secure_file.txt
   python secure_monitor.py monitor ./configs --interval 5
```
   2. **Analyze Auth Logs:**
   ```bash
   python log_analyzer_v1.py real_auth.log
```
 3. **Fire Up the SIEM Center:**

```bash
   python siem_center.py
```
*Developed as a practical study of Blue Teaming, Log Correlation, and Cryptographic Integrity Monitoring.*


