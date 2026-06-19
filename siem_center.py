import json
import os
import time
from datetime import datetime

LOG_REPORT = "log_analysis_report.json"
FIM_REPORT = "fim_report.json"
PORT_REPORT = "port_scan_report.json"
FINAL_SIEM_OUTPUT = "siem_final_report.json"

# We can change the rules whenever necessary
RULES = {
    "failed_login_single": 1,
    "brute_force_medium": 5,
    "brute_force_high": 10,
    "file_modified": 7,
    "untracked_file_added": 4,
    "open_port_critical": 5,
    "open_port_other": 2
}

def get_risk_level(score):
    if score == 0: return "CLEAN"
    if score < 5: return "LOW"
    if score < 12: return "MEDIUM"
    if score < 20: return "HIGH"
    return "CRITICAL"

def analyze_security_state():
    total_score = 0
    triggered_events = []
    summary_details = []

    # --- 1-Processing logs---
    if os.path.exists(LOG_REPORT):
        try:
            with open(LOG_REPORT, "r", encoding="utf-8") as f:
                data = json.load(f)
            failed_attempts = data.get("total_failed_attempts", 0)
            if failed_attempts > 0:
                total_score += failed_attempts * RULES["failed_login_single"]
                triggered_events.append("failed_logins")
                summary_details.append(f"• {failed_attempts} failed login attempts detected.")
            
            # Checking alerts in the log section
            for user_info in data.get("top_users", []):
                sev = user_info.get("severity", "LOW")
                if sev in ["HIGH", "CRITICAL"]:
                    total_score += RULES["brute_force_high"]
                    triggered_events.append("brute_force_attack")
                elif sev == "MEDIUM":
                    total_score += RULES["brute_force_medium"]
        except Exception as e:
            print(f"[!] Debug: Error parsing Log JSON: {e}")

    # --- 2-FIM processing---
    if os.path.exists(FIM_REPORT):
        try:
            with open(FIM_REPORT, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Compatible with both old and new versions of your FIM
            if data.get("status") == "ALERT":
                details = data.get("details", {})
                modified = details.get("modified_files", [])
                untracked = details.get("new_untracked_files", [])
                
                if modified:
                    total_score += len(modified) * RULES["file_modified"]
                    triggered_events.append("file_modification")
                    summary_details.append(f"• {len(modified)} file(s) MODIFIED.")
                if untracked:
                    total_score += len(untracked) * RULES["untracked_file_added"]
                    triggered_events.append("untracked_file_created")
                    summary_details.append(f"• {len(untracked)} new untracked file(s) created.")
        except Exception as e:
            print(f"[!] Debug: Error parsing FIM JSON: {e}")

    # --- 3-Port scan processing---
    if os.path.exists(PORT_REPORT):
        try:
            with open(PORT_REPORT, "r", encoding="utf-8") as f:
                data = json.load(f)
            open_ports = data.get("open_ports", [])
            if open_ports:
                triggered_events.append("open_ports_detected")
                summary_details.append(f"• Open ports found: {open_ports}")
                for port in open_ports:
                    if port in [22, 21, 23, 80, 443]: #we can add more sensitive ports
                        total_score += RULES["open_port_critical"]
                    else:
                        total_score += RULES["open_port_other"]
        except Exception as e:
            print(f"[!] Debug: Error parsing Port JSON: {e}")

    # --- 4-Correlation logic ---
    if "open_ports_detected" in triggered_events and "brute_force_attack" in triggered_events:
        total_score += 15
        triggered_events.append("CORRELATION_ALERT")
        summary_details.append("🔥 CRITICAL: Active Brute-Force on open ports!")

    risk_level = get_risk_level(total_score)
    siem_report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_risk_score": total_score,
        "risk_level": risk_level,
        "triggered_events": list(set(triggered_events)),
        "summary": summary_details
    }

    try:
        with open(FINAL_SIEM_OUTPUT, "w", encoding="utf-8") as f:
            json.dump(siem_report, f, indent=4)
    except Exception as e:
        print(f"[!] Debug: Failed to write final SIEM JSON: {e}")

    return siem_report

def main():
    print("[+] SIEM Center initialized. Starting dashboard loop...")
    while True:
        try:
            report = analyze_security_state()
            
            print("\n" + "="*50)
            print(f"🛡️  MINI SIEM DASHBOARD | {report['timestamp']}")
            print("="*50)
            print(f"RISK SCORE : {report['total_risk_score']}")
            print(f"RISK LEVEL : {report['risk_level']}")
            print("-"*50)
            print("EVENTS SUMMARY:")
            if not report['summary']:
                print("  No threats detected. System is calm.")
            else:
                for line in report['summary']:
                    print(f"  {line}")
            print("="*50)
            
        except Exception as main_err:
            print(f"❌ CRITICAL LOOP ERROR: {main_err}")
            
        time.sleep(5)

if __name__ == "__main__":
    main()
