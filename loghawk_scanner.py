import re
import sys
from collections import defaultdict

# === CONFIGURATION ===
# Valid log files that can be scanned
VALID_LOG_FILES = ["auth.log", "access.log", "app.log", "system.log"]

# === PATTERNS TO SEARCH ===
PATTERNS = {
    "Failed SSH Login": re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"),
    "Accepted SSH Login": re.compile(r"Accepted password for .* from (\d+\.\d+\.\d+\.\d+)"),
    "Invalid User": re.compile(r"Failed password for invalid user .* from (\d+\.\d+\.\d+\.\d+)"),
    "HTTP 401 Unauthorized": re.compile(r"(\d+\.\d+\.\d+\.\d+).+\"[A-Z]+ .+\" 401"),
    "HTTP 403 Forbidden": re.compile(r"(\d+\.\d+\.\d+\.\d+).+\"[A-Z]+ .+\" 403"),
    "App CRITICAL Alert": re.compile(r"CRITICAL: (.+)"),
    "App ERROR Alert": re.compile(r"ERROR: (.+)"),
    "Suspicious CRON Job": re.compile(r"CRON\[\d+\]: \(.+\) CMD \((.+malicious\.py|malware\.py).+\)"),
    "Unauthorized Root Access": re.compile(r"sudo: .+ : TTY=.+ ; USER=root ; COMMAND=(.+)")
}

# === MAIN LOG SCANNER ===
def scan_log(file_path):
    try:
        with open(file_path, 'r') as log:
            lines = log.readlines()

        print(f"\n--- Scan Results for {file_path} ---\n")
        failed_logins_by_ip = defaultdict(int)
        http_errors_by_ip = defaultdict(lambda: defaultdict(int))
        app_alerts = defaultdict(list)
        suspicious_cron_jobs = []
        root_access_attempts = []

        for pattern_name, regex in PATTERNS.items():
            matches = [line.strip() for line in lines if regex.search(line)]
            if matches:
                print(f"Pattern: {pattern_name}")
                for match in matches:
                    print(f"  -> {match}")
                    ip_match = regex.search(match)
                    if ip_match:
                        if "Failed" in pattern_name:
                            ip = ip_match.group(1)
                            failed_logins_by_ip[ip] += 1
                        elif "HTTP" in pattern_name:
                            ip = ip_match.group(1)
                            http_errors_by_ip[ip][pattern_name] += 1
                        elif "App" in pattern_name:
                            app_alerts[pattern_name].append(ip_match.group(1))
                        elif "CRON" in pattern_name:
                            suspicious_cron_jobs.append(ip_match.group(1))
                        elif "Unauthorized Root Access" in pattern_name:
                            root_access_attempts.append(ip_match.group(1))
                print("")

        # === BRUTE-FORCE DETECTION ===
        if any(count >= 5 for count in failed_logins_by_ip.values()):
            print("--- Brute-force Attempt Detection ---\n")
            for ip, count in failed_logins_by_ip.items():
                if count >= 5:
                    print(f"ALERT: Possible brute-force attack detected from IP {ip} ({count} failed login attempts)")

        # === SUSPICIOUS WEB ACCESS DETECTION ===
        if any(sum(errors.values()) >= 3 for errors in http_errors_by_ip.values()):
            print("\n--- Suspicious Web Access Detection ---\n")
            for ip, errors in http_errors_by_ip.items():
                total_errors = sum(errors.values())
                if total_errors >= 3:
                    print(f"ALERT: Multiple HTTP errors from IP {ip} ({errors})")

        # === CRITICAL AND ERROR ALERTS FROM APP LOG ===
        if any(app_alerts.values()):
            print("\n--- Application Alerts ---\n")
            for level, messages in app_alerts.items():
                for msg in messages:
                    print(f"ALERT ({level}): {msg}")

        # === SUSPICIOUS CRON JOBS AND ROOT ACCESS ===
        if suspicious_cron_jobs:
            print("\n--- Suspicious CRON Jobs ---\n")
            for cmd in suspicious_cron_jobs:
                print(f"ALERT: Suspicious cron job execution: {cmd}")

        if root_access_attempts:
            print("\n--- Unauthorized Root Access Attempts ---\n")
            for cmd in root_access_attempts:
                print(f"ALERT: Unauthorized root command executed: {cmd}")

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")


# === RUN SCANNER ===
if __name__ == "__main__":
    user_input = input("Enter a log file name (auth.log, access.log, app.log, system.log): ").strip()

    if user_input in VALID_LOG_FILES:
        scan_log(user_input)
    else:
        print("Invalid File Name!")
# This code is a log scanner that reads specified log files and searches for patterns indicating security issues.
# It detects failed login attempts, HTTP errors, application alerts, suspicious cron jobs, and unauthorized root access attempts.
