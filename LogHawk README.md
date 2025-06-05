# LogHawk
LogHawk is an open-source Python tool designed for cybersecurity teams and IT administrators. Its purpose is to automate the monitoring and analysis of system and application log files, helping to identify potential security threats like brute-force attacks, unauthorized access, and suspicious activity. Log monitoring is a critical component of any defense-in-depth security strategy, as logs contain clues about intrusions, misconfigurations, and malware behavior.
## What LogHawk Does
LogHawk helps security teams:
- Detect brute-force SSH and web login attempts by identifying repeated failed login entries.
- Identify critical application errors and unauthorized access to sensitive areas such as admin panels.
- Catch suspicious cron job executions which could indicate malware persistence.
- Monitor and raise alerts for unusual system activity like high CPU usage, port scans, or script abuse.
- Customize detection by modifying or adding new regex patterns in the source code.
## How It Works
LogHawk uses Python's built-in `re` module to define and search for suspicious patterns in various log files. The script categorizes findings by log type and severity and prints results to the console. It supports threshold-based alerting (e.g., more than 5 failed login attempts from a single IP) and scans logs line-by-line for matches. Output includes both alerts and matching log lines.
## Installation
Before using LogHawk, make sure you have Python 3 installed:
```bash
sudo apt-get install python3
```
Clone the GitHub repository:
```bash
git clone https://github.com/MagicMike2018/LogHawkScanner.git
cd LogHawkScanner
```
## How to Use It
To run LogHawk on any log file, use the following command:
```bash
python3 loghawk_scanner.py /path/to/logfile.log
```
Example:
```bash
python3 loghawk_scanner.py auth.log
```
## Sample Output
```bash
--- Scan Results for auth.log ---
Pattern: Failed SSH Login
  -> Feb 17 10:15:14 Failed password for invalid user admin from 192.168.1.15
...
--- Brute-force Attempt Detection ---
ALERT: Possible brute-force attack detected from IP 203.0.113.42 (5 failed login attempts)
...
--- Application Alerts ---
ALERT (App ERROR Alert): Payment gateway timeout
--- Suspicious CRON Jobs ---
ALERT: Suspicious cron job execution: /opt/scripts/malicious.py
```
## Automate with CRON
To run LogHawk once a day automatically using cron:
```bash
0 0 * * * /usr/bin/python3 /full/path/to/loghawk_scanner.py /var/log/auth.log
```
Use `crontab -e` to edit your cron jobs.
## Supported Log Types
- auth.log - SSH authentication attempts and sudo commands
- access.log - Web server access logs (Apache/Nginx)
- app.log - Application-specific log output and errors
- system.log - System-level events like CRON, kernel warnings, and network issues
## Contributing
LogHawk is modular. To contribute, fork the repo, make changes, and submit a pull request. New detection rules can be added by updating the `PATTERNS` dictionary in the Python script.
## License
MIT License