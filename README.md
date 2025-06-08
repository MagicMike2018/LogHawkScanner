# LogHawk

**LogHawk** is an open-source Python tool designed to help security teams automatically monitor and analyze system and application log files for suspicious activity. It scans for common security threats like brute-force login attempts, unauthorized web access, malicious scripts, and system errors.

---

##  What LogHawk Does
LogHawk helps security teams:

- Detect brute-force SSH and web login attempts
- Identify critical errors and unauthorized access
- Catch suspicious cron job executions
- Monitor system and application alerts
- Customize and expand threat detection using regex patterns

---

##  Installation
Before using LogHawk, make sure you have **Python 3** installed:

```bash
sudo apt-get install python3
```

Clone the repo:
```bash
git clone https://github.com/your-username/loghawk.git
cd loghawk
```

---

##  How to Use It
When you run the script, you will be prompted to enter one of the following valid log files:

```
auth.log
access.log
app.log
system.log
```

Example:
```bash
python loghawk_scanner.py
```
Then type:
```
auth.log
```

If the file exists and is valid, it will scan and print results.
If the input is invalid, it will return:
```
Invalid File Name!
```

 **Only matching results will be shown** — pattern headers and detection alerts are skipped if there are no matches to reduce clutter.

Expected output:
```
--- Scan Results for auth.log ---
Pattern: Failed SSH Login
  -> Feb 17 10:15:14 Failed password for invalid user admin from 192.168.1.15
...
--- Brute-force Attempt Detection ---
ALERT: Possible brute-force attack detected from IP 203.0.113.42 (5 failed login attempts)
```

---

##  Automate with CRON
To run LogHawk every day using cron, add this to your crontab:

```bash
0 0 * * * /usr/bin/python3 /full/path/to/loghawk_scanner.py
```

Use `crontab -e` to edit your crontab file.

---

##  Supported Log Types
- `auth.log` (SSH activity)
- `access.log` (Web server access)
- `app.log` (Application events)
- `system.log` (Cron, sudo, kernel alerts)

---

##  Why Use LogHawk?
- Lightweight and script-based: no heavy dependencies
- Easy to read and extend with regex
- Detects real-world threats your team cares about
- Perfect for bootcamp projects or beginner-friendly security tools

---

##  License
MIT License

---

##  Contributing
Have an idea or want to expand the detection patterns? Contributions are welcome! Fork the repo, make your changes, and submit a pull request.
