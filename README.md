
# 🛡️ Enterprise Network Log Analyzer & Security Event Detection Automation

## 📌 Overview
The **Enterprise Network Log Analyzer** is a Python-based security automation system that simulates a **Security Operations Center (SOC)** workflow.  
It ingests multiple types of network logs, applies rule-based threat detection, generates alerts, displays a live security dashboard, and produces daily security reports.

This project reflects **real-world IT infrastructure monitoring and security automation systems**.

---

## 🎯 Objectives
- Parse multiple network log formats
- Detect suspicious and malicious activities using predefined rules
- Generate medium and high severity alerts
- Display a security summary dashboard in the console
- Produce daily security reports automatically

---

## 📂 Supported Log Types
The system processes logs from the `network_logs/` directory, including:
- Firewall logs
- Access logs
- System event logs
- Login attempt logs
- API gateway logs

Each log entry may include:
- Timestamp
- Source IP
- Destination / Endpoint
- Request method
- Status code
- User ID (optional)

---

## 🚨 Threat Detection Rules
The rule engine detects the following security threats:

### 🔴 High Severity
- **Brute Force Attack**
  - More than _N failed logins_ from the same IP within _T minutes_
- **Suspicious IP Access**
  - Access from blacklisted IP addresses
- **Unauthorized Access Attempt**
  - Accessing restricted endpoints with failed status codes

### 🟠 Medium Severity
- **High Traffic Spike**
  - More than _N requests_ from a single IP in _T seconds_
- **Firewall Block Alert**
  - Any log entry containing the keyword `BLOCKED`

All thresholds and rules are configurable.

---

## 📊 Security Dashboard (Console)
After analysis, the system displays:
- Total logs processed
- Unique IP addresses detected
- Total alerts and critical alerts
- Failed login attempts
- Top 5 most active IPs
- Top accessed endpoints
- Recent critical alerts

---

## 📝 Report Generation
A **daily security report** is generated automatically:

**Filename format**
```
security_report_YYYY-MM-DD.txt
```

**Report includes**
- Total logs processed
- Alerts and critical alerts count
- Threat categories triggered
- Top suspicious IPs
- Blocked attempts summary
- ASCII-based time activity chart

Reports are saved in the `reports/` directory.

---

## ⚙️ Configuration
All detection behavior is driven by `config.json`, which contains:
- Blacklisted IPs
- Detection thresholds
- Restricted endpoints
- Allowed countries
- Log and report directories

The system dynamically adapts when configuration values are changed.

---

## 📁 Project Structure
```
network_security/
│
├── network_logs/          # Input log files
├── logs/
│   ├── alerts.log
│   └── critical_alerts.log
│
├── reports/
│   └── security_report_<date>.txt
│
├── modules/
│   ├── log_parser.py
│   ├── rule_engine.py
│   ├── dashboard.py
│   └── reporter.py
│
├── config.json
├── main.py
└── README.md
```

---

## ▶️ How to Run
1. Place log files inside the `network_logs/` directory
2. Configure rules in `config.json`
3. Run the application:
```bash
python main.py
```

---

## 🧰 Recommended Libraries
- `re`
- `json`
- `datetime`
- `logging`
- `collections`
- `reportlab` *(optional – for PDF reports)*

---

## 🏁 Output
- Real-time console dashboard
- Alert logs stored in `logs/`
- Daily security reports in `reports/`

---

## 🔐 Use Cases
- SOC automation simulation
- Security monitoring practice
- Python-based log analysis learning
- Academic and portfolio projects

---

**Author:** Vayineni Devi malini 
**Category:** Cybersecurity | SOC | Automation | Python
