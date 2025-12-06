# 🛡️ Malicious URL Detector

Multi-source phishing & malicious URL analysis toolkit for SOC / Threat Hunting.

**Developed by:** Lior Simchi  
**Status:** Active  
**Type:** Security Tool – Threat Intelligence / URL Analysis  
**Language:** Python  


## 📌 Overview

`malicious-url-detector` is a Python tool designed to analyze URLs using a **multi-source scoring approach**, similar to how a SOC analyst triages indicators of compromise (IoCs).

This tool performs:

- **Static URL analysis** (TLD, phishing keywords, IP-based URL)  
- **Threat intelligence lookups**  
  - VirusTotal API  
  - PhishTank  
  - AbuseIPDB (for IP indicators)

The result is a **combined risk score** with an automated recommendation:

> ✔️ Safe  
> ⚠️ High Risk — Block & escalate to SOC


## 🧠 Why this tool?

Phishing and malicious hosting infrastructure evolve rapidly.  
SOC analysts need **fast triage** without manually pivoting across multiple platforms.

This tool:

- Saves time  
- Standardizes triage  
- Uses multiple intelligence sources  
- Works offline for static scoring  
- Helps reduce false positives  


## ✨ Features

- Static heuristic analysis  
- VirusTotal URL scanning API  
- PhishTank phishing database lookup  
- AbuseIPDB IP reputation lookup  
- Prints clear analyst recommendation  
- Simple architecture with `config.py` secrets isolation  
- Supports batch analysis via `urls.txt`  
- Easy to extend with additional TI sources  


## 🏗 Architecture

```
malicious-url-detector/
│-- analyzer.py        ← main logic
│-- config.py          ← API keys (ignored in git)
│-- urls.txt           ← URL list to analyze
│-- requirements.txt   ← dependencies
│-- .gitignore         ← hides secrets
```

## 🔐 API Keys Setup

Create a `config.py` file in the project root containing your API keys:

```python
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_KEY = "YOUR_ABUSEIPDB_API_KEY"
```

⚠️ Make sure `config.py` is included in `.gitignore` and **never pushed to GitHub**.


## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USER/malicious-url-detector.git
cd malicious-url-detector
pip install -r requirements.txt
```


## ▶ Usage

Edit `urls.txt` to include URLs (one per line):

```
https://google.com
https://paypal-login-reset.ru
http://192.168.1.11/login/bank
```

Run the analyzer:

```bash
python analyzer.py
```


### ✔️ Example Output

```
=== Checking URL: https://paypal-login-reset.ru ===

[Static Analysis]
Score: 4
 - Suspicious TLD: ru
 - Contains keyword: login
 - Contains keyword: paypal
 - Contains keyword: reset

[VirusTotal]
Malicious: 2
Suspicious: 1
Harmless: 0

[PhishTank]
In Database: True
Valid Phishing: True
Verified: True

[AbuseIPDB]
No data

Recommendation:
⚠️ HIGH RISK — Block & escalate to SOC
```


## 🧭 Detection Logic

Risk scoring is based on:

### 1. Static Analysis
- Suspicious TLDs  
- IP-based URLs  
- Known phishing keywords  

### 2. VirusTotal
- Malicious / suspicious engines  

### 3. PhishTank
- Verified phishing database  

### 4. AbuseIPDB
- Confidence score > 50 triggers risk


## 🔮 Future Roadmap

Planned additions:

- URLhaus intelligence integration  
- AbuseIPDB domain analysis  
- Suspicious redirect detection  
- WHOIS checks for fresh domains  
- Machine learning scoring  
- Proxy support  
- JSON export for SIEM  
- Docker containerization  


## ⚠ Legal Disclaimer

This tool is provided for educational and defensive security purposes only.
It is intended to support SOC analysts, cybersecurity students, threat
researchers and blue team operations in identifying potentially malicious
or phishing URLs.

The author does not take any responsibility or liability for any misuse,
illegal activity, damage, loss or consequences resulting from the use of
this tool. Running this tool against systems, networks, individuals or
targets without explicit written authorization may be illegal and is
strictly prohibited.

By using this tool, you agree that any actions you perform are at your
own risk, and the author assumes no responsibility for any outcomes
or consequences.


## 📝 License

This project is licensed under the MIT License.
See the LICENSE file for details.