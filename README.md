#  HSR Advanced v2.0

### AI-Powered Web Security Testing Framework

> ⚡ Advanced automated vulnerability scanner with AI integration, WAF bypassing, and deep security analysis.

---

## 📌 Overview

**HSR Advanced v4.0** is a powerful web application security testing framework designed for penetration testers, bug bounty hunters, and cybersecurity professionals.

It combines:

* 🔍 Automated vulnerability scanning
* 🤖 AI-powered payload generation (Ollama / OpenAI)
* 🛡️ WAF detection & bypass techniques
* 📊 CVSS scoring & reporting
* ⚙️ Multi-threaded high-speed scanning

---

## 🚀 Features

### 🔎 Core Scanning

* XSS (Reflected, Stored, DOM)
* SQL Injection (Error, Blind, Time-based)
* Command Injection
* LFI / Path Traversal
* SSRF
* XXE
* SSTI
* NoSQL Injection
* Open Redirect

---

### 🤖 AI Integration

* Local AI using **Ollama (offline)**
* Cloud AI support (OpenAI API)
* Smart payload generation
* Response analysis using AI

---

### 🛡️ Advanced Detection

* WAF Detection (Cloudflare, AWS, Akamai, etc.)
* WAF bypass payload mutation
* ML-based anomaly detection (Z-score)
* Baseline response comparison
* Pattern-based detection engine

---

### 🔐 API & Modern Web Testing

* API endpoint discovery
* GraphQL security testing
* JWT token analysis & attacks
* IDOR vulnerability detection

---

### 📊 Reporting

* Multiple output formats:

  * TXT
  * JSON
  * HTML
  * PDF
  * SARIF

---

## ⚙️ Installation

```bash
git clone https://github.com/your-username/hsr-advanced.git
cd hsr-advanced
pip install -r requirements.txt
```

---

## 📦 Requirements

* Python 3.8+
* Required libraries:

  ```
  requests
  beautifulsoup4
  colorama
  numpy
  aiohttp
  pyyaml
  fpdf
  ```

---

## 🤖 AI Setup (Optional)

### 🧠 Local AI (Recommended)

Install Ollama:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama run phi
```

### ☁️ OpenAI

Set API key:

```bash
export HSR_AI_API_KEY=your_api_key
```

---

## ▶️ Usage

```bash
python a5.py -u https://target.com
```

### Example:

```bash
python a5.py --url https://example.com --threads 20
```

---

## 📁 Configuration

Edit config file:

```
hsr_config.yaml
```

Customize:

* Threads
* Scan depth
* Rate limit
* AI provider
* Detection settings

---

## 🛡️ Scope Control

Define allowed domains in:

```
scope.txt
```

Example:

```
example.com
api.example.com
```

---

## 📊 Output Example

```json
{
  "type": "xss",
  "parameter": "search",
  "payload": "<script>alert(1)</script>",
  "severity": "High",
  "cvss_score": 8.2
}
```

---

## ⚠️ Legal Disclaimer

> 🚨 This tool is for **educational and authorized security testing only**.

* Do NOT scan systems without permission
* Unauthorized testing is illegal
* Developer is NOT responsible for misuse

---

## 🧠 Future Improvements

* 🔥 Full automation pipeline
* 📡 OSINT integration
* 🧬 AI self-learning engine
* 🛠️ Burp Suite integration
* 🌐 Dashboard UI

---

## 👨‍💻 Author

**HSR (Harsh Singh Rao)**
Cybersecurity Enthusiast | Pentester | SOC Analyst

---

## ⭐ Support

If you like this project:

* ⭐ Star the repo
* 🍴 Fork it
* 🧠 Contribute

---

## 💡 Inspiration

Built with passion for:

* Cybersecurity
* Bug bounty hunting
* AI + Offensive Security

---

## Result:
<img width="1024" height="768" alt="Screenshot From 2026-03-24 21-10-12" src="https://github.com/user-attachments/assets/9c678fda-dcdb-42cc-be07-21e3eec40603" />

---

<img width="1024" height="768" alt="Screenshot From 2026-03-24 21-30-01" src="https://github.com/user-attachments/assets/14a75b27-3532-48dd-94b2-189ce54e23db" />

---

<img width="660" height="319" alt="Screenshot From 2026-03-24 22-01-24" src="https://github.com/user-attachments/assets/b86adb66-5325-4061-9cc8-5797899c1726" />


---

<img width="660" height="319" alt="Screenshot From 2026-03-24 22-01-33" src="https://github.com/user-attachments/assets/8ae08c7e-7276-4231-ad90-9ad3480ab84f" />

---
