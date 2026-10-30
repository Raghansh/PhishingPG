<div align="center">

  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=1,2,7,12&height=180&section=header&text=PhishingPG&fontSize=42&fontColor=ffffff&desc=%F0%9F%9B%A1%EF%B8%8F+Heuristic+Phishing+URL+Detector+%26+Security+Research&descAlignY=62&descAlign=50" width="100%" alt="PhishingPG Header" />

  <p align="center">
    <img src="https://img.shields.io/badge/Language-Python_3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/Field-Cybersecurity-1F2430?style=for-the-badge&logo=shield&logoColor=7aa2f7" alt="Cybersecurity" />
    <img src="https://img.shields.io/badge/Audience-Ethical_Hackers-000000?style=for-the-badge&logo=hackthebox&logoColor=99CC00" alt="Ethical Hackers" />
    <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT License" />
  </p>

</div>

---

## 📌 Overview

**PhishingPG** is an educational cybersecurity tool designed to analyze URLs and domains for suspicious phishing heuristics, credential harvesting indicators, homoglyph attacks, and evasion techniques.

Developed for security researchers, penetration testers, and community security awareness, this utility breaks down domain structure and quantifies risk scoring against real-world threat indicators.

---

## ⚡ Key Features

- 🔍 **Homograph / Punycode Detection**: Identifies internationalized domain name (IDN) spoofing (`xn--`).
- 🎯 **Targeted Brand Spoofing Check**: Detects unauthorized corporate and banking brand strings embedded inside subdomains or fake paths.
- 📐 **Shannon Entropy Scoring**: Analyzes character randomness in domain labels to flag Domain Generation Algorithms (DGAs).
- 🌐 **IP Hostname & Port Anomalies**: Catches direct IP address requests designed to bypass DNS reputation feeds.
- 🔗 **Shortener & Obfuscation Detection**: Flags common URL shortening services that mask final redirect targets.
- 📊 **Dynamic Risk Verdict**: Produces a structured report categorized from *BENIGN* to *CRITICAL*.

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/Raghansh/PhishingPG.git
cd PhishingPG
```

### 2. Run the Detector
```bash
# Analyze a direct URL:
python phishing_detector.py "http://paypal-verification.secure-update.xyz/login"

# Or run interactively:
python phishing_detector.py
```

### 3. Example Output
```text
=================================================================
 🛡️  PhishingPG - URL Heuristic Risk Analyzer
 Developed by Raghansh Gulati (@Raghansh)
=================================================================

[+] Target URL:   http://paypal-verification.secure-update.xyz/login
[+] Target Host:  paypal-verification.secure-update.xyz
[+] Risk Score:   85 / 100
[+] Verdict:      CRITICAL / HIGH RISK

[+] Detailed Heuristic Findings:
    - ⚠️ Insecure Protocol: Plain HTTP instead of HTTPS (+15)
    - 🚨 Brand Spoofing: 'paypal' keyword in subdomain/domain prefix (+35)
    - ⚠️ High-Risk TLD: '.xyz' is frequently abused in phishing campaigns (+15)
    - ⚠️ Excessive Subdomains (3 parts): Common in domain spoofing (+20)

=================================================================
```

---

## ⚖️ Legal & Ethical Disclaimer

> [!IMPORTANT]
> This tool is developed strictly for **educational purposes**, **defensive research**, and **security awareness training**. Use it responsibly to safeguard digital assets and understand attack vectors.

---

## 👨‍💻 Author

- **Raghansh Gulati** ([@Raghansh](https://github.com/Raghansh))
- Ethical Hacker, Linux Enthusiast & Full-Stack Developer
