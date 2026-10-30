#!/usr/bin/env python3
"""
PhishingPG - Phishing Detection & URL Risk Assessment Tool
Author: Raghansh Gulati (@Raghansh)
License: MIT
Description:
    An educational cybersecurity tool that evaluates URLs for common phishing
    vectors, suspicious heuristics, homoglyphs, and spoofing indicators.
"""

import sys
import math
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "loan", "click", "racing", "date",
    "men", "stream", "live", "gq", "cf", "ml", "ga", "tk"
}

TARGET_BRANDS = [
    "paypal", "netflix", "apple", "google", "microsoft", "amazon",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "steam", "discord", "binance", "coinbase", "github", "twitter"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "goo.gl", "tiny.cc"
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy to identify randomly generated domain strings."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def analyze_url(url: str) -> dict:
    """Analyze a given URL for common phishing heuristics."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    findings = []
    risk_score = 0  # Max ~ 100

    # 1. Scheme Check
    if parsed.scheme == "http":
        findings.append("⚠️ Insecure Protocol: Plain HTTP instead of HTTPS (+15)")
        risk_score += 15

    # 2. IP Address as Hostname
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, hostname):
        findings.append("🚨 Direct IP Hostname: Bypasses DNS domain reputation (+30)")
        risk_score += 30

    # 3. Known URL Shortener
    if hostname.lower() in SHORTENER_DOMAINS:
        findings.append("ℹ️ URL Shortener Detected: Hides true landing destination (+15)")
        risk_score += 15

    # 4. Punycode / Homograph Attack (IDN)
    if "xn--" in hostname:
        findings.append("🚨 Punycode (IDN) Detected: Possible homoglyph character spoofing (+35)")
        risk_score += 35

    # 5. Excessive Subdomains
    subdomain_parts = hostname.split(".")
    if len(subdomain_parts) > 3:
        findings.append(f"⚠️ Excessive Subdomains ({len(subdomain_parts)} parts): Common in domain spoofing (+20)")
        risk_score += 20

    # 6. Brand Spoofing in Subdomains / Paths
    for brand in TARGET_BRANDS:
        if brand in hostname.lower():
            # Check if brand is not the primary domain (e.g., paypal.com vs paypal.secure-login.com)
            parts = hostname.lower().split(".")
            if len(parts) >= 2 and parts[-2] != brand:
                findings.append(f"🚨 Brand Spoofing: '{brand}' keyword in subdomain/domain prefix (+35)")
                risk_score += 35
                break
        elif brand in path.lower() or brand in query.lower():
            findings.append(f"⚠️ Targeted Brand Mention: '{brand}' referenced in path/query (+15)")
            risk_score += 15
            break

    # 7. Suspicious TLD
    tld = hostname.split(".")[-1].lower() if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(f"⚠️ High-Risk TLD: '.{tld}' is frequently abused in phishing campaigns (+15)")
        risk_score += 15

    # 8. High Entropy (Domain Randomness)
    domain_body = parts[0] if parts else hostname
    entropy = calculate_entropy(domain_body)
    if entropy > 4.2 and len(domain_body) > 10:
        findings.append(f"⚠️ High Character Entropy ({entropy:.2f}): Likely randomly generated DGA domain (+20)")
        risk_score += 20

    # 9. At symbol in URL
    if "@" in url:
        findings.append("🚨 '@' Symbol in URL: Misleads user to ignore actual destination host (+35)")
        risk_score += 35

    # 10. Hyphen count
    if hostname.count("-") >= 3:
        findings.append("⚠️ Excessive Hyphens: Multiple hyphens commonly used to impersonate legitimate domains (+15)")
        risk_score += 15

    # Cap risk score
    risk_score = min(risk_score, 100)

    # Risk level classification
    if risk_score >= 60:
        risk_level = "CRITICAL / HIGH RISK"
    elif risk_score >= 30:
        risk_level = "MEDIUM RISK"
    elif risk_score > 0:
        risk_level = "LOW RISK"
    else:
        risk_level = "BENIGN / CLEAN"

    return {
        "url": url,
        "hostname": hostname,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings or ["No immediate heuristics flags triggered."]
    }


def main():
    print("=" * 65)
    print(" 🛡️  PhishingPG - URL Heuristic Risk Analyzer")
    print(" Developed by Raghansh Gulati (@Raghansh)")
    print("=" * 65)

    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("\nEnter URL to analyze: ").strip()

    if not target_url:
        print("[-] Error: No URL provided.")
        sys.exit(1)

    result = analyze_url(target_url)

    print(f"\n[+] Target URL:   {result['url']}")
    print(f"[+] Target Host:  {result['hostname']}")
    print(f"[+] Risk Score:   {result['risk_score']} / 100")
    print(f"[+] Verdict:      {result['risk_level']}")
    print("\n[+] Detailed Heuristic Findings:")
    for f in result["findings"]:
        print(f"    - {f}")
    print("\n" + "=" * 65)


if __name__ == "__main__":
    main()
