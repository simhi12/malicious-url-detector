import re
import json
import requests
from urllib.parse import urlparse
from config import API_KEY, ABUSEIPDB_KEY


# ===== Static Analysis =====

SUSPICIOUS_TLDS = ["xyz", "top", "gq", "tk", "ru"]
PHISHING_KEYWORDS = ["login", "paypal", "reset", "bank", "verify", "signin", "account"]

def static_analysis(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    score = 0
    reasons = []

    # Check if using IP instead of domain
    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 2
        reasons.append("URL uses IP address")

    # Suspicious extension (TLD)
    tld = domain.split(".")[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        score += 1
        reasons.append(f"Suspicious TLD: {tld}")

    # Keywords used in phishing
    for kw in PHISHING_KEYWORDS:
        if kw in url.lower():
            score += 1
            reasons.append(f"Contains phishing keyword: '{kw}'")

    return score, reasons


# ===== VirusTotal =====

def check_virustotal(url):
    headers = {"x-apikey": API_KEY}
    data = {"url": url}

    res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)

    if res.status_code != 200:
        return None

    url_id = res.json()["data"]["id"]
    res2 = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=headers)

    if res2.status_code != 200:
        return None

    return res2.json()["data"]["attributes"]["stats"]


# ===== PhishTank =====

def check_phishtank(url):
    try:
        data = {
            'format': 'json',
            'url': url
        }
        res = requests.post("https://checkurl.phishtank.com/checkurl/", data=data)
        if res.status_code != 200:
            return None

        result = json.loads(res.text)
        verified = result['results']['verified']
        valid = result['results']['valid']
        in_database = result['results']['in_database']

        return {
            "in_database": in_database,
            "valid": valid,
            "verified": verified
        }
    except:
        return None


# ===== AbuseIPDB =====

def check_abuseipdb(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check"
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        headers = {
            'Key': ABUSEIPDB_KEY,
            'Accept': 'application/json'
        }
        res = requests.get(url, headers=headers, params=params)

        if res.status_code != 200:
            return None

        data = res.json()['data']
        return {
            "score": data['abuseConfidenceScore'],
            "reports": data['totalReports'],
            "last_report": data['lastReportedAt']
        }
    except:
        return None



# ===== Main Analysis =====

def analyze_url(url):
    print(f"\n=== Checking URL: {url} ===")

    # Static
    score, reasons = static_analysis(url)
    print("\n[Static Analysis]")
    print(f"Score: {score}")
    for r in reasons:
        print(f" - {r}")

    # VirusTotal
    vt_stats = check_virustotal(url)
    print("\n[VirusTotal]")
    if vt_stats:
        print(f"Malicious: {vt_stats['malicious']}")
        print(f"Suspicious: {vt_stats['suspicious']}")
        print(f"Harmless: {vt_stats['harmless']}")
    else:
        print("No data or API limit")

    # PhishTank
    ps = check_phishtank(url)
    print("\n[PhishTank]")
    if ps:
        print(f"In Database: {ps['in_database']}")
        print(f"Valid Phishing: {ps['valid']}")
        print(f"Verified: {ps['verified']}")
    else:
        print("No PhishTank data")

    # AbuseIPDB
    parsed = urlparse(url)
    domain = parsed.netloc
    is_ip = re.match(r"\d+\.\d+\.\d+\.\d+", domain)

    ip_data = None
    if is_ip:
        ip_data = check_abuseipdb(domain)

    print("\n[AbuseIPDB]")
    if ip_data:
        print(f"Abuse Score: {ip_data['score']}")
        print(f"Total Reports: {ip_data['reports']}")
        print(f"Last Report: {ip_data['last_report']}")
    else:
        print("No AbuseIPDB data")

    # ===== Decision Logic =====
    high = False

    if score > 2:
        high = True

    if vt_stats and vt_stats['malicious'] > 0:
        high = True

    if ps and ps['valid'] == True:
        high = True

    if ip_data and ip_data['score'] > 50:
        high = True

    print("\nRecommendation:")
    if high:
        print("⚠️ HIGH RISK — block and alert SOC")
    else:
        print("✔ LOW RISK — looks safe")


if __name__ == "__main__":
    with open("urls.txt", "r") as f:
        urls = f.read().splitlines()

    for url in urls:
        analyze_url(url)
