#!/usr/bin/env python3
"""
Clean passive web enumeration runner.
- Writes full raw outputs to report.txt
- Saves structured results to report.json
- Prints concise progress + final summary
- Uses stricter WP detection to reduce false positives
"""

import subprocess
import requests
import socket
import ssl
import re
import json
from datetime import datetime

REPORT_TXT = "report.txt"
REPORT_JSON = "report.json"
UA = {"User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"}

# ---------------- helpers ----------------

def append_report(text):
    with open(REPORT_TXT, "a", encoding="utf-8") as f:
        f.write(text + "\n")

def run_cmd(cmd, timeout=30):
    append_report(f"$ {cmd}")
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, timeout=timeout)
        out = proc.stdout or ""
        append_report(out)
        return out
    except Exception as e:
        err = f"ERROR running `{cmd}`: {e}"
        append_report(err)
        return ""

def http_get(url, timeout=6):
    try:
        r = requests.get(url, headers=UA, timeout=timeout, allow_redirects=True)
        snippet = r.text[:4000]  # limit amount written to txt
        append_report(f"GET {url} - {r.status_code}\n{snippet}")
        return r
    except Exception as e:
        append_report(f"GET {url} - ERROR: {e}")
        return None

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        s.settimeout(5)
        s.connect((domain, 443))
        cert = s.getpeercert()
        append_report(f"SSL cert raw: {cert}")
        return {
            "issuer": cert.get("issuer"),
            "subject": cert.get("subject"),
            "valid_from": cert.get("notBefore"),
            "valid_to": cert.get("notAfter")
        }
    except Exception as e:
        append_report(f"SSL error: {e}")
        return {}

def extract_first_values(whois_text, field_names):
    out = {}
    for field in field_names:
        m = re.findall(rf"^{re.escape(field)}:\s*(.+)$", whois_text, flags=re.I | re.M)
        if m:
            out[field] = list(dict.fromkeys([x.strip() for x in m]))  # unique
    return out

# ---------------- main flow ----------------

def detect_wordpress(domain):
    """
    Stricter WP detection:
    - Score signals (each +1):
      * wp-content/wp-includes/wp-json in homepage HTML
      * /wp-login.php returns 200
      * /wp-admin returns 200
      * X-Powered-By or Server header contains 'wordpress'
      * common WP JSON endpoint /wp-json returns 200 or contains 'wp'
    - Mark detected True if score >= 2 (configurable)
    Returns boolean and score (but this script will only display boolean + confidence)
    """
    score = 0
    max_score = 5
    headers = UA

    # 1) homepage HTML check
    r = None
    try:
        r = requests.get(f"https://{domain}", headers=headers, timeout=6, allow_redirects=True)
    except:
        try:
            r = requests.get(f"http://{domain}", headers=headers, timeout=6, allow_redirects=True)
        except:
            r = None

    html = (r.text.lower() if r and r.text else "")
    if any(x in html for x in ("wp-content", "wp-includes", "wp-json")):
        score += 1

    # 2) wp-login
    try:
        r2 = requests.get(f"https://{domain}/wp-login.php", headers=headers, timeout=6, allow_redirects=True)
        if r2.status_code == 200:
            score += 1
    except:
        pass

    # 3) wp-admin
    try:
        r3 = requests.get(f"https://{domain}/wp-admin", headers=headers, timeout=6, allow_redirects=True)
        if r3.status_code == 200:
            score += 1
    except:
        pass

    # 4) headers
    try:
        head = requests.get(f"https://{domain}", headers=headers, timeout=6, allow_redirects=True)
        header_values = " ".join([str(v).lower() for v in head.headers.values() if v])
        if "wordpress" in header_values:
            score += 1
    except:
        pass

    # 5) /wp-json endpoint
    try:
        r4 = requests.get(f"https://{domain}/wp-json/", headers=headers, timeout=6, allow_redirects=True)
        if r4.status_code == 200 and ("wp" in (r4.text[:100].lower() or "")):
            score += 1
    except:
        pass

    detected = score >= 2  # require at least two independent signals
    return detected, score, max_score

def parse_waf_from_wafw00f(output):
    out = {"detected": False, "name": None}
    txt = (output or "").lower()
    if "is behind" in txt:
        out["detected"] = True
        m = re.search(r"is behind ([\w\s\-]+)", txt, flags=re.I)
        if m:
            out["name"] = m.group(1).strip()
    # fallback: search for known waf names in output
    for w in ("cloudflare", "sucuri", "f5", "imperva", "akamai", "fastly"):
        if w in txt:
            out["detected"] = True
            out["name"] = out["name"] or w.capitalize()
    return out

def main():
    print("Passive enumeration starting (silent raw capture -> report.txt).")
    domain = input("Enter target domain: ").strip()

    # initialize reports
    append_report("\n" + "="*80)
    append_report(f"Scan target: {domain}  Time: {datetime.utcnow().isoformat()}Z")
    append_report("="*80)

    results = {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ips": [],
        "dns": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []},
        "waf": {"detected": False, "name": None},
        "cloudflare": False,
        "wordpress": {"detected": False, "confidence": 0, "max_confidence": 0},
        "robots": False,
        "sitemap": False,
        "ssl": {},
        "server_header": None,
        "whatweb": [],
        "whois": {},
        "subdomains_count": 0
    }

    # Stage: DNS / host
    print("[+] Running DNS / host checks...")
    host_out = run_cmd(f"host {domain}")
    for line in host_out.splitlines():
        if "has address" in line:
            ip = line.split("has address")[-1].strip()
            results["ips"].append(ip)

    dig_any = run_cmd(f"dig {domain} ANY +short")
    for line in dig_any.splitlines():
        line = line.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
            results["dns"]["A"].append(line)
        elif ":" in line:
            results["dns"]["AAAA"].append(line)

    results["dns"]["MX"] = [l.strip() for l in run_cmd(f"dig {domain} MX +short").splitlines() if l.strip()]
    results["dns"]["NS"]  = [l.strip() for l in run_cmd(f"dig {domain} NS +short").splitlines() if l.strip()]
    results["dns"]["TXT"] = [l.strip() for l in run_cmd(f"dig {domain} TXT +short").splitlines() if l.strip()]

    # Stage: robots + sitemap
    print("[+] Checking robots.txt and sitemap.xml...")
    rrobots = http_get(f"https://{domain}/robots.txt") or http_get(f"http://{domain}/robots.txt")
    results["robots"] = bool(rrobots and rrobots.status_code == 200)

    rsitemap = http_get(f"https://{domain}/sitemap.xml") or http_get(f"http://{domain}/sitemap.xml")
    results["sitemap"] = bool(rsitemap and rsitemap.status_code == 200)

    # Stage: whatweb
    print("[+] Fingerprinting technologies (whatweb)...")
    whatweb_out = run_cmd(f"whatweb {domain}")
    results["whatweb"] = [l.strip() for l in whatweb_out.splitlines() if l.strip()][:50]

    # Stage: waf detection
    print("[+] Detecting WAF (wafw00f)...")
    waf_out = run_cmd(f"wafw00f -a {domain}")
    waf_info = parse_waf_from_wafw00f(waf_out)
    results["waf"] = waf_info

    # Stage: header-based Cloudflare detection
    print("[+] Checking headers for Cloudflare & server info...")
    try:
        rhead = requests.get(f"https://{domain}", headers=UA, timeout=6, allow_redirects=True)
        append_report(f"HEADERS: {rhead.headers}")
        server_hdr = rhead.headers.get("server", "")
        results["server_header"] = server_hdr
        if "cloudflare" in server_hdr.lower() or any("cloudflare" in str(v).lower() for v in rhead.headers.values()):
            results["cloudflare"] = True
    except Exception as e:
        append_report(f"Header fetch error: {e}")

    # Stage: WHOIS
    print("[+] Collecting WHOIS...")
    whois_out = run_cmd(f"whois {domain}")
    results["whois"] = extract_first_values(whois_out, ["Registrar", "Creation Date", "Registry Expiry Date", "Name Server"])

    # Stage: SSL
    print("[+] Fetching SSL certificate details...")
    results["ssl"] = get_ssl_info(domain)

    # Stage: WordPress detection (stricter)
    print("[+] Performing WordPress detection (stricter, fewer false positives)...")
    detected, score, max_score = detect_wordpress(domain)
    results["wordpress"]["detected"] = bool(detected)
    results["wordpress"]["confidence"] = int(score)
    results["wordpress"]["max_confidence"] = int(max_score)

    # Stage: Subdomains enumeration (silent)
    print("[+] Enumerating subdomains silently (sublist3r/dnsrecon/theHarvester)...")
    s1 = run_cmd(f"sublist3r -d {domain}")
    s2 = run_cmd(f"dnsrecon -d {domain}")
    s3 = run_cmd(f"theHarvester -d {domain} -b crtsh,urlscan,otx,bing")
    combined = "\n".join([s1, s2, s3])
    subs = set(re.findall(rf"([a-zA-Z0-9\-_\.]+\.{re.escape(domain)})", combined))
    results["subdomains_count"] = len(subs)

    # Save structured JSON
    with open(REPORT_JSON, "w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=2)

    # Append a concise summary to report.txt
    summary_lines = [
        "\n" + "="*70,
        f"SUMMARY — {domain}",
        "="*70,
        f"Resolved IPs: {results['ips'] or results['dns']['A']}",
        f"DNS A: {results['dns']['A']}",
        f"DNS AAAA: {results['dns']['AAAA']}",
        f"MX: {results['dns']['MX']}",
        f"NS: {results['dns']['NS']}",
        f"TXT: {results['dns']['TXT']}",
        f"robots.txt present: {results['robots']}",
        f"sitemap.xml present: {results['sitemap']}",
        f"WAF detected: {results['waf']['detected']}  name: {results['waf']['name']}",
        f"Cloudflare (header): {results['cloudflare']}",
        f"Server header: {results.get('server_header')}",
        f"WordPress detected: {results['wordpress']['detected']}  (confidence {results['wordpress']['confidence']}/{results['wordpress']['max_confidence']})",
        f"SSL valid_from: {results['ssl'].get('valid_from')}  valid_to: {results['ssl'].get('valid_to')}",
        f"Whois (Registrar): {results['whois'].get('Registrar')}",
        f"Technologies (whatweb sample): {results['whatweb'][:6]}",
        f"Subdomains found: {results['subdomains_count']}",
        "="*70
    ]
    for line in summary_lines:
        append_report(line)

    # Print final summary to user (clean)
    print("\n" + "="*60)
    print(f"PASSIVE ENUMERATION SUMMARY — {domain}")
    print("="*60)
    print(f"Resolved IPs: {results['ips'] or results['dns']['A']}")
    print(f"robots.txt present: {results['robots']}")
    print(f"sitemap.xml present: {results['sitemap']}")
    print(f"WAF detected: {results['waf']['detected']}  name: {results['waf']['name']}")
    print(f"Cloudflare (header): {results['cloudflare']}")
    print(f"Server header: {results.get('server_header')}")
    print(f"WordPress detected: {results['wordpress']['detected']}  (confidence {results['wordpress']['confidence']}/{results['wordpress']['max_confidence']})")
    print(f"SSL valid_from: {results['ssl'].get('valid_from')}  valid_to: {results['ssl'].get('valid_to')}")
    print(f"Whois (Registrar): {results['whois'].get('Registrar')}")
    print(f"Top tech (whatweb sample): {results['whatweb'][:6]}")
    print(f"Subdomains found: {results['subdomains_count']}")
    print("="*60)
    print(f"Full raw outputs: {REPORT_TXT}")
    print(f"Structured JSON: {REPORT_JSON}")
    print("="*60)

if __name__ == "__main__":
    main()
