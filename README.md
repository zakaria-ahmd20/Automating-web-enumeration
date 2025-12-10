# 🕵️ Passive Web Enumeration Framework (Python)

### Author: Zakaria  
**Version:** 1.0  
**License:** MIT  
**Status:** Under Development  

---

## 📘 Overview
This project is a **passive web reconnaissance framework** written in Python.  
It collects **publicly available information** about a target domain without sending intrusive or exploitative requests.

The script helps cybersecurity professionals and learners practice **passive information gathering** and **digital footprint analysis** safely and legally.

All outputs are saved to:
- `report.txt` — full logs from each command and HTTP check  
- `report.json` — clean structured summary of the findings  

---

## ⚙️ Features

| Feature | Description |
|----------|--------------|
| 🌐 **DNS & IP Resolution** | Gathers A, MX, TXT, and NS records |
| 🤖 **robots.txt / sitemap.xml Detection** | Detects if search engine control files exist |
| 🧩 **Technology Fingerprinting** | Identifies frameworks, CMS, and server types using WhatWeb |
| 🔥 **WAF & Cloudflare Detection** | Detects common Web Application Firewalls via headers and wafw00f |
| 🔑 **SSL & Certificate Info** | Parses SSL certificate details using OpenSSL |
| 🧾 **WHOIS Summary** | Collects registrar, expiry, and contact data |
| 🕸️ **Subdomain Discovery** | Uses passive subdomain enumeration tools |
| 📰 **WordPress Detection (Smart)** | Heuristic detection using HTML, headers, and known WP endpoints |
| 🧠 **Final Summary Report** | Prints a clean summary and saves detailed logs to disk |

---

## 🧩 Example Usage

```bash
python3 web_enum.py
