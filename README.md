# Cyber Recon & Threat Intelligence Automation Suite

A professional, modular reconnaissance and threat intelligence automation toolkit built for enterprise-grade penetration testing, red teaming, and government-level cybersecurity operations. This suite automates reconnaissance, vulnerability discovery, and intelligence enrichment using modern industry standards and compliance frameworks like MITRE ATT&CK, OWASP, and NIST 800-53.

---

##  Key Features

- Automated DNS & IP Intelligence
- ASN / Netblock Enumeration (Netblock, ASN, Organization Data)
- Parallel Subdomain Enumeration (Passive, Brute-force, Permutations)
- Comprehensive Port Scanning (TCP/UDP)
- HTTP Security Headers & TLS Certificate Analysis
- Web Application Fingerprinting & WAF Detection
- Hidden Paths, Parameters, API Keys, Headers Fuzzing (FFUF)
- Integrated Shodan, VirusTotal, ThreatFox, AlienVault OTX APIs
- Archived URLs Retrieval & Visual Recon (Screenshots)
- Auto-generated HTML Reports (Compliance Mapped)
- Parallel Execution Engine for High-Speed Scanning

---

## ⚙ Setup & Installation

```bash
git clone https://github.com/muhammadateeeb/cyber-recon-suite.git
cd cyber-recon-suite

# Set permanent API keys in ~/.bashrc or ~/.zshrc:
echo 'export SHODAN_API_KEY="YOUR_SHODAN_API_KEY"' >> ~/.bashrc
echo 'export VT_API_KEY="YOUR_VT_API_KEY"' >> ~/.bashrc
source ~/.bashrc

chmod +x scan.sh
./scan.sh target.com
```

Required Dependencies:

    bash, curl, jq, nmap, amass, assetfinder, subfinder, httpx, dnsx

    asnmap, puredns or shuffledns

    nuclei, ffuf, aquatone

 Reporting & Output

    Structured HTML Report with:

        Technical Findings Summary

        Screenshots of Discovered Interfaces

        Vulnerability Intelligence Summary

        MITRE, OWASP, NIST Compliance Mapping

Output directory:

reports/
└── target.com/
    ├── report_TIMESTAMP.html
    ├── subdomains.txt
    ├── asn_info.txt
    ├── shodan.txt
    ├── nuclei_output.txt
    ├── aquatone/screenshots/

- Compliance Mapping
Module	Standard / Framework
TLS Certificate Analysis	NIST 800-53 SC-12, SC-17
HTTP Security Headers	OWASP A06:2021, MITRE T1595.002
Subdomain Enumeration	OWASP A06:2021, NIST CM-8
WAF Detection	NIST SI-4, MITRE T1555
Archived URL Discovery	OWASP A06:2021
Threat Intelligence APIs	MITRE ATT&CK T1595
- Primary Use Cases

    Corporate Red Team Operations

    Military/Defense Reconnaissance Projects

    Enterprise Penetration Testing

    OSINT-Driven Vulnerability Assessments

    Cyber Threat Intelligence Automation

 Repository Structure

cyber-recon-suite/
 ├── scan.sh
 ├── README.md
 ├── LICENSE
 └── reports/
      └── target.com/
           ├── asn_info.txt
           ├── subdomains.txt
           ├── shodan.txt
           ├── headers.txt
           ├── nuclei_output.txt
           ├── aquatone/screenshots/
           └── report_TIMESTAMP.html
- Disclaimer
This toolkit is developed strictly for authorized penetration testing, red teaming, and academic research. Unauthorized use against systems without explicit consent is prohibited and may violate local, national, or international regulations.
