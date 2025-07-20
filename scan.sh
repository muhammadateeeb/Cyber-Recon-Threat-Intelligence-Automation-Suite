#!/bin/bash
# PAF-Grade Recon Script – 2025 by Muhammad Ateeb + ChatGPT

set -uo pipefail
trap 'echo -e "\n[!] Error on line $LINENO for target $target"; exit 1' ERR


RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; CYAN='\e[36m'; NC='\e[0m'

# Input & Setup
if [[ -z "${1:-}" ]]; then echo -e "${RED}[!] Usage: $0 <target>${NC}"; exit 1; fi
target="$1"
timestamp=$(date +%F_%H-%M-%S)
report_dir="reports/$target"
mkdir -p "$report_dir/screenshots"
log_file="$report_dir/recon_$timestamp.log"
resolved_file="$report_dir/resolved_subdomains_$target.txt"
if [[ -f ".env" ]]; then
  export $(grep -v '^#' .env | xargs)
fi
exec > >(tee -a "$log_file") 2>&1
log() { echo -e "$1"; }

# ============================
#         FUNCTIONS
# ============================

check_tools() {
  log "\n${CYAN}✅ Checking tools...${NC}"
  for tool in subfinder httpx whois dig curl jq naabu waybackurls gau aquatone openssl; do
    if ! command -v "$tool" &>/dev/null; then
      echo -e "${RED}[!] Required tool missing: $tool${NC}"; exit 1
    fi
  done
  log "${GREEN}✅ All required tools are installed.${NC}"
}

is_alive() {
  ping -c 1 "$target" &>/dev/null
}

dns_info() {
  log "\n${CYAN}========== DNS Information ==========${NC}"
  {
    echo "📡 Host Info:"; timeout 10 host "$target" || echo "host failed"
    echo -e "\n📄 WHOIS Info:"; timeout 10 whois "$target" | head -n 20 || echo "whois failed"
    echo -e "\n📜 DIG Info:"; timeout 10 dig "$target" any +short || echo "dig failed"
  } > "$report_dir/dns.txt"
  cat "$report_dir/dns.txt"
}

scan_ports() {
  log "\n${CYAN}========== Port Scan ==========${NC}"
  naabu -host "$target" -silent -top-ports 100 > "$report_dir/ports.txt" || echo "naabu failed" > "$report_dir/ports.txt"
  cat "$report_dir/ports.txt"
}

get_headers() {
  log "\n${CYAN}========== HTTP Headers ==========${NC}"
  > "$report_dir/headers.txt"
  for proto in http https; do
    echo "-- $proto://$target --" >> "$report_dir/headers.txt"
    curl -sI --connect-timeout 5 "$proto://$target" >> "$report_dir/headers.txt" || echo "No response" >> "$report_dir/headers.txt"
  done
  cat "$report_dir/headers.txt"
}

enumerate_subdomains() {
  log "\n${CYAN}========== Subdomain Enumeration (Deep) ==========${NC}"
  passive="$report_dir/passive_subs.txt"
  brute="$report_dir/brute_subs.txt"
  perms="$report_dir/permutations.txt"
  all="$report_dir/all_subdomains.txt"

  mkdir -p "$(dirname "$passive")"
  touch "$passive" "$brute" "$perms"

  # --- Passive enumeration ---
  {
    subfinder -d "$target" -silent 2>/dev/null || true
    assetfinder --subs-only "$target" 2>/dev/null || true
    amass enum -passive -d "$target" 2>/dev/null || true
  } | sort -u > "$passive"
  log "🔍 Passive found: $(wc -l < "$passive")"

  # --- Brute-force enumeration ---
  wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  resolvers="$report_dir/resolvers.txt"
  echo -e "1.1.1.1\n8.8.8.8" > "$resolvers"

  if command -v puredns &>/dev/null && [[ -f "$wordlist" ]]; then
    log "🧨 Brute-forcing with puredns..."
    timeout 60s puredns bruteforce "$wordlist" "$target" \
      --resolvers "$resolvers" --write "$brute" 2>/dev/null || echo "⚠️ Puredns timeout or failed"
  elif command -v shuffledns &>/dev/null && [[ -f "$wordlist" ]]; then
    log "🧨 Brute-forcing with shuffledns..."
    shuffledns -d "$target" \
      -w "$wordlist" \
      -r "$resolvers" \
      -o "$brute" 2>/dev/null || echo "⚠️ Shuffledns failed"
  else
    log "⚠️ Brute-force tool or wordlist missing. Skipping."
  fi
  log "🔓 Brute-force found: $(wc -l < "$brute")"

  # --- Permutation Generation ---
  # Permutation Generation
if command -v dnsgen &>/dev/null && command -v massdns &>/dev/null; then
  log "🔤 Generating permutations..."
  dnsgen "$passive" > "$report_dir/dnsgen_raw.txt" || echo "⚠️ dnsgen failed"
  massdns -r "$resolvers" -t A -o S -w "$perms" "$report_dir/dnsgen_raw.txt" || echo "⚠️ massdns failed"
else
  log "⚠️ dnsgen or massdns missing. Skipping permutations."
  touch "$perms"
fi


  # --- Merge and deduplicate all results ---
  cat "$passive" "$brute" "$perms" | sort -u > "$all"
  log "📦 Total unique subdomains: $(wc -l < "$all")"

  # --- Live/Resolved check ---
  if command -v dnsx &>/dev/null; then
    dnsx -l "$all" -silent -o "$resolved_file"
  else
    httpx -l "$all" -silent -o "$resolved_file"
  fi

  cat "$resolved_file"
  log "🌍 Alive/Resolved: $(wc -l < "$resolved_file")"
}


web_fingerprint() {
  log "\n${CYAN}========== Web Fingerprinting ==========${NC}"
  if [[ -s "$resolved_file" ]]; then
    httpx -l "$resolved_file" \
      --status-code --title --tech-detect \
      --silent --json --threads 50 \
      --output "$report_dir/web_fingerprinting.json" || echo "httpx failed"

    if [[ -s "$report_dir/web_fingerprinting.json" ]]; then
      jq -r '. | "\(.url) [\(.status_code)] - \(.title // "No Title")"' "$report_dir/web_fingerprinting.json" > "$report_dir/web_fingerprinting.txt"
    else
      echo "❌ No fingerprint data." > "$report_dir/web_fingerprinting.txt"
    fi
    cat "$report_dir/web_fingerprinting.txt"
  else
    echo "❌ No subdomains found. Skipping fingerprinting." > "$report_dir/web_fingerprinting.txt"
    cat "$report_dir/web_fingerprinting.txt"
  fi
}
fingerprint_tech_stack() {
  log "\n${CYAN}========== Web Technology Fingerprinting ==========${NC}"
  output="$report_dir/tech_stack.txt"

  if command -v whatweb &>/dev/null; then
    whatweb --no-errors --color=never --log-verbose="$output" "$target"
    echo "🔍 Tech stack identified with WhatWeb:"
    cat "$output"
  else
    echo "⚠️ whatweb not installed. Skipping tech stack fingerprinting."
  fi
}

analyze_tls_cert() {
  log "\n${CYAN}========== TLS Certificate Analysis ==========${NC}"
  {
    echo "🔐 TLS Analysis for: $target"
    echo "--------------------------------------------------"

    cert=$(timeout 10 openssl s_client -connect "$target:443" -servername "$target" < /dev/null 2>/dev/null)

    if [[ -z "$cert" || "$cert" == *"Connection refused"* || "$cert" == *"handshake failure"* ]]; then
      echo "❌ TLS fetch failed (no certificate returned or connection timed out)."
    else
      echo "$cert" | openssl x509 -noout -text 2>/dev/null |
      awk '
        /Subject:/ && !subject_printed++ {print "📛 Subject: " $0}
        /Issuer:/ && !issuer_printed++ {print "🛡️  Issuer: " $0}
        /Not Before:/ && !valid_from++ {print "🕒 Valid From: " $0}
        /Not After :/ && !valid_until++ {print "⌛ Expiry: " $0}
        /DNS:/ {print "🌐 SAN: " $0}
      '
    fi
  } > "$report_dir/tls_cert.txt" || echo "❌ TLS parse failed." > "$report_dir/tls_cert.txt"

  [[ -s "$report_dir/tls_cert.txt" ]] && cat "$report_dir/tls_cert.txt" || echo "❌ Empty TLS report."
}


analyze_http_security_headers() {
  log "\n${CYAN}========== HTTP Security Headers Analysis ==========${NC}"
  {
    echo "🛡️ Security Headers for: https://$target"
    echo "--------------------------------------------------"
    
    curl -sI -k "https://$target" |
    grep -iE 'Strict-Transport-Security|X-Frame-Options|X-XSS-Protection|Content-Security-Policy|Referrer-Policy|Permissions-Policy|Access-Control-Allow-Origin' |
    while read -r line; do
      key=$(echo "$line" | cut -d: -f1)
      value=$(echo "$line" | cut -d: -f2-)
      echo "🔐 $key: $value"
    done
  } > "$report_dir/http_security_headers.txt"

  [[ -s "$report_dir/http_security_headers.txt" ]] || echo "❌ No strong security headers detected." > "$report_dir/http_security_headers.txt"
  cat "$report_dir/http_security_headers.txt"
}

detect_waf() {
  log "\n${CYAN}========== WAF Detection ==========${NC}"
  if command -v wafw00f &>/dev/null; then
    echo "🔍 Scanning for WAF at $target..."
    wafw00f "http://$target" > "$report_dir/waf_detection.txt" 2>/dev/null

    if grep -iq "is behind" "$report_dir/waf_detection.txt"; then
      grep -i "is behind" "$report_dir/waf_detection.txt" | head -n 1
    else
      echo "✅ No WAF detected." >> "$report_dir/waf_detection.txt"
    fi
    cat "$report_dir/waf_detection.txt"
  else
    echo "⚠️ wafw00f not found. Skipping WAF detection." > "$report_dir/waf_detection.txt"
    cat "$report_dir/waf_detection.txt"
  fi
}

run_nuclei() {
  if command -v nuclei &>/dev/null; then
    log "\n${CYAN}========== Nuclei Scan ==========${NC}"

    # Prepare valid URLs (http & https) for nuclei
    urls_file="$report_dir/nuclei_urls.txt"
    [[ -s "$resolved_file" ]] || echo "$target" > "$resolved_file"

    {
      for sub in $(cat "$resolved_file"); do
        echo "http://$sub"
        echo "https://$sub"
      done
    } > "$urls_file"

    nuclei -l "$urls_file" \
      -silent \
      -no-color \
      -stats \
      -timeout 10 \
      -rate-limit 50 \
      -retries 2 \
      -max-host-error 10 \
      -o "$report_dir/nuclei_output.txt" || echo "nuclei failed"

    cat "$report_dir/nuclei_output.txt"
  else
    log "⚠️ nuclei not installed. Skipping."
  fi
}


fetch_archives() {
  log "\n${CYAN}========== Archived URLs ==========${NC}"
  [[ ! -s "$resolved_file" ]] && echo "$target" > "$resolved_file"
  {
    for sub in $(cat "$resolved_file"); do
      echo "$sub" | waybackurls 2>/dev/null || true
      echo "$sub" | gau 2>/dev/null || true
    done
  } | sort -u > "$report_dir/archives.txt"
  [[ -s "$report_dir/archives.txt" ]] || echo "No archives found." > "$report_dir/archives.txt"
  log "📦 Total archived URLs: $(wc -l < "$report_dir/archives.txt")"
}

capture_screenshots() {
  log "\n${CYAN}========== Screenshot Capture (Aquatone) ==========${NC}"
  if [[ -s "$resolved_file" ]]; then
    sed 's/^/http:\/\//' "$resolved_file" > "$report_dir/aquatone_input.txt"
    cat "$report_dir/aquatone_input.txt" | aquatone -chrome-path /usr/bin/google-chrome -out "$report_dir/aquatone" || echo "Aquatone failed"
  else
    echo "❌ No subdomains found. Skipping screenshots." > "$report_dir/screenshots.txt"
  fi
}

generate_html_report() {
  log "\n${CYAN}========== Generating HTML Report ==========${NC}"

  # Ensure variables are defined
  : "${report_dir:=reports/default}"
  : "${timestamp:=$(date +%Y%m%d_%H%M%S)}"
  html_file="$report_dir/report_$timestamp.html"
  mkdir -p "$report_dir"

  {
    echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Recon Report</title>"
    echo "<style>
      body { font-family: Arial, sans-serif; background: #f4f4f4; color: #333; padding: 20px; }
      pre { background: #eee; padding: 10px; border-left: 5px solid #555; border-radius: 4px; white-space: pre-wrap; }
      h2 { color: #fff; background: #222; padding: 8px; border-radius: 5px; }
      img { border: 1px solid #ccc; box-shadow: 0 0 5px rgba(0,0,0,0.1); margin: 10px; }
    </style></head><body>"

    echo "<h1>Recon Report for <u>$target</u></h1>"
    echo "<p><b>Date:</b> $(date)</p><p><b>Conducted by:</b> Muhammad Ateeb</p><hr>"

    # Follow recommended order for readability
    for section in \
      dns \
      ports \
      headers \
      resolved_subdomains \
      web_fingerprinting \
      tls_cert \
      http_security_headers \
      waf_detection \
      asn_info \
      passive_threat_intel \
      shodan \
      threatfox \
      virustotal \
      nuclei_output \
      archives \
      mitre_mapping \
      ffuf_combined; do
      
      file="$report_dir/${section}.txt"
      if [[ -f "$file" ]]; then
        echo "<h2>${section^^}</h2><pre>$(cat "$file")</pre><hr>"
      fi
    done

    # Screenshot section
    if [[ -d "$report_dir/aquatone/screenshots" ]]; then
      echo "<h2>🖼️ Screenshots</h2>"
      for img in "$report_dir/aquatone/screenshots"/*.png; do
        [[ -f "$img" ]] && echo "<img src='aquatone/screenshots/$(basename "$img")' width='400'>"
      done
      echo "<hr>"
    fi

    # Compliance mapping
    echo "<h2>📘 Compliance Mapping</h2><pre>"
    echo "🔐 TLS Cert              → NIST 800-53 SC-12, SC-17"
    echo "🛡️ Security Headers       → OWASP A06:2021, MITRE T1595.002"
    echo "🌍 Subdomains            → OWASP A06:2021, NIST CM-8"
    echo "🧱 WAF Detection         → NIST SI-4, MITRE T1555"
    echo "📦 Archived URLs         → OWASP A06:2021"
    echo "</pre><hr>"

    echo "</body></html>"
  } > "$html_file"

  log "${GREEN}📄 HTML report saved: $html_file${NC}"
}

enumerate_asn_info() {
  log "\n${CYAN}========== ASN / Netblock Enumeration ==========${NC}"
  {
    echo "🌐 Target: $target"
    echo "-----------------------------------------------"

    ip=$(dig +short "$target" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
    if [[ -z "$ip" ]]; then
      echo "❌ Could not resolve IP for $target"
    else
      echo "📌 Resolved IP: $ip"

      # Run asnmap and store output
      timeout 15s asnmap -i "$ip" -o "$report_dir/asn_raw.json" 2>/dev/null

      if [[ -s "$report_dir/asn_raw.json" ]]; then
        if jq -e . "$report_dir/asn_raw.json" >/dev/null 2>&1; then
          # Valid JSON, parse it
          jq -r '.[] | "ASN: \(.asn)\nOrg: \(.organization)\nNetblock: \(.netblock)\nCountry: \(.country)\n"' "$report_dir/asn_raw.json"
        else
          # Not JSON – likely a plain netblock
          netblock=$(cat "$report_dir/asn_raw.json")
          echo "Netblock (raw): $netblock"
          echo "⚠️ Detailed ASN info unavailable"
        fi
      else
        echo "❌ ASN mapping failed (empty or timeout)"
      fi
    fi
  } > "$report_dir/asn_info.txt"

  cat "$report_dir/asn_info.txt"
}




passive_threat_intel() {
  log "\n${CYAN}========== Passive Threat Intelligence ==========${NC}"
  intel_out="$report_dir/passive_threat_intel.txt"
  echo "🕵️ Passive Recon Results for: $target" > "$intel_out"

  [[ ! -s "$resolved_file" ]] && echo "$target" > "$resolved_file"

  while read -r sub; do
    echo -e "\n🌐 $sub" >> "$intel_out"
    dig +short "$sub" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$intel_out"

    # Timed API call to avoid freeze
    response=$(timeout 8 curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$sub/general" -H 'Accept: application/json')

    if [[ -n "$response" ]]; then
      echo "$response" | jq '.pulse_info.count as $score | "🔎 OTX Score: \($score)\nOTX Tags: \(.pulse_info.pulses[].name // "None")"' >> "$intel_out" 2>/dev/null || echo "⚠️ Could not parse JSON"
    else
      echo "❌ OTX timeout or no data" >> "$intel_out"
    fi

  done < "$resolved_file"

  cat "$intel_out"
}
test_api_keys() {
  log "\n${CYAN}========== API Key Test ==========${NC}"
  success=true

  if [[ -z "${SHODAN_API_KEY:-}" ]]; then
    echo -e "${RED}❌ SHODAN_API_KEY is not set!${NC}"
    success=false
  else
    test_shodan=$(curl -s --max-time 10 "https://api.shodan.io/api-info?key=$SHODAN_API_KEY" | jq -r '.plan // empty')
    if [[ -z "$test_shodan" ]]; then
      echo -e "${RED}❌ Shodan API test failed (invalid or expired key).${NC}"
      success=false
    else
      echo -e "${GREEN}✅ Shodan API is valid. Plan: $test_shodan${NC}"
    fi
  fi

  if [[ -z "${VT_API_KEY:-}" ]]; then
    echo -e "${RED}❌ VT_API_KEY is not set!${NC}"
    success=false
  else
    test_vt=$(curl -s --max-time 10 "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=$VT_API_KEY&ip=8.8.8.8" | jq -r '.response_code // empty')
    if [[ "$test_vt" == "1" ]]; then
      echo -e "${GREEN}✅ VirusTotal API is valid.${NC}"
    else
      echo -e "${RED}❌ VirusTotal API test failed (invalid or expired key).${NC}"
      success=false
    fi
  fi

  if [[ "$success" == false ]]; then
    echo -e "${YELLOW}[!] Fix API keys and re-run.${NC}"
    exit 1
  fi
}

fetch_threatfox_iocs() {
  log "\n${CYAN}========== ThreatFox IOC Lookup ==========${NC}"
  output="$report_dir/threatfox_iocs.txt"
  echo "🦊 ThreatFox IOC Check for: $target" > "$output"

  ip=$(dig +short "$target" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)

  if [[ -n "$ip" ]]; then
    curl -s -X POST "https://threatfox-api.abuse.ch/api/v1/" \
      -d "query=ioc&search_term=$ip" |
      jq -r '
        .data[]? | "⚠️ IOC: \(.ioc)\nType: \(.ioc_type)\nThreat: \(.threat_type)\nConfidence: \(.confidence_level)\n"
      ' >> "$output" || echo "❌ ThreatFox API failed or no results." >> "$output"
  else
    echo "❌ Could not resolve IP." >> "$output"
  fi

  cat "$output"
}
fetch_virustotal_info() {
  log "\n${CYAN}========== VirusTotal Intelligence ==========${NC}"
  output="$report_dir/virustotal.txt"
  echo "🦠 VirusTotal for: $target" > "$output"

  if [[ -z "$VT_API_KEY" ]]; then
    echo "❌ VT_API_KEY not set in environment." >> "$output"
  else
    response=$(curl -s -H "x-apikey: $VT_API_KEY" \
      "https://www.virustotal.com/api/v3/domains/$target")

    echo "$response" | jq -r '
      "Reputation: \(.data.attributes.reputation)",
      "Categories: \(.data.attributes.categories | to_entries[]? | "\(.key): \(.value)")",
      "Last Analysis Stats: \(.data.attributes.last_analysis_stats | to_entries[] | "\(.key): \(.value)")"
    ' >> "$output" || echo "❌ Failed to parse VT output" >> "$output"
  fi

  cat "$output"
}
enumerate_shodan_info() {
  log "\n${CYAN}========== Shodan Intelligence ==========${NC}"
  local ip
  ip=$(dig +short "$target" | head -n 1)

  if [[ -z "$SHODAN_API_KEY" ]]; then
    echo "❌ SHODAN_API_KEY is not set"
    return 1
  fi

  if [[ -z "$ip" ]]; then
    echo "❌ Could not resolve IP for $target"
    return 1
  fi

  local response
  response=$(curl -s --max-time 15 "https://api.shodan.io/shodan/host/$ip?key=$SHODAN_API_KEY")

  # If the response is null or missing expected fields
  if [[ "$response" == "null" || -z "$response" ]]; then
    echo "❌ No data found for IP: $ip"
    return 1
  fi

  # Validate it's valid JSON and has required fields
  if ! echo "$response" | jq -e . >/dev/null 2>&1; then
    echo "❌ Invalid JSON response or rate limit hit"
    echo "Raw response:"
    echo "$response"
    return 1
  fi

  # Check if ports exist before using join
  ports=$(echo "$response" | jq -r '.ports // empty | join(", ")')
  if [[ -z "$ports" ]]; then
    ports="N/A"
  fi

  echo "$response" | jq -r --arg t "$target" --arg p "$ports" '
    "📡 Shodan Info for: \($t)\nIP: \(.ip_str)\nISP: \(.isp // "N/A")\nOrg: \(.org // "N/A")\nCity: \(.city // "N/A")\nOpen Ports: \($p)"
  '
}
fuzz_hidden_paths() {
  log "\n${CYAN}========== Hidden Path Fuzzing (Dirs, Params, Headers) ==========${NC}"

  dir_output="$report_dir/ffuf_dirs.txt"
  param_output="$report_dir/ffuf_params.txt"
  header_output="$report_dir/ffuf_headers.txt"

  if ! command -v ffuf &>/dev/null; then
    echo "⚠️ ffuf not installed. Skipping fuzzing."
    return
  fi

  # Directory/API Fuzzing
  ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
       -u "https://$target/FUZZ" -mc 200,204,301,302,403 \
       -t 50 -of md -o "$dir_output" || echo "⚠️ FFUF dir fuzzing failed"

  # Parameter Fuzzing
  if [[ -f "/usr/share/wordlists/seclists/Fuzzing/parameters.txt" ]]; then
    ffuf -w /usr/share/wordlists/seclists/Fuzzing/parameters.txt \
         -u "https://$target/index.php?FUZZ=test" -mc 200,403 \
         -t 30 -of md -o "$param_output" || echo "⚠️ FFUF param fuzzing failed"
  else
    echo "⚠️ Parameter fuzzing wordlist missing."
  fi

  # API Key/Header Fuzzing (Authorization header as example)
  if [[ -f "/usr/share/wordlists/seclists/Discovery/Web-Content/api-keys.txt" ]]; then
    ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/api-keys.txt \
         -u "https://$target/" \
         -H "Authorization: Bearer FUZZ" -mc 200,403 \
         -t 20 -of md -o "$header_output" || echo "⚠️ FFUF header fuzzing failed"
  else
    echo "⚠️ API key wordlist missing."
  fi

  {
    echo -e "\n📄 Directory/API Fuzzing Results:"
    [[ -f "$dir_output" ]] && cat "$dir_output"
    echo -e "\n🔧 Parameter Fuzzing Results:"
    [[ -f "$param_output" ]] && cat "$param_output"
    echo -e "\n🔐 API-Key Fuzzing Results (Authorization Header):"
    [[ -f "$header_output" ]] && cat "$header_output"
  } > "$report_dir/ffuf_combined.txt"

  log "📦 Fuzzing complete. Results saved to ffuf_combined.txt"
}

map_findings_to_mitre() {
  log "\n${CYAN}========== MITRE Technique Mapping ==========${NC}"
  output="$report_dir/mitre_mapping.txt"
  echo "🎯 Mapped Techniques Based on Recon Findings for $target" > "$output"

  [[ -s "$report_dir/tls_cert.txt" ]] && echo "🔐 TLS Cert → NIST 800-53 SC-12, SC-17 / MITRE T1600" >> "$output"
  [[ -s "$report_dir/http_security_headers.txt" ]] && echo "🛡️ Security Headers → OWASP A06:2021 / MITRE T1595.002" >> "$output"
  [[ -s "$report_dir/resolved_subdomains.txt" ]] && echo "🌍 Subdomains → OWASP A06:2021 / MITRE T1590.002" >> "$output"
  [[ -s "$report_dir/waf_detection.txt" ]] && echo "🧱 WAF Detection → MITRE T1555 / NIST SI-4" >> "$output"
  [[ -s "$report_dir/archives.txt" ]] && echo "📦 Archived URLs → OWASP A06:2021 / MITRE T1213" >> "$output"
  [[ -s "$report_dir/passive_threat_intel.txt" ]] && echo "🕵️ Passive Threat Intel → MITRE T1598 / T1589" >> "$output"
  [[ -s "$report_dir/ffuf_combined.txt" ]] && echo "🧨 API/Param Fuzzing → MITRE T1190 (Exploitation for Initial Access), T1499 (DoS)" >> "$output"
  [[ -s "$report_dir/nuclei_output.txt" ]] && echo "🚨 Nuclei Findings → Custom, based on detected CVEs (e.g., T1190, T1210)" >> "$output"

  cat "$output"
}




# ============================
#            MAIN
# ============================

log "${CYAN}🚀 Starting Recon on $target at $(date)${NC}"
check_tools
test_api_keys

if is_alive; then
  log "✅ Host is alive!"

  ## ===== Phase 1: DNS & Network Info (Parallel) =====
  dns_info 
  enumerate_asn_info 

  ## ===== Phase 2: Network Mapping (Parallel) =====
  scan_ports 
  enumerate_subdomains 

  ## ===== Phase 3: Web Enumeration (Parallel) =====
  get_headers 
  analyze_tls_cert 
  analyze_http_security_headers 
  detect_waf 
  web_fingerprint 

  ## ===== Phase 4: Vulnerability Scanning (Sequential - avoid rate limits) =====
  run_nuclei

  ## ===== Phase 5: Threat Intelligence (Parallel) =====
  enumerate_shodan_info 
  passive_threat_intel 
  fetch_virustotal_info 
  fetch_threatfox_iocs 

  ## ===== Phase 6: Historical Recon & Visual Mapping (Parallel) =====
  fetch_archives 
  capture_screenshots 

  ## ===== Phase 7: Advanced Fuzzing (Parallel) =====
  fuzz_hidden_paths 
  fuzz_parameters 
  fuzz_api_keys_headers 

  ## ===== Phase 8: Reporting =====
  generate_html_report

else
  log "❌ Host is not reachable. Skipping recon."
fi

log "\n${GREEN}✅ Recon complete. Output saved to $log_file${NC}"

