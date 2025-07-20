#!/bin/bash
# Enhanced Multi-Target Recon Launcher with Summary Table
set -euo pipefail

if [[ -z "${1:-}" ]]; then
  echo "❌ Usage: $0 targets.txt"
  exit 1
fi

input_file="$1"

if [[ ! -f "$input_file" ]]; then
  echo "❌ File '$input_file' not found!"
  exit 1
fi

mkdir -p logs summary

echo "🚀 Launching recon for multiple targets..."
targets=()

# Run scans in background and capture logs
while IFS= read -r target; do
  [[ -z "$target" || "$target" =~ ^# ]] && continue
  targets+=("$target")
  (
    bash single_scan1.sh "$target"
  ) > "logs/$target.out" 2>&1 &
done < "$input_file"

wait
echo "✅ All recon jobs completed!"

# === Generate Summary Table ===
summary_file="summary/summary_$(date +%F_%H-%M-%S).txt"
{
  printf "\n%-25s | %-12s | %-10s | %-18s | %s\n" "Target" "Host Status" "Ports" "Subdomains Found" "Log File"
  printf -- "-----------------------------------------------------------------------------------------------\n"

  for target in "${targets[@]}"; do
    logfile="logs/$target.out"
    [[ ! -f "$logfile" ]] && continue

    host_status=$(grep -m1 "Host is" "$logfile" | awk '{print $2, $3}')
    open_ports=$(grep -c "Port [0-9]* is open" "$logfile")
    subdomains=$(grep -cE "^\✅ .* resolves" "$logfile")
    printf "%-25s | %-12s | %-10s | %-18s | %s\n" "$target" "$host_status" "$open_ports" "$subdomains" "$logfile"
  done
} | tee "$summary_file"

echo -e "\n📄 Summary saved to: $summary_file"

