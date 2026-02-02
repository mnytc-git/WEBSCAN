#!/bin/bash
# auto_scan.sh - Skrip Scanning Otomatis (HANYA UNTUK LAB SAH)

TARGET="satsiber-tni.mil.id" # ⚠️ GANTI DENGAN TARGET LAB ANDA SENDIRI!
OUTPUT_DIR="scan_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[!] PERINGATAN: Hanya untuk sistem yang Anda miliki/izin!"
echo "[*] Target: $TARGET"
echo "[*] Output disimpan di: $OUTPUT_DIR/"
read -p "Lanjutkan? (y/N): " -n 1 -r
if [[ ! $REPLY =~ ^[Yy]$ ]]; then exit 1; fi

# 1. RECON
echo "[1] Reconnaissance..."
subfinder -d $TARGET -silent | httpx -status-code -title -tech-detect -o $OUTPUT_DIR/subdomains.txt
naabu -host $TARGET -top-ports 1000 -o $OUTPUT_DIR/ports.txt
wafw00f https://$TARGET -a > $OUTPUT_DIR/waf.txt

# 2. WEB SCAN
echo "[2] Web Scanning..."
nuclei -u https://$TARGET -severity medium,high,critical -o $OUTPUT_DIR/nuclei_scan.txt
ffuf -u https://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.bak -mc 200,301,302,403 -ac -c -o $OUTPUT_DIR/ffuf.json
whatweb -a 3 https://$TARGET > $OUTPUT_DIR/whatweb.txt

# 3. VULN SCAN
echo "[3] Vulnerability Scanning..."
# SQLi & XSS (jika ada parameter)
sqlmap -u "https://$TARGET" --batch --crawl=2 --level=1 --risk=1 -o $OUTPUT_DIR/sqlmap.txt
python3 XSStrike/xsstrike.py -u "https://$TARGET" --crawl -o $OUTPUT_DIR/xss.txt

# 4. NETWORK SCAN
echo "[4] Network Scanning..."
sudo nmap -sV -sC -p- -T4 $TARGET -oA $OUTPUT_DIR/nmap_full
testssl.sh $TARGET > $OUTPUT_DIR/testssl.txt

echo "[+] Selesai! Hasil di: $OUTPUT_DIR/"
