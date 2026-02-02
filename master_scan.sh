#!/bin/bash

TARGET="satsiber-tni.mil.id"
echo "[!] PERINGATAN: HANYA UNTUK SISTEM YANG ANDA MILIKI ATAU MEMILIKI IZIN RESMI."
read -p "[?] Konfirmasi target adalah LAB SAH Anda (y/N): " -r
if [[ ! $REPLY =~ ^[Yy]$ ]]; then exit 1; fi

echo "[*] 1. Membersihkan ruang disk sementara..."
sudo apt clean 2>/dev/null
sudo rm -rf /tmp/* 2>/dev/null
sudo rm -rf /var/tmp/* 2>/dev/null
journalctl --vacuum-time=1d 2>/dev/null

echo "[*] 2. Memeriksa dan menginstal dependensi sistem..."
sudo apt update -q
sudo apt install -y git curl wget python3 python3-pip python3-venv golang-go ruby perl nikto dnsutils net-tools libpcap-dev libssl-dev seclists dirb 2>/dev/null

echo "[*] 3. Mengatur environment Golang..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc

echo "[*] 4. Menginstal/memperbarui tools Project Discovery..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null
nuclei -update-templates -silent 2>/dev/null
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null

echo "[*] 5. Menginstal tools tambahan..."
sudo apt install -y whatweb ffuf wafw00f sqlmap testssl.sh nmap zaproxy 2>/dev/null
if [ ! -d "XSStrike" ]; then
    git clone -q https://github.com/s0md3v/XSStrike.git 2>/dev/null
    pip3 install -r XSStrike/requirements.txt 2>/dev/null
fi

echo "[*] 6. Membuat direktori hasil scan..."
OUTPUT_DIR="scan_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[*] 7. MENJALANKAN PEMINDAIAN PENUH..."
echo "[7.1] Reconnaissance: Subdomain & Port..."
subfinder -d $TARGET -silent 2>/dev/null | httpx -status-code -title -tech-detect -o $OUTPUT_DIR/subdomains.txt 2>/dev/null
naabu -host $TARGET -top-ports 100 -silent 2>/dev/null > $OUTPUT_DIR/ports.txt
wafw00f https://$TARGET -a 2>/dev/null > $OUTPUT_DIR/waf.txt

echo "[7.2] Web Scanning: Direktori & Kerentanan..."
nuclei -u https://$TARGET -severity low,medium,high,critical -silent -o $OUTPUT_DIR/nuclei_scan.txt 2>/dev/null
ffuf -u https://$TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.html,.bak -t 20 -mc 200,301,302,403 -ac -c -o $OUTPUT_DIR/ffuf.json 2>/dev/null
whatweb https://$TARGET --color=never > $OUTPUT_DIR/whatweb.txt 2>/dev/null

echo "[7.3] Vulnerability Scanning: SQLi & XSS..."
sqlmap -u "https://$TARGET" --batch --crawl=2 --level=1 --risk=1 --flush-session -o $OUTPUT_DIR/sqlmap.txt 2>/dev/null
python3 XSStrike/xsstrike.py -u "https://$TARGET" --crawl -l 2 --skip > $OUTPUT_DIR/xss.txt 2>/dev/null

echo "[7.4] Network Scanning: Nmap & SSL..."
sudo nmap -sV -sC -T3 -p 80,443,22,21,25,53,8080 $TARGET -oA $OUTPUT_DIR/nmap_basic 2>/dev/null
testssl.sh $TARGET 2>/dev/null | head -50 > $OUTPUT_DIR/testssl_quick.txt

echo "[+] PEMINDAIAN SELESAI. Hasil disimpan di: $OUTPUT_DIR/"
ls -la $OUTPUT_DIR/
