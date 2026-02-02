#!/bin/bash

TARGET="satsiber-tni.mil.id"
echo "[!] PERINGATAN: HANYA UNTUK SISTEM YANG ANDA MILIKI ATAU MEMILIKI IZIN RESMI."
read -p "[?] Konfirmasi target adalah LAB SAH Anda (y/N): " -r
if [[ ! $REPLY =~ ^[Yy]$ ]]; then exit 1; fi

echo "[*] 1. Membersihkan ruang disk kritis..."
sudo apt clean 2>/dev/null || true
sudo find /var/log -type f -name "*.gz" -delete 2>/dev/null || true
sudo rm -rf /tmp/* 2>/dev/null || true
sudo journalctl --vacuum-time=1d 2>/dev/null || true

echo "[*] 2. Memeriksa dan menginstal dependensi sistem..."
sudo apt update -q
sudo apt install -y git curl wget python3 python3-pip python3-venv golang-go nikto net-tools libssl-dev exploitdb 2>/dev/null || true

echo "[*] 3. Mengatur environment..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
mkdir -p $GOPATH 2>/dev/null || true

echo "[*] 4. Menginstal tools Project Discovery..."
tools=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    "github.com/projectdiscovery/httpx/cmd/httpx" 
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu"
)
for tool in "${tools[@]}"; do
    tool_name=$(basename $tool)
    if ! command -v $tool_name &> /dev/null; then
        echo "[*] Installing $tool_name..."
        CGO_ENABLED=0 go install -v $tool@latest 2>&1 | tail -3
    fi
done
nuclei -update-templates -silent 2>/dev/null || true

echo "[*] 5. Menginstal tools tambahan..."
if ! command -v searchsploit &> /dev/null; then
    sudo apt install -y exploitdb 2>/dev/null || true
fi
if [ ! -d "XSStrike" ]; then
    git clone --depth 1 https://github.com/s0md3v/XSStrike.git 2>/dev/null || true
    [ -d "XSStrike" ] && cd XSStrike && pip3 install -r requirements.txt 2>/dev/null && cd .. || true
fi

echo "[*] 6. Membuat direktori hasil scan..."
OUTPUT_DIR="scan_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[*] 7. MENJALANKAN PEMINDAIAN PENUH..."

echo "[7.1] Reconnaissance..."
if command -v subfinder &> /dev/null; then
    subfinder -d $TARGET -silent 2>/dev/null | httpx -status-code -title -tech-detect -o $OUTPUT_DIR/subdomains.txt 2>&1 | head -5
fi
if [ -f "$OUTPUT_DIR/subdomains.txt" ]; then
    echo "[*] Subdomain ditemukan:"
    cat "$OUTPUT_DIR/subdomains.txt"
fi

echo "[7.2] Vulnerability Scanning..."
if command -v nuclei &> /dev/null; then
    echo "[*] Scanning dengan nuclei (CVE detection)..."
    nuclei -u https://$TARGET -tags cve -severity critical,high,medium -silent -o $OUTPUT_DIR/nuclei_cve.txt 2>/dev/null
    nuclei -u https://$TARGET -tags exposure,misconfig -silent -o $OUTPUT_DIR/nuclei_misc.txt 2>/dev/null
fi

echo "[7.3] Technology Analysis..."
if command -v whatweb &> /dev/null; then
    whatweb https://$TARGET --color=never > $OUTPUT_DIR/whatweb.txt 2>/dev/null
    echo "[*] Teknologi terdeteksi:"
    grep -E "(PHP|Apache|Nginx|Laravel|WordPress|Joomla)" "$OUTPUT_DIR/whatweb.txt" 2>/dev/null || true
fi

echo "[*] 8. SEARCHSPLOIT ANALYSIS (FASE AKHIR)..."
echo "[8.1] Mencari CVE dari hasil scan..."
CVES_FOUND=()
if [ -f "$OUTPUT_DIR/nuclei_cve.txt" ]; then
    CVES_FOUND=($(grep -oE "CVE-[0-9]{4}-[0-9]+" "$OUTPUT_DIR/nuclei_cve.txt" | sort -u))
fi

if [ ${#CVES_FOUND[@]} -eq 0 ]; then
    echo "[*] Tidak ada CVE spesifik ditemukan, mencari berdasarkan teknologi..."
    TECH_DETECTED=""
    if [ -f "$OUTPUT_DIR/whatweb.txt" ]; then
        TECH_DETECTED=$(grep -E "(PHP|Apache|Nginx|Laravel|WordPress|Joomla|Zimbra)" "$OUTPUT_DIR/whatweb.txt" | head -3)
    fi
    if [ -n "$TECH_DETECTED" ]; then
        echo "[*] Teknologi untuk searchsploit: $TECH_DETECTED"
        echo "$TECH_DETECTED" > "$OUTPUT_DIR/tech_for_search.txt"
    fi
fi

echo "[8.2] Menjalankan searchsploit..."
if command -v searchsploit &> /dev/null; then
    if [ ${#CVES_FOUND[@]} -gt 0 ]; then
        echo "[*] Mencari exploit untuk ${#CVES_FOUND[@]} CVE..."
        for cve in "${CVES_FOUND[@]}"; do
            echo "=== $cve ===" >> "$OUTPUT_DIR/searchsploit_results.txt"
            searchsploit "$cve" >> "$OUTPUT_DIR/searchsploit_results.txt" 2>/dev/null
            echo "" >> "$OUTPUT_DIR/searchsploit_results.txt"
        done
    else
        echo "[*] Mencari exploit berdasarkan teknologi umum..."
        searchsploit webapps 2024 2025 >> "$OUTPUT_DIR/searchsploit_general.txt" 2>/dev/null
        if [ -f "$OUTPUT_DIR/tech_for_search.txt" ]; then
            while read -r tech; do
                echo "=== $tech ===" >> "$OUTPUT_DIR/searchsploit_tech.txt"
                searchsploit "$tech" >> "$OUTPUT_DIR/searchsploit_tech.txt" 2>/dev/null
            done < "$OUTPUT_DIR/tech_for_search.txt"
        fi
    fi
else
    echo "[!] searchsploit tidak terinstal, menginstal..."
    sudo apt install -y exploitdb 2>/dev/null || true
    if command -v searchsploit &> /dev/null; then
        searchsploit --help > "$OUTPUT_DIR/searchsploit_check.txt" 2>&1
    fi
fi

echo "[*] 9. GENERATING FINAL REPORT..."
echo "=== LAPORAN PEMINDAIAN KEAMANAN ===" > "$OUTPUT_DIR/FINAL_REPORT.txt"
echo "Target: $TARGET" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
echo "Waktu: $(date)" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
echo "==================================" >> "$OUTPUT_DIR/FINAL_REPORT.txt"

echo "" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
echo "1. SUBDOMAIN DITEMUKAN:" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
[ -f "$OUTPUT_DIR/subdomains.txt" ] && cat "$OUTPUT_DIR/subdomains.txt" >> "$OUTPUT_DIR/FINAL_REPORT.txt" || echo "Tidak ada" >> "$OUTPUT_DIR/FINAL_REPORT.txt"

echo "" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
echo "2. CVE YANG DITEMUKAN:" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
if [ ${#CVES_FOUND[@]} -gt 0 ]; then
    printf '%s\n' "${CVES_FOUND[@]}" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
else
    echo "Tidak ada CVE kritis/tinggi yang terdeteksi" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
fi

echo "" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
echo "3. HASIL SEARCHSPLOIT:" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
if [ -f "$OUTPUT_DIR/searchsploit_results.txt" ] && [ -s "$OUTPUT_DIR/searchsploit_results.txt" ]; then
    grep -A2 -B2 "Exploit" "$OUTPUT_DIR/searchsploit_results.txt" >> "$OUTPUT_DIR/FINAL_REPORT.txt" 2>/dev/null || head -20 "$OUTPUT_DIR/searchsploit_results.txt" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
elif [ -f "$OUTPUT_DIR/searchsploit_tech.txt" ] && [ -s "$OUTPUT_DIR/searchsploit_tech.txt" ]; then
    head -20 "$OUTPUT_DIR/searchsploit_tech.txt" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
else
    echo "Tidak ada exploit publik yang ditemukan" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
fi

echo "" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
echo "4. REKOMENDASI:" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
if [ ${#CVES_FOUND[@]} -gt 0 ]; then
    echo "- Patch segera CVE yang ditemukan" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
    echo "- Monitor exploit database untuk CVE terkait" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
else
    echo "- Tidak ada kerentanan kritis yang terdeteksi" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
    echo "- Pertahankan update rutin sistem" >> "$OUTPUT_DIR/FINAL_REPORT.txt"
fi

echo "[+] PEMINDAIAN SELESAI!"
echo "[*] Hasil disimpan di: $OUTPUT_DIR/"
echo "[*] File penting:"
ls -la $OUTPUT_DIR/*.txt 2>/dev/null | head -10

echo ""
echo "=== PREVIEW HASIL ==="
if [ -f "$OUTPUT_DIR/FINAL_REPORT.txt" ]; then
    cat "$OUTPUT_DIR/FINAL_REPORT.txt"
fi
