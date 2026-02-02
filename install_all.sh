#!/bin/bash
# install_all.sh - Skrip Instalasi Tools Pentesting Lengkap

echo "[!] PERINGATAN: Pastikan Anda memiliki izin untuk menggunakan alat ini."
echo "[*] Memulai instalasi semua tools..."

# Update sistem dan instal dependensi
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget build-essential python3 python3-pip python3-venv golang-go ruby perl npm nikto dnsutils net-tools libpcap-dev libssl-dev

# Setup Go PATH
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc

# 1. RECONNAISSANCE TOOLS
echo "[*] Instalasi Reconnaissance Tools..."
# Gau & Katana
go install github.com/lc/gau/v2/cmd/gau@latest
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
# Httpx, Nuclei, Subfinder
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# Naabu
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
# WhatWeb, FFUF, WAFW00F
sudo apt install -y whatweb ffuf wafw00f
# CloudFail
git clone https://github.com/m0rtem/CloudFail.git
cd CloudFail && pip3 install -r requirements.txt && cd ..

# 2. WEB VULNERABILITY SCANNERS
echo "[*] Instalasi Web Vulnerability Scanners..."
# ZAP
sudo apt install -y zaproxy
# XSStrike
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike && pip3 install -r requirements.txt && cd ..
# SQLMap, WPScan, Joomscan
sudo apt install -y sqlmap wpscan joomscan
# Kiterunner
go install github.com/assetnote/kiterunner/cmd/kr@latest

# 3. NETWORK VULNERABILITY SCANNERS
echo "[*] Instalasi Network Vulnerability Scanners..."
# Sn1per
git clone https://github.com/1N3/Sn1per.git
cd Sn1per && sudo bash install.sh && cd ..
# Hydra & Wordlists
sudo apt install -y hydra wordlists seclists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
# TestSSL
sudo apt install -y testssl.sh

# 4. OFFENSIVE TOOLS
echo "[*] Instalasi Offensive Tools..."
# Subjack & Amass
go install github.com/haccer/subjack@latest
go install -v github.com/owasp-amass/amass/v3/...@master
# Dalfox
go install github.com/hahwul/dalfox/v2@latest
# Searchsploit
sudo apt install -y exploitdb

# 5. UTILITIES
echo "[*] Instalasi Utilities..."
# Whois, etc.
sudo apt install -y whois iputils-ping

echo "[+] Instalasi selesai! Restart terminal atau jalankan: source ~/.bashrc"
