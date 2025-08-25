# Project Sentinel v2

> **Professional Bug Hunter's Framework — Use Responsibly, Think Ethically**

## ⚠️ Disclaimer
Project Sentinel dibuat untuk membantu **peneliti keamanan, bug hunter, dan profesional IT** dalam melakukan **pengujian keamanan** hanya pada sistem yang **dimiliki sendiri** atau memiliki **izin eksplisit** dari pemilik sistem. 

⚠️ Segala bentuk penyalahgunaan terhadap tool ini untuk menyerang pihak ketiga tanpa izin adalah **ilegal** dan sepenuhnya menjadi tanggung jawab pengguna.

---

## 📌 Ringkasan
Project Sentinel v2 adalah framework all-in-one yang membantu bug hunter melakukan:
- Reconnaissance (pencarian subdomain & aset)
- Content & endpoint scanning
- Analisis kerentanan umum (security headers, subdomain takeover, secret exposure)

---

## 🚀 Fitur Utama
- **Recon / Subdomain Discovery**  
  - Bruteforce subdomain dengan wordlist eksternal
  - Multi-threaded untuk kecepatan tinggi
  - Menyimpan hasil ke file

- **Content & Endpoint Scanner**  
  - Pemindaian direktori/file menggunakan wordlist
  - Deteksi status code (200, 300 redirect, dll)

- **Vulnerability Analysis**  
  - Cek security headers penting (CSP, HSTS, XFO, dll)
  - Deteksi potensi subdomain takeover
  - Cari kebocoran informasi sensitif di file JavaScript

---

## 🛠️ Instalasi
### Persyaratan
Pastikan Python 3 sudah terpasang, lalu install modul yang dibutuhkan:
```bash
pip install requests beautifulsoup4 colorama
```

### Clone Repository
```bash
git clone https://github.com/r00tH3x/sentinel.git
cd sentinel
```

---

## 📖 Cara Penggunaan
Jalankan dengan Python 3:
```bash
python3 sentinel.py [mode] [options]
```

### 1. Recon (Subdomain Discovery)
```bash
python3 sentinel.py recon -d target.com -w wordlist.txt -t 50 -o subdomains.txt
```
- `-d` : Domain target
- `-w` : Wordlist subdomain
- `-t` : Jumlah thread (default: 50)
- `-o` : Simpan hasil ke file

### 2. Scan (Content & Endpoint)
```bash
python3 sentinel.py scan -u https://target.com -w directories.txt -t 50
```
- `-u` : URL target
- `-w` : Wordlist direktori/file
- `-t` : Jumlah thread (default: 50)

### 3. Vuln (Vulnerability Analysis)
- Target tunggal:
```bash
python3 sentinel.py vuln -u https://target.com
```
- Banyak target dari file:
```bash
python3 sentinel.py vuln -f urls.txt
```

---

## 📂 Menggunakan Wordlist Eksternal (contoh: SecLists)
Project Sentinel mendukung penggunaan wordlist eksternal seperti [SecLists](https://github.com/danielmiessler/SecLists).

### Clone SecLists (opsional)
```bash
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists
```

### Contoh penggunaan:
- Untuk subdomain brute-force:
```bash
python3 sentinel.py recon -d target.com -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

- Untuk directory/file scan:
```bash
python3 sentinel.py scan -u https://target.com -w ~/SecLists/Discovery/Web-Content/common.txt
```

> ⚠️ Pastikan hanya menggunakan wordlist di **domain/sistem yang Anda miliki izin eksplisit** untuk diuji.

---

## 📊 Output & Hasil
- Hasil **Recon** dapat disimpan otomatis ke file dengan `-o`
- Hasil **Scan & Vuln** ditampilkan langsung di terminal
- Status code berwarna untuk memudahkan analisis

---

## ❓ FAQ
**Q: Apakah tool ini legal untuk dipakai di target bebas di internet?**  
A: **Tidak.** Gunakan hanya pada domain/sistem milik Anda atau yang Anda dapat izin tertulis.

**Q: Bisa jalan di Windows/Linux/Mac?**  
A: Bisa, asalkan Python 3 dan dependensi sudah terpasang.

**Q: Apa bedanya dengan tool lain (dirsearch, sublist3r, dll)?**  
A: Sentinel menggabungkan beberapa modul (recon, content scan, vuln analysis) dalam satu framework dengan output yang lebih rapih.

---

## 🤝 Kontribusi
Pull request, issue, dan saran sangat diterima. Pastikan setiap kontribusi memperhatikan aspek **etika & legalitas**.

---

## 📜 Lisensi
MIT License — Gunakan secara **bertanggung jawab & beretika**.

