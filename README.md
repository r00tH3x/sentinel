# 🛡️ Sentinel v3 — Advanced OSINT & Reconnaissance Framework

> **Use Responsibly — for authorized testing, learning, and research only.** 🚨

**Source reference:** Core implementation and feature set are based on `sentinel.py`. citeturn2view0

---

## 📌 Ringkasan singkat
Sentinel v3 adalah framework reconnaissance dan vulnerability discovery yang menggabungkan: enhanced subdomain discovery, content discovery, vulnerability heuristics, network intelligence, dan integrasi API pihak ketiga (Shodan, VirusTotal, Hunter.io, SecurityTrails, dll.). Tool ini dirancang untuk riset & OSINT di lingkungan yang **memiliki izin**. 

> ⚠️ **Penting:** Jangan gunakan untuk mengakses, memindai, atau memeriksa sistem tanpa izin. Pelanggaran dapat berakibat hukum.

---

## 📚 Daftar isi
1. Fitur utama
2. Instalasi & dependensi
3. Konfigurasi API (detail)
4. Penjelasan modul & alur kerja (rinci)
5. Contoh penggunaan / CLI
6. Output & format laporan
7. Etika, rate limits & privasi
8. Troubleshooting & FAQ
9. Kontribusi & lisensi

---

## ✨ 1) Fitur Utama (ringkasan) 🎯
- Enhanced Subdomain Discovery (CRT, Wayback, RapidDNS, SecurityTrails, crt.sh, Google dorking, built-in wordlists). 
- Content discovery & directory bruteforce (built-in wordlist + backup file heuristics). 
- Vulnerability heuristics: SSL/TLS analysis, security header checks, subdomain takeover signatures, secret/key discovery in JS, and detection heuristics for common web vulns. 
- Network reconnaissance & WHOIS/DNS enrichment.
- Email harvesting (Hunter.io + passive sources).
- API integrations: Shodan, VirusTotal, Hunter.io, SecurityTrails (premium — optional) and several free sources (RapidDNS, AlienVault OTX, ThreatCrowd, HackerTarget).
- Output & reporting: JSON, CSV, TXT (timestamped) and HTML report template.

---

## 🛠️ 2) Instalasi & dependensi (singkat) 🧩
**Prasyarat:** Python 3.8+ (disarankan) dan akses internet untuk API/enrichment.

**Dependensi pip (umum):**
```bash
pip install requests beautifulsoup4 colorama dnspython python-whois shodan
```
> Catatan: nama paket dapat bervariasi (mis. `whois` atau `python-whois`). Jika ada import error, periksa nama paket di environment Anda.

---

## ⚙️ 3) Konfigurasi API (di dalam kode / config file)
Sentinel menyimpan konfigurasi API di dict `CONFIG` di `sentinel.py`, dan juga menyediakan subcommand `config` untuk menyimpan `sentinel_config.json`. Anda dapat mengisi API key di dua cara:

1. **Sunting langsung `CONFIG`** (baris awal file):
   - `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `HUNTER_API_KEY`, `SECURITYTRAILS_API_KEY`.
2. **Gunakan subcommand `config`** (CLI helper) untuk menyimpan kunci ke `sentinel_config.json`:
   - Contoh: `python sentinel.py config --shodan YOUR_KEY --hunter YOUR_KEY` (tool akan menyimpan file config dan memperbarui runtime). 

### Ringkasan API yang didukung & peranannya
- **Shodan** — network/device intelligence & port/service data (opsional, premium).
- **VirusTotal** — domain/IP enrichment, URL scans, reputation data.
- **Hunter.io** — email harvesting & contact discovery (domain search). 
- **SecurityTrails** — DNS/subdomain history & enumerasi (premium). 

> ⚠️ Perhatikan batasan penggunaan & rate-limit operator API tersebut — baca dokumentasi masing-masing sebelum pemakaian. 

---

## 🔍 4) Penjelasan Modul & Alur Kerja (dengan detail) 🧭
> Catatan: uraian di bawah **menjelaskan perilaku program** (apa yang dilakukan), bukan panduan untuk menyalahgunakan fitur.

### A. Logger (`Logger`)
- Fungsi utama: menyimpan hasil ke `sentinel_output/`.
- Format: JSON (`filename_timestamp.json`), CSV (`filename_timestamp.csv`) dan TXT (`filename_timestamp.txt`).
- Contoh penggunaan: `logger.save_json(data, "subdomains")` menyimpan file bernama `subdomains_YYYYmmdd_HHMMSS.json`.

### B. API Client (`APIClient`)
- Abstraksi panggilan ke layanan eksternal (Shodan, VirusTotal, SecurityTrails, Hunter.io) serta beberapa pengambilan data gratis (RapidDNS, AlienVault OTX, ThreatCrowd).
- Setiap method akan: memeriksa ketersediaan API key di `CONFIG`, melakukan request, lalu mengembalikan data yang diproses (mis. list subdomain, list email, matches dari Shodan). Jika API gagal/error, method akan mengembalikan struktur kosong dan mencetak error. 

### C. EnhancedSubdomainScanner
- **Sumber**: kombinasi wordlist bruteforce (built-in), crt.sh (cert transparency), Wayback Machine, Google dorking, RapidDNS, DNSDumpster (parsing HTML), SecurityTrails, AlienVault OTX, ThreatCrowd, HackerTarget, sonar.omnisint & Riddler-like sources. 
- **Langkah umum**:
  1. Query certificate transparency (`crt.sh`) untuk entri subdomain.
  2. Query Wayback Machine / archived URLs.
  3. Query sejumlah layanan API/free-sources (RapidDNS, OTX, etc.).
  4. DNS bruteforce menggunakan `SUBDOMAIN_WORDLIST` (multi-threaded).
  5. Validasi hasil dengan DNS lookup dan deduplikasi.
- **Output**: list objek `{ 'subdomain': <str>, 'ips': [<ip>, ...], 'method': <string> }` dan file JSON/TXT yang disimpan melalui `Logger`. 

### D. EnhancedContentScanner
- **Tujuan**: temukan aset web (login pages, admin panels, file backups, config files, .git, .env, dll.).
- **Metode**:
  - Memeriksa file/direktori umum (`robots.txt`, `sitemap.xml`, `.env`, `config.php`, `.git`, `README.md`, dll.)
  - Melakukan directory bruteforce dari `DIRECTORY_WORDLIST` (multi-threaded).
  - Menghasilkan candidate backup paths (ekstensi/prefix/suffix seperti `.bak`, `backup_`, `_old`) dan memeriksanya terbatas (to avoid spam).
- **Data yang dicatat**: URL, status_code, content_length, content_type, server, last_modified, location(header jika redirect).
- **Output**: JSON + CSV ringkasan untuk analisis lebih lanjut. citeturn2view0

### E. EnhancedVulnScanner
- **Analisis mencakup**:
  - SSL/TLS: mengambil sertifikat, issuer, valid-until dan cipher suite; menandai cipher lemah atau ketiadaan HTTPS.  
  - Security headers: cek header seperti `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, dll.  
  - Subdomain takeover: mencari tanda (fingerprints) dari penyedia layanan yang meninggalkan halaman default (GitHub Pages, Heroku, S3 bucket, Fastly, Shopify, dll.).  
  - Secret discovery: memindai sumber JS/halaman untuk pola yang mungkin menunjukkan API keys, tokens, private keys, AWS keys, JWT-like strings, dsb.  
  - Heuristics untuk kerentanan web umum (otomatis mendeteksi indikasi SQLi, XSS, Directory Traversal berdasarkan pola respons/error signatures).
- **Bagaimana hasilnya disajikan**: setiap temuan disimpan sebagai object dengan _fields_ minimal: `type`, `severity` (High/Medium/Low), `description`, `url`, `evidence` (potongan teks). Semua temuan dikumpulkan ke `vulnerabilities` list dan disimpan oleh `Logger`. 

> ⚠️ NOTE: beberapa pemeriksaan mengirim permintaan GET/HTTP ke target (non-intrusive by design), tetapi tetap dapat dianggap invasive. Gunakan **hanya pada target yang Anda miliki izin**.

### F. Phases / Full Run (Alur Utama)
Sentinel menyediakan beberapa mode, termasuk `network`, `subdomain`, `email`, `scan`, `vuln` dan `full` yang mengorkestrasi seluruh alur: network reconnaissance → subdomain discovery → email harvesting → content discovery → vulnerability assessment → report generation. Contoh alur `full` (urutannya):

1. Network reconnaissance (WHOIS, DNS, IP enrichment)
2. Subdomain discovery (crt.sh, Wayback, RapidDNS, bruteforce)
3. Email harvesting (Hunter.io + sources)
4. Content discovery (directory scanning)
5. Vulnerability assessment (SSL, headers, secrets, heuristics)
6. Generate comprehensive report (JSON/CSV/HTML)

Semua fase di atas disinkronkan otomatis ketika `python sentinel.py full -d example.com` dijalankan.

---

## ▶️ 5) Contoh Penggunaan / CLI (singkat) ⚙️
(Tangkapan contoh langsung dari `sentinel.py` — gunakan ini hanya di lingkungan lab/berizin). 

```bash
# Recon / subdomain discovery
python sentinel.py recon -d example.com

# Content scan (directory discovery)
python sentinel.py scan -u https://example.com

# Vulnerability checks for a URL
python sentinel.py vuln -u https://example.com

# Run full pipeline (network -> subdomains -> emails -> content -> vuln -> report)
python sentinel.py full -d example.com

# Configure API keys (saves to sentinel_config.json)
python sentinel.py config --shodan YOUR_SHODAN_KEY --hunter YOUR_HUNTER_KEY
```

---

## 📦 6) Output & Format Laporan (contoh)
- `sentinel_output/comprehensive_report_YYYYmmdd_HHMMSS.json` — ringkasan penuh: jaringan, subdomains, emails, content paths, vulnerabilities (struktur JSON). citeturn2view0
- `sentinel_output/content_discovery_*.csv` — tabel path/url dan header terkait.
- `sentinel_output/subdomains_*.txt` — daftar subdomain satu-per-baris.
- HTML report template (simple) dibuat untuk visual summary (nama template ada di file `sentinel.py`).

---

## 🔐 7) Etika, Rate Limits & Privasi
- **Hanya** gunakan pada target yang Anda miliki izin untuk menguji. 🔒
- Periksa _Terms of Service_ tiap API (Shodan, VirusTotal, Hunter, SecurityTrails). Be mindful of rate limits — Sentinel tidak magically bypass rate limits. citeturn3search0turn3search1
- Jangan menyimpan PII yang tidak perlu. Jika menemukan kredensial/leak, laporkan secara bertanggung jawab ke pemilik/owner dan hapus data sensitif dari penyimpanan publik.

---

## 🐞 8) Troubleshooting & FAQ (singkat)
**Q — Script gagal saat `import shodan`**  
A — Install `shodan` package: `pip install shodan`. Restart environment.

**Q — `config` subcommand tidak menyimpan API key**  
A — Pastikan Anda memiliki hak tulis di folder proyek dan tidak ada permission error.

**Q — Scan berjalan lambat / terblokir**  
A — Periksa koneksi, rate limits API, dan firewall/IDS di jaringan target (ingat: gunakan lab!).

---

## 🤝 9) Kontribusi & Lisensi
- Fork, PR, dan issue diterima. Sertakan deskripsi perubahan, threat-model, dan test-case.  
- Lisensi: MIT (lihat file `LICENSE`).

---

## 🔚 Penutup
Terima kasih telah menggunakan **Sentinel v3** — tool ini kuat untuk OSINT & research bila dipakai secara etis!!✨

---

*References & source snippets pulled from sentinel.py and relevant API docs.* 

