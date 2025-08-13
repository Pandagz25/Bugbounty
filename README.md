# Bug Bounty Scanner

Bug Bounty Scanner adalah alat sederhana untuk memindai kerentanan umum pada website, cocok untuk pembelajaran keamanan web dan bug bounty hunting.  
Script ini **hanya untuk penggunaan etis** dengan izin pemilik sistem yang diuji.

## ✨ Fitur
- **Pemeriksaan Header HTTP** (server info & missing security headers)
- **Deteksi File Sensitif** (config files, database backups, dll.)
- **Pemeriksaan Directory Listing**
- **Pencarian Panel Admin Umum**
- **Pemeriksaan SQL Injection** (basic)
- **Pemeriksaan XSS** (basic)
- **Scan Port Umum**
- **Rekomendasi Keamanan**

## ⚠️ Disclaimer
- Gunakan **hanya** pada sistem milik sendiri atau dengan izin tertulis dari pemilik.
- Script ini dapat menghasilkan **false positives**.
- Penulis tidak bertanggung jawab atas penyalahgunaan.

## 📦 Instalasi

1. **Clone repo** atau download script:
   ```bash
   pkg install python
   pkg install git
   pip install requests beautifulsoup4 colorama
   git clone https://github.com/Pandagz25/Bugbounty.git
   cd Bugbounty
   python bag.py
