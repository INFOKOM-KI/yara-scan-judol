# Aturan YARA Deteksi Judi Online (Judol) — TangerangKota-CSIRT

**Author:** NAuliajati &lt;csirt@tangerangkota.go.id&gt;  
**Organisasi:** TangerangKota-CSIRT  
**Versi:** 1.0  
**Tanggal:** 2026-05-06  
**Lisensi:** TangerangKota-CSIRT Detection Rule License 1.0

---

## Daftar Isi

1. [Latar Belakang](#latar-belakang)
2. [Apa Itu Judol Backdoor?](#apa-itu-judol-backdoor)
3. [Struktur File Aturan](#struktur-file-aturan)
4. [Daftar Aturan dan Penjelasan](#daftar-aturan-dan-penjelasan)
5. [Cara Penggunaan](#cara-penggunaan)
6. [Kalibrasi Threshold dan Skor](#kalibrasi-threshold-dan-skor)
7. [Menangani False Positive](#menangani-false-positive)
8. [Peta Teknik Serangan](#peta-teknik-serangan)
9. [Pemeliharaan dan Pembaruan](#pemeliharaan-dan-pembaruan)
10. [Keterbatasan](#keterbatasan)

---

## Latar Belakang

Judi Online (dikenal luas sebagai "judol" di Indonesia) merupakan ancaman siber yang unik karena pelakunya tidak hanya membangun situs judi sendiri, tetapi secara aktif meretas website yang sah, terutama milik instansi Pemerintah, Sekolah, dan Organisasi Publik, untuk dijadikan instrumen manipulasi pada mesin pencari (google/yahoo/bing/etc).

Mengapa domain .go.id, .sch.id, dan .ac.id yang jadi target? Sederhana, mesin pencari seperti Google memberikan kepercayaan (domain authority) yang lebih tinggi kepada domain-domain ini dibanding domain komersial biasa. Ketika halaman judi online di indeks via domain Pemerintah, peringkat pencarian naik secara signifikan.

Fenomena ini menimbulkan dua masalah sekaligus:
1. Reputasi instansi Pemerintah/Publik tercoreng karena halaman web mereka menampilkan konten judi
2. Keberadaan backdoor pada server Pemerintah membuka pintu untuk ancaman yang jauh lebih serius

Ruleset yara ini dikembangkan berdasarkan analisis pada sampel-sampel file yang ditemukan dalam insiden judol yang di temukan dan diamati.

---

## Apa Itu Judol Backdoor?

Tidak seperti ransomware atau pencurian data konvensional, judol backdoor bekerja dengan cara yang lebih halus:

```
[Pelaku] --> [Eksploitasi celah] --> [Tanam Backdoor] --> [Injeksi konten judi/judol]
                                                                    |
                                          +--------------------------+
                                          |
                              +-----------|--------+     +------------------+
                              |  Teknik yang digunakan  |
                              +------------------+     
                              | 1. Keyword stuffing      |
                              | 2. Hidden links          |
                              | 3. Meta tag injection    |
                              | 4. Cloaking (UA-based)   |
                              | 5. .htaccess redirect    |
                              | 6. iframe tersembunyi    |
                              +------------------+
```

**Alur serangan yang paling umum:**

1. **Initial Access**: Eksploitasi celah di WordPress (plugin outdated, tema rentan, credential default)
2. **Persistence**: Upload file php backdoor atau modifikasi file functions.php
3. **SEO Manipulation**: Injeksi konten judi melalui berbagai teknik (lihat di atas)
4. **Monetization**: Setiap klik dari hasil pencarian Google menghasilkan komisi afiliasi pada pelakunya

Backdoor judol yang baik (dari perspektif pelaku) melakukan hal berikut secara bersamaan:
- Menampilkan konten judi ke crawler Google tapi bukan ke pengunjung manusia (bot cloaking)
- Menyembunyikan dirinya dari administrator website (misalnya tidak tampil di daftar plugin)
- Mempertahankan akses (persistance) meski plugin/tema diupdate

---

## Struktur File Aturan

```
/home/hunters/yara-rules-dev/
├── judol_keywords_.yar          # Deteksi kata kunci konten judi
├── judol_php_backdoor_.yar         # Deteksi PHP backdoor judol
├── judol_blackseo_inject_.yar      # Deteksi injeksi Black SEO
├── judol_wordpress_hack_.yar       # Deteksi kompromi WordPress
├── judol_javascript_inject_.yar    # Deteksi injeksi JavaScript
├── JUDOL_YARA_RULES.md             # Dokumentasi ini
└── LICENSE                         # Lisensi penggunaan
```

---

## Daftar Aturan dan Penjelasan

### File: `judol_keywords_.yar`

Mendeteksi konten judi berdasarkan kata kunci spesifik bahasa Indonesia yang tidak ditemukan dalam konteks yang sah.

| Nama Aturan | Threshold | Skor | Keterangan |
|---|---|---|---|
| `Judol_1` | 4 dari 17 string | 70 | Kata kunci slot gambling |
| `Judol_2` | 2 dari 15 string | 75 | Kata kunci togel/lotere ilegal |
| `Judol_3` | 3 dari 15 string | 65 | Kata kunci kasino dan poker online |
| `Judol_4` | 2 provider + 1 action | 60 | Provider + kata tindakan judi |
| `Judol_5` | 2 dari 15 string | 75 | Metode deposit + promosi spesifik |
| `Judol_6` | 6 dari 12 string, file < 100KB | 80 | Keyword stuffing |

**Catatan tentang threshold:** Aturan togel menggunakan threshold rendah (2 string) karena istilah seperti "bandar togel" dan "togel online" hampir tidak pernah muncul dalam konteks yang sah. Aturan slot membutuhkan lebih banyak string (4) karena beberapa istilah bisa muncul dalam ulasan game atau berita.

---

### File: `judol_php_backdoor_.yar`

Mendeteksi file php yang memiliki kemampuan backdoor dikombinasikan dengan injeksi konten judi.

| Nama Aturan | Skor | Keterangan |
|---|---|---|
| `Judol_PHP_Eval_Inject` | 85 | eval/base64/assert + konten judi |
| `Judol_PHP_Cloaking_Bot` | 90 | Cloaking User-Agent crawler + judi |
| `Judol_PHP_WP_OptionInject` | 90 | Manipulasi wp_options dengan judi |
| `Judol_PHP_Redirect_Domain` | 80 | Php header redirect ke domain judi |
| `Judol_PHP_Backdoor_Hidden_SEO` | 85 | Backdoor yang fetch + tampilkan konten tersembunyi |
| `Judol_PHP_Shell_Combo` | 95 | Webshell RCE + konten judi dalam satu file |

**Aturan dengan skor tertinggi (95):** `Judol_PHP_Shell_Combo` — Kombinasi kemampuan RCE (system, exec, shell_exec) dengan konten judi dalam satu file hampir mustahil terjadi secara legit.

---

### File: `judol_blackseo_inject_.yar`

Mendeteksi teknik Black SEO yang menyembunyikan konten judi dari pengunjung manusia tapi membuatnya terlihat oleh crawler mesin pencari (bot).

| Nama Aturan | Skor | Keterangan |
|---|---|---|
| `Judol_BlackSEO_Hidden_Links` | 85 | CSS hide + link judi tersembunyi |
| `Judol_BlackSEO_Meta_Inject` | 80 | Injeksi meta keywords/description |
| `Judol_BlackSEO_WhiteText` | 80 | Teks putih di atas latar putih |
| `Judol_Htaccess_Redirect` | 85 | .htaccess redirect ke domain judi |
| `Judol_BlackSEO_Hidden_Iframe` | 80 | Iframe tersembunyi (0x0 pixel) |
| `Judol_BlackSEO_AnchorText` | 75 | Anchor text judi dalam tag `<a>` |

---

### File: `judol_wordpress_.yar`

Mendeteksi pola kompromi yang spesifik pada instalasi WordPress, CMS yang paling banyak digunakan untuk keperluan judol.

| Nama Aturan | Skor | Keterangan |
|---|---|---|
| `Judol_WP_FakePlugin` | 85 | Plugin palsu berisi injeksi judol |
| `Judol_WP_ThemeInject` | 80 | Modifikasi file tema + injeksi |
| `Judol_WP_Action_Hook_Inject` | 85 | Hook WP (add_action/filter) + judi |
| `Judol_WP_PostDB_Inject` | 85 | Manipulasi database WP + konten judi |
| `Judol_WP_Admin_Backdoor` | 90 | Pembuatan admin tersembunyi + judi |
| `Judol_WP_Cloaking_Bypass` | 85 | Cloaking via fungsi WP conditional |

---

### File: `judol_javascript_inject_.yar`

Mendeteksi kode JavaScript yang digunakan untuk redirect, injeksi konten, atau cloaking berbasis browser dalam serangan judol.

| Nama Aturan | Skor | Keterangan |
|---|---|---|
| `Judol_JS_Redirect` | 80 | window.location redirect ke judol |
| `Judol_JS_ContentGen` | 80 | document.write/innerHTML + konten judi |
| `Judol_JS_Cloaking_UA` | 90 | navigator.userAgent cloaking + judi |
| `Judol_JS_RemoteLoad` | 80 | Fetch konten remote + konteks judi |
| `Judol_JS_Obfuscated_Payload` | 75 | JS terobfuskasi + kata kunci judi |

---

## Cara Penggunaan

### Persyaratan

Ruleset ini kompatibel dengan:
- **YARA 4.x** (minimum YARA 4.0)
- **YARA-X** (Rust-based, direkomendasikan untuk performa)

Install YARA-X:
```bash
# Via cargo (Rust)
git clone https://github.com/VirusTotal/yara-x 
cd yara-x
cargo install --path cli

# Via brew (macOS)
brew install yara-x
```

### Validasi Sintaks

Selalu validasi file aturan sebelum digunakan dalam produksi:

```bash
# YARA standar
yara --syntax-check judol_keywords_.yar
yara --syntax-check judol_php_backdoor_.yar

# YARA-X (rekomendasi)
yr check judol_keywords_.yar
yr check judol_php_backdoor_.yar
yr check judol_blackseo_inject_.yar
yr check judol_wordpress_.yar
yr check judol_javascript_inject_.yar
```

### Pemindaian File

```bash
# Yara
yara judol_php_backdoor_.yar /path/ke/file.php

# YARA-X dengan output
yr scan -s judol_php_backdoor_.yar /path/ke/file.php
```

### Pemindaian Direktori

```bash
# Yara — pindai seluruh direktori web
yara -r judol_php_backdoor_.yar /var/www/html/

# Gunakan semua file
yara -r judol_*.yar /var/www/html/

# YARA-X — pemindaian lebih cepat
yr scan -r judol_php_backdoor_.yar /var/www/html/
```

### Pemindaian dengan Output ke File

```bash
# Output hasil ke file
yara -r judol_*.yar /var/www/html/ > hasil_scan_judol_$(date +%Y%m%d).txt

# YARA-X dengan format NDJSON
yr scan --output-format ndjson -r judol_php_backdoor.yar /var/www/html/ \
  > hasil_scan_$(date +%Y%m%d).ndjson
```

### Integrasi dengan Wazuh SIEM

Untuk organisasi yang menggunakan Wazuh SIEM, yara rules ini dapat diintegrasikan melalui active response atau custom script:

```bash
# Script wrapper untuk Wazuh active response
#!/bin/bash
# /var/ossec/active-response/bin/scan_judol.sh

WEBROOT="/var/www/html"
YARA_RULES_DIR="/home/hunters/yara-rules-dev"
LOG_FILE="/var/ossec/logs/judol_scan.log"

/usr/bin/yara -r ${YARA_RULES_DIR}/judol_*.yar ${WEBROOT} >> ${LOG_FILE} 2>&1
```

### Automasi Pemindaian Berkala (via Cron)

```bash
# Tambahkan ke crontab untuk pemindaian harian
0 2 * * * /usr/bin/yara -r /home/hunters/yara-rules-dev/judol_*.yar \
  /var/www/html/ >> /var/log/judol_scan.log 2>&1
```

---

## Threshold dan Skor

### Interpretasi Skor

| Skor | Interpretasi | Tindakan yang Disarankan |
|---|---|---|
| 90-100 | Sangat mencurigakan, kemungkinan besar positif | Investigasi segera, isolasi file |
| 80-89 | Mencurigakan, perlu verifikasi manual | Tinjau file dalam 24 jam |
| 70-79 | Indikasi lemah, kemungkinan false positive lebih tinggi | Catat dan monitor |
| 60-69 | Kontekstual, butuh informasi tambahan | Gunakan sebagai petunjuk awal |

### Penyesuaian Konteks

Skor perlu disesuaikan berdasarkan konteks server yang dipindai:

- **Website pemerintah/sekolah**: Naikkan kepekaan. Website .go.id/.sch.id tidak seharusnya mengandung SATU PUN kata kunci judi/judol.
- **Website berita/media**: Potensi false positive lebih tinggi untuk aturan kata kunci (bisa memuat berita tentang judi). Fokus pada aturan backdoornya.
- **Repository kode/development**: Mungkin ada kode test yang mengandung kata kunci. Verifikasi konteksnya.

---

## False Positive Alarm

### Sumber False Positive yang Umum

1. **Artikel berita tentang judi**: Website media yang menulis berita tentang penggerebekan judol bisa memicu aturan kata kunci. **Solusi**: Verifikasi apakah kata kunci muncul dalam konteks jurnalistik (ada tag `<article>`, `<p>` biasa, bukan dalam `display:none` atau kode php).

2. **Akademik/penelitian**: Paper atau laporan tentang dampak judi online. **Solusi**: Periksa apakah file ada di direktori web aktif atau hanya arsip dokumen.

3. **Game review yang menyebut Pragmatic Play/PG Soft**: **Solusi**: Verifikasi apakah ada kata dan tindakan yang mengarah kepada aktivitas judi (deposit, daftar, link alternatif) bersama nama provider.

4. **Plugin WordPress legitimate**: Beberapa plugin pembayaran DANA/GoPay mungkin memicu rulesnya. **Solusi**: Verifikasi konteks, apakah "deposit dana" muncul dalam konteks e-commerce atau kegiatan judi.

### Prosedur Verifikasi

Ketika aturan terpicu, lakukan langkah-langkah berikut:

```bash
# 1. Identifikasi string yang memicu aturan
yr scan -s judol_blackseo_inject_.yar file_tersangka.php

# 2. Lihat konteks pada string
grep -n -A 5 -B 5 "slot gacor" file_tersangka.php

# 3. Cek waktu modifikasi file
stat file_tersangka.php

# 4. Bandingkan dengan backup (jika ada)
diff file_tersangka.php /backup/file_asli.php

# 5. Cek kepemilikan file
ls -la file_tersangka.php
```

### Melaporkan False Positive

Jika menemukan false positive, segera laporkan ke:
- Email: csirt@tangerangkota.go.id
- Sertakan: nama file aturan, string yang memicu, dan konteks file

---

## Peta Teknik Serangan

Aturan dalam ruleset ini memetakan ke teknik MITRE ATT&CK berikut (dalam konteks website compromise):

| Aturan | Teknik MITRE | ID |
|---|---|---|
| PHP Eval Backdoor | Command and Scripting Interpreter: PHP | T1059.005 |
| Cloaking User-Agent | Defense Evasion: Masquerading | T1036 |
| Hidden SEO Content | Defense Evasion: Hidden Files and Directories | T1564 |
| WP Option Injection | Persistence: Web Shell | T1505.003 |
| .htaccess Redirect | Defense Evasion: Traffic Signaling | T1205 |
| JS Remote Load | Command and Scripting Interpreter: JavaScript | T1059.007 |
| Fake Plugin | Persistence: Web Shell | T1505.003 |
| Admin Backdoor | Persistence: Account Manipulation | T1098 |
| Meta Tag Injection | Impact: Defacement | T1491.001 |

---

## Pemeliharaan dan Pembaruan

### Pola yang Perlu Dipantau untuk Update Rutin

Pelaku judol terus mengembangkan teknik mereka. Perhatikan pola baru berikut yang perlu ditambahkan ke dalam ruleset:

1. **Nama game baru**: Pragmatic Play dan provider lain rutin merilis game baru yang digunakan dalam konten judol. Pantau nama game baru yang viral di komunitas.

2. **Domain/subdomain baru**: Operator judol sering mengganti domain. Nama domain bisa menjadi indikator tambahan.

3. **Teknik obfuskasi baru**: Pelaku terus memperbarui metode obfuskasi PHP/JS untuk menghindari deteksi.

4. **CMS baru**: Selain WordPress, juga terdapat serangan ke cms Joomla, Drupal, dan CMS Lainnya (CI/Laravel/etc).

5. **Kata kunci baru**: Istilah slang judi online berkembang. Pantau platform seperti Telegram dan media sosial untuk istilah baru.

### Jadwal Review

Disarankan untuk melakukan review dan update ruleset ini secara berkala:
- **Bulanan**: Tambah nama game/provider baru
- **Kuartalan**: Tambah teknik baru yang ditemukan
- **Setahun sekali**: Review ulang semua aturan untuk relevansi dan tingkat akurasi

---

## Keterbatasan

Ruleset ini memiliki beberapa keterbatasan yang perlu dipahami:

1. **Tidak mendeteksi payload terenkripsi penuh**: Backdoor yang sepenuhnya terenkripsi (misalnya konten judi tersimpan di database terenkripsi dan hanya didekripsi saat runtime) tidak akan terdeteksi oleh aturan string based.

2. **Tidak mendeteksi teknik steganografi**: Konten judi yang disembunyikan dalam gambar atau file media tidak tercakup.

3. **Bukan pengganti analisis manual/re**: Aturan ini adalah alat bantu triase, bukan pengganti investigasi forensik atau reverse engineering (re).

4. **Potensi false negative untuk domain judi**: Aturan tidak mendeteksi berdasarkan domain/IP server judi, karena daftar domain dapat berubah-ubah. Untuk deteksi berbasis domain, gunakan threat intelligence feed yang diperbarui secara real-time.

5. **Tidak mencakup insiden database compromise**: Injeksi langsung ke tabel database MySQL/MariaDB/Postgre/etc, tidak dapat dideteksi dengan yara.

---

*Dikembangkan oleh TangerangKota-CSIRT. Seluruh aturan dirancang untuk penggunaan defensif dan respons insiden. Untuk pertanyaan teknis, hubungi csirt@tangerangkota.go.id.*
