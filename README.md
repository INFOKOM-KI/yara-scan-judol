# YARA Rules — Deteksi Judi Online (Judol) Indonesia

Kumpulan Yara rules untuk mendeteksi konten judi online, backdoor judol, dan teknik Black SEO yang menarget website Indonesia.

**Penulis:** Nauliajati &lt;csirt@tangerangkota.go.id&gt;  
**Organisasi:** TangerangKota-CSIRT  
**Versi:** 1.0 | **Tanggal:** 2026-05-06  
**Lisensi:** [TangerangKota-CSIRT Detection Rule License 1.0](LICENSE)

---

## Latar Belakang

Website pemerintah, sekolah, dan institusi publik Indonesia menjadi sasaran utama aktivitas illegal judol. Pelakunya tidak sekadar membangun situs judi sendiri, mereka meretas website resmi Pemerintah, sekolah, dan organisasi lainnya, lalu menyuntikkan konten judi secara tersembunyi untuk kebutuhan promosi pada mesin pencari (SEO).

Ruleset ini dikembangkan dari pengamatan langsung pola serangan dan dirancang untuk membantu tim CSIRT, pengelola server, dan analis keamanan dalam mendeteksi aktivitas semacam ini secara cepat & tepat.

---

## Struktur Ruleset

```
yara-rules-dev/
├── judol_keywords_.yar          # Deteksi kata kunci konten judi (6 aturan)
├── judol_php_backdoor_.yar      # Deteksi PHP backdoor judol (6 aturan)
├── judol_blackseo_inject_.yar   # Deteksi injeksi Black SEO (6 aturan)
├── judol_wordpress_.yar         # Deteksi kompromi WordPress (6 aturan)
├── judol_javascript_inject_.yar # Deteksi injeksi JavaScript (5 aturan)
├── JUDOL_YARA_RULES.md          # Dokumentasi teknis lengkap
├── LICENSE                      # Lisensi penggunaan
└── README.md                    # File ini
```

---

## Apa yang Dideteksi

### 1. Kata Kunci Konten Judi (`judol_keywords_.yar`)

Mendeteksi kata kunci judol dalam file web. Kata-kata ini tidak pernah muncul dalam konteks yang sah di website Pemerintah atau publik.

| Aturan | Threshold | Skor |
|---|---|---|
| `Judol_1` | 4 dari 17 kata kunci slot | 70 |
| `Judol_2` | 2 dari 15 kata kunci togel | 75 |
| `Judol_3` | 3 dari 15 kata kunci kasino | 65 |
| `Judol_4` | 2 provider + 1 kata tindakan | 60 |
| `Judol_5` | 2 dari 15 term deposit/promo | 75 |
| `Judol_6` | 6 kata kunci dalam file < 100KB | 80 |

Mencakup: `slot gacor`, `bocoran rtp`, `bandar togel`, `togel online`, `deposit pulsa`, `bonus new member`, `pragmatic play`, `mahjong ways`, `gates of olympus`, dan term lainnya.

---

### 2. PHP Backdoor Judol (`judol_php_backdoor_.yar`)

Mendeteksi file PHP yang punya kemampuan shell atau injeksi, sekaligus mengandung konten judi.

| Aturan | Skor | Yang Dideteksi |
|---|---|---|
| `Judol_PHP_Eval_Inject` | 85 | `eval()` / `base64_decode()` + kata kunci judi |
| `Judol_PHP_Cloaking_Bot` | 90 | Cek User-Agent Googlebot + konten/redirect judi |
| `Judol_PHP_WP_OptionInject` | 90 | `update_option()` WordPress + metadata judi |
| `Judol_PHP_Redirect_Domain` | 80 | `header("Location:")` + domain/kata kunci judi |
| `Judol_PHP_Backdoor_Hidden_SEO` | 85 | Fetch konten remote + hidden div berisi judi |
| `Judol_PHP_Shell_Combo` | 95 | RCE (`system`, `exec`) + konten judi |

---

### 3. Black SEO Injection (`judol_blackseo_inject_.yar`)

Mendeteksi teknik penyembunyian konten judol agar terlihat oleh mesin pencari (SEO).

| Aturan | Skor | Yang Dideteksi |
|---|---|---|
| `Judol_BlackSEO_Hidden_Links` | 85 | `display:none` / `visibility:hidden` + link judi |
| `Judol_BlackSEO_Meta_Inject` | 80 | Meta keywords/description diisi kata kunci judi |
| `Judol_BlackSEO_WhiteText` | 80 | Teks warna putih Inject |
| `Judol_Htaccess_Redirect` | 85 | `RewriteRule` .htaccess ke domain judi |
| `Judol_BlackSEO_Hidden_Iframe` | 80 | Iframe ukuran 0x0 pixel mengarah ke judol |
| `Judol_BlackSEO_AnchorText` | 75 | Tag `<a>` dengan anchor text kata kunci judi |

---

### 4. Kompromi WordPress (`judol_wordpress_.yar`)

WordPress adalah CMS yang paling sering dikompromikan untuk judol. Ruleset ini mendeteksi pola yang spesifik terhadap ekosistem WordPress.

| Aturan | Skor | Yang Dideteksi |
|---|---|---|
| `Judol_WP_FakePlugin_2025` | 85 | Plugin palsu dengan header WP + kode injeksi judol |
| `Judol_WP_ThemeInject` | 80 | functions.php / tema dimodifikasi + konten judol |
| `Judol_WP_Action_Hook_Inject` | 85 | `add_action()` / `add_filter()` + konten judol |
| `Judol_WP_PostDB_Inject` | 85 | `wp_insert_post()` / `wpdb->query()` + konten judol |
| `Judol_WP_Admin_Backdoor` | 90 | Pembuatan akun admin tersembunyi + konteks judol |
| `Judol_WP_Cloaking_Bypass` | 85 | `is_user_logged_in()` + konten judol tersembunyi |

---

### 5. Injeksi JavaScript (`judol_javascript_inject_.yar`)

Mendeteksi kode JavaScript yang digunakan untuk redirect, generate konten dinamis, atau cloaking SEO berbasis browser.

| Aturan | Skor | Yang Dideteksi |
|---|---|---|
| `Judol_JS_Redirect` | 80 | `window.location` redirect ke domain/kata kunci judol |
| `Judol_JS_ContentGen` | 80 | `document.write()` / `innerHTML` + konten judol |
| `Judol_JS_Cloaking_UA` | 90 | `navigator.userAgent` check Googlebot + konten judol |
| `Judol_JS_RemoteLoad` | 80 | `fetch()` / `XMLHttpRequest` + konteks judol |
| `Judol_JS_Obfuscated_Payload` | 75 | `eval(atob())` / `fromCharCode()` + kata kunci judol |

---

## Cara Penggunaan

### Prasyarat

```bash
# Install Yara
apt install yara                    # Debian/Ubuntu
yum install yara                    # CentOS/RHEL
brew install yara                   # macOS

# Yara-X (recommended)
git clone https://github.com/VirusTotal/yara-x 
cd yara-x
cargo install --path cli
```

### Validasi Sintaks

```bash
# Yara
yara --syntax-check *.yar

# YARA-X
yr check *.yar
```

### Pindai Satu File

```bash
yara -r *.yar /var/www/html/wp-content/plugins/plugin-xxx/a.php
```

### Pindai Seluruh Direktori Web

```bash
# Semua aturan sekaligus, rekursif
yara -r *.yar /var/www/html/

# Tampilkan string yang memicu (untuk triase)
yara -rs *.yar /var/www/html/
```

### Simpan Hasil ke File

```bash
yara -r *.yar /var/www/html/ > hasil_scan_$(date +%Y%m%d).txt
```

### Pindai Hanya File PHP

```bash
find /var/www/html -name "*.php" -exec yara judol_php_backdoor_.yar {} \;
```

### Automasi via Cron

```bash
# Tambahkan ke crontab (crontab -e)
0 2 * * * yara -r /home/auli/yara-rules-dev/*.yar /var/www/html/ \
  >> /var/log/hasil_judol_scan.log 2>&1
```

---

## Interpretasi Skor

| Skor | Interpretasi | Tindakan |
|---|---|---|
| **90–95** | Hampir pasti terkompromi | Isolasi segera, investigasi forensik |
| **80–89** | Sangat mencurigakan | Verifikasi manual dalam waktu 24 jam |
| **70–79** | Mencurigakan, perlu konteks | Tinjau file, dan periksa histori modifikasi |
| **60–69** | Indikasi awal | Catat, monitor, dan jadikan bukti petunjuk |

---

## Menangani False Positive

Sumber false positive yang paling umum:

- **Artikel berita** yang melaporkan penggerebekan judol, biasanya memicu aturan keyword, bukan aturan teknis yaranya
- **Plugin pembayaran** yang menyebut DANA/GoPay, periksa apakah dalam konteks e-commerce atau judol
- **Review game** yang menyebut Pragmatic Play/PG Soft, cek apakah ada kata tindakan dari judol (daftar, deposit, link alternatif)

Cara verifikasi cepat:

```bash
# Lihat string mana yang memicu dan konteksnya
yara -s judol_keywords_.yar xxx.html

# Cek waktu terakhir file dimodifikasi
stat xxx.php

# Bandingkan dengan backup
diff xxx.php /backup/xxx.php
```

Laporkan false positive ke csirt@tangerangkota.go.id agar ruleset terus diperbaiki.

---

## Teknik TTP (MITRE ATT&CK)

| Teknik | ID MITRE | Aturan Terkait |
|---|---|---|
| PHP Command Execution | T1059.005 | `PHP_Eval_Inject`, `PHP_Shell_Combo` |
| JavaScript Execution | T1059.007 | `JS_Redirect`, `JS_ContentGen` |
| Masquerading (Cloaking) | T1036 | `PHP_Cloaking_Bot`, `JS_Cloaking_UA` |
| Web Shell | T1505.003 | `WP_FakePlugin`, `WP_ThemeInject` |
| Defacement | T1491.001 | `BlackSEO_Meta_Inject`, `AnchorText` |
| Account Manipulation | T1098 | `WP_Admin_Backdoor` |
| Traffic Signaling | T1205 | `Htaccess_Redirect` |
| Hidden Files | T1564 | `BlackSEO_Hidden_Links`, `WhiteText` |

---

## Keterbatasan

- Tidak mendeteksi payload terenkripsi penuh yang didekripsi saat runtime
- Tidak mencakup injeksi langsung ke database (MySQL/MariaDB)
- Tidak berbasis reputasi domain, untuk blocklist domain judi, gunakan threat intel feed terpisah
- Konten dalam gambar/file media belum terdeteksi (akan di update soon)

Untuk dokumentasi teknis lengkap termasuk alur serangan judol, MITRE mapping detail, dan panduan integrasi SIEM, lihat [JUDOL_YARA_RULES.md](JUDOL_YARA_RULES.md).

---

## Lisensi dan Atribusi

Ruleset ini dikembangkan oleh **Nauliajati, TangerangKota-CSIRT** dan dilisensikan di bawah [TangerangKota-CSIRT Detection Rule License 1.0](LICENSE). Bebas digunakan untuk keperluan defensif dengan atribusi yang sesuai.

Untuk pertanyaan teknis, kontribusi, atau pelaporan false positive:  
**csirt@tangerangkota.go.id**
