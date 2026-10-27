# AgentPreflight

[![CI](https://github.com/lunarjjo/agentpreflight/actions/workflows/ci.yml/badge.svg)](https://github.com/lunarjjo/agentpreflight/actions/workflows/ci.yml)
[![Self-scan](https://github.com/lunarjjo/agentpreflight/actions/workflows/self-scan.yml/badge.svg)](https://github.com/lunarjjo/agentpreflight/actions/workflows/self-scan.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Lisensi: MIT](https://img.shields.io/badge/lisensi-MIT-green)](LICENSE)
[![Tanpa dependensi](https://img.shields.io/badge/dependensi-0-success)](pyproject.toml)

**Pemindai keamanan repositori lokal-first dan kesiapan pra-rilis.** AgentPreflight menemukan secret yang terekspos, artefak sensitif, konfigurasi bawaan yang tidak aman, dan risiko higiene supply-chain **sebelum** Anda mempublikasikan, mendeploy, atau merilis — sepenuhnya offline, dengan output yang ter-redaksi, dan **tanpa dependensi runtime**.

<div align="center">

<sub>🌐 <a href="README.md">English</a> · **Bahasa Indonesia**</sub>

</div>

---

## Mengapa ada pemindai lagi?

AgentPreflight bukan mesin deteksi secret baru, dan tidak mencoba menggantikan SAST Anda. Ini adalah **gerbang kesiapan pra-rilis** yang belum tercakup oleh tool lain — satu perintah cepat, offline, dan privat yang menjawab: *"apakah repositori ini aman dirilis sekarang?"*

- **Gitleaks / TruffleHog** memindai secret (TruffleHog memverifikasinya lewat panggilan jaringan). Keduanya tidak menilai artefak, default tidak aman, atau keamanan CI; Gitleaks kini berstatus "feature complete" (hanya perbaikan keamanan).
- **Semgrep** melakukan analisis taint mendalam — tetapi versi OSS-nya terbatas pada satu file, dan menulis rule memerlukan keahlian khusus.
- **OSV-Scanner / Trivy / Dependabot** menjawab "apakah dependensi saya rentan?" — tetapi hanya dengan akses jaringan dan unduhan database.
- **Repolinter** (higiene repositori) sudah diarsipkan.

Tidak ada tool yang menggabungkan deteksi secret + artefak sensitif + default tidak aman + keamanan CI + higiene repositori dalam satu gerbang **offline**. Itulah cakupan AgentPreflight — lihat [perbandingan lengkap](docs/comparison.md) beserta sumber terverifikasinya.

**Di luar cakupan, secara sadar:** pencarian advisory kerentanan (pakai OSV-Scanner/Trivy), analisis taint mendalam (pakai Semgrep), dan verifikasi "apakah secret ini masih aktif?" (pakai TruffleHog, yang melakukan panggilan API).

## Apa yang dideteksi (47 rule)

| Kategori | Contoh | Jumlah |
|---|---|---|
| **Secret** (`APF-SEC-*`) | Token AWS/GitHub/Slack/Stripe/OpenAI/GitLab/npm/PyPI/SendGrid/Telegram/Shopify/Azure/Square/Meta, private key, JWT, URL dengan kredensial, assignment generik ber-entropi tinggi | 20 |
| **Artefak** (`APF-ART-*`) | File `.env`, private key/keystore, `.netrc`/`.aws/credentials`/`.docker/config.json`, dump SQL, `.DS_Store`, direktori `node_modules`/IDE yang ter-commit | 8 |
| **Default tidak aman** (`APF-DEF-*`) | Django `DEBUG=True`, `verify=False`, bypass SSL, CORS `*`, password lemah/bawaan, Ansible `host_key_checking=False`, Dockerfile berjalan sebagai root, pengaturan Kubernetes berbahaya, MD5/SHA-1, JWT `none` | 12 |
| **Supply chain** (`APF-DEP-*`) | curl-to-shell pipelines, requirements tanpa pin, `pull_request_target` + checkout PR (celah kritis CI), `permissions: write-all`, Action tanpa pin SHA, lockfile hilang, hook instalasi npm | 7 |

Model severity: `critical` / `high` / `medium` / `low` / `info` — kriterianya didokumentasikan di [docs/rules.md](docs/rules.md). Katalog lengkap: `agentpreflight rules list`.

## Instalasi

**Persyaratan:** Python 3.10+ (3.11+ memakai TOML bawaan stdlib; 3.10 memakai parser fallback internal). Tidak ada dependensi lain.

```bash
# dari repositori (disarankan hingga rilis bertag pertama)
python -m pip install "git+https://github.com/lunarjjo/agentpreflight"

# atau dari checkout
python -m pip install .
```

Verifikasi:

```bash
agentpreflight version
agentpreflight doctor
```

## Mulai cepat

```bash
agentpreflight scan .                     # pindai working tree
agentpreflight scan . --history           # + seluruh riwayat git (termasuk secret yang sudah dihapus)
agentpreflight scan . --format json       # output terstruktur untuk otomasi
agentpreflight scan . --format sarif      # SARIF 2.1.0 untuk code scanning
agentpreflight init                       # tulis .agentpreflight.toml
agentpreflight rules list                 # katalog semua rule
agentpreflight rules explain APF-SEC-007  # detail satu rule
agentpreflight doctor                     # diagnostik lingkungan + self-test
```

Contoh output (nilai secret selalu di-redaksi):

```
AgentPreflight 0.1.0 — memindai /proyek

CRITICAL APF-SEC-007  config/server.pem:1
         Private key material detected
           [REDACTED:ssh_private_key]

HIGH     APF-SEC-009  .env:1
         URL with embedded credentials detected
         value: post…8b0111bc (redacted)
           DB_URL=****REDACTED****

────────────────────────────────────────────────────────────────────────
  1 critical · 1 high
  42 file dipindai · 0 dilewati (ukuran) · 0.4s

  temuan setara atau di atas HIGH — gagal (exit 1)
```

### Kode keluar (exit code)

| Kode | Arti |
|---|---|
| 0 | tidak ada temuan pada/melayangi ambang kegagalan |
| 1 | ada temuan pada/melayangi ambang kegagalan (bawaan: `high`) |
| 2 | kesalahan operasional (path tidak terbaca, pemindaian parsial) |
| 3 | kesalahan penggunaan atau konfigurasi |
| 130 | dibatalkan (interrupt) |

### Menangani false positive

Inline (disarankan untuk contoh dokumentasi):

```python
api_key = "AKIAIOSFODNN7EXAMPLE"  # agentpreflight: allow
```

Atau supresi terdokumentasi dengan masa kedaluwarsa di `.agentpreflight.toml`:

```toml
[[ignore]]
path = "tests/fixtures/**"
rule_id = "APF-SEC-*"
reason = "Secret sintetis sebagai fixture pengujian"
expires = "2027-12-31"
```

Menyupresi **semua** rule untuk sebuah path memerlukan `allow_all = true` eksplisit — supresi menyeluruh tidak pernah terjadi diam-diam. Lihat [docs/configuration.md](docs/configuration.md) (EN) dan [docs/false-positives.md](docs/false-positives.md) (EN).

## Pakai di CI (GitHub Actions)

```yaml
- name: AgentPreflight
  uses: lunarjjo/agentpreflight@main  # pin ke tag/SHA setelah v0.1.0 dirilis
  with:
    fail-severity: high
    sarif: agentpreflight.sarif

- uses: github/codeql-action/upload-sarif@v3.28.15
  if: always()
  with:
    sarif_file: agentpreflight.sarif
```

Input: `path`, `fail-severity`, `severity`, `history`, `sarif`, `exclude-rules`. Output: `findings-count`, `exit-code`. Referensi lengkap di [docs/ci-cd.md](docs/ci-cd.md) (EN) — repositori ini memindai dirinya sendiri dengan action ini di setiap push.

## Model keamanan & privasi

- **Lokal-first.** Pemindaian biasa tidak pernah menyentuh jaringan — tanpa telemetri, tanpa API key, tanpa upload. Tidak ada fitur bergantung-jaringan pada v0.1.0.
- **Redaksi tidak bersyarat.** Nilai yang terdeteksi tidak pernah muncul di output terminal, JSON, maupun SARIF — hanya prefiks pendek + fingerprint (`AKIA…1a5d44a2`) untuk triase.
- **Penanganan input tidak tepercaya.** Isi repositori diperlakukan sebagai musuh: symlink tidak pernah diikuti, path index divalidasi terhadap traversal, anggaran file/jumlah dipatuhi, escape sequence terminal disanitasi, dan rule yang crash menurun menjadi temuan informasional "please report", bukan pemindaian yang gagal.
- **Pemindai tidak pernah mengeksekusi kode yang dipindai** dan tidak pernah mengubah file Anda.

Model lengkap: [docs/security-model.md](docs/security-model.md) (EN) · Laporkan kerentanan: [SECURITY.md](SECURITY.md) (EN).

## Dokumentasi

Dokumentasi teknis lengkap berbahasa Inggris (kanonis) di direktori [docs/](docs/). Panduan memulai berbahasa Indonesia:

| Topik | |
|---|---|
| Perbandingan dengan tool lain | [docs/comparison.md](docs/comparison.md) |
| Katalog rule (otomatis-dihasilkan) | [docs/rules.md](docs/rules.md) |
| Matriks bahasa yang didukung | [docs/supported-languages.md](docs/supported-languages.md) |
| Referensi konfigurasi | [docs/configuration.md](docs/configuration.md) |
| Referensi CLI | [docs/cli.md](docs/cli.md) |
| Integrasi CI/CD | [docs/ci-cd.md](docs/ci-cd.md) |
| Arsitektur | [docs/architecture.md](docs/architecture.md) |
| Roadmap | [ROADMAP.md](ROADMAP.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Berkontribusi

Issue dan pull request sangat diterima — termasuk rule baru, yang mengikuti [pola terdokumentasi ~50 baris](CONTRIBUTING.md#writing-a-new-rule). Baca [CONTRIBUTING.md](CONTRIBUTING.md) (EN) untuk panduan menulis rule, setup pengembangan, dan ekspektasi review. Semua kontribusi terikat [Code of Conduct](CODE_OF_CONDUCT.md) (EN).

## Keterbatasan (yang jujur)

- Deteksi secret bersifat **struktural + heuristik**. Tidak dapat memverifikasi apakah kredensial masih aktif (tugas TruffleHog) dan tidak menangkap semua format kustom. Rule generik (APF-SEC-020) menukar recall demi presisi.
- Pemindaian riwayat git memerlukan binary `git` dan dibatasi `max_commits` / anggaran memori; riwayat sangat besar terpotong dengan peringatan.
- Deteksi berbasis regex bisa menghasilkan false positive pada dokumentasi yang mirip penggunaan nyata — untuk itulah ada allow marker dan ignore terdokumentasi.
- *Pengenalan* bahasa mencakup 50+ ekosistem; **pemeriksaan** spesifik-ekosistem saat ini tersedia untuk Python, JavaScript/TypeScript, Docker, Kubernetes/Helm, GitHub Actions, GitLab CI, dan Ansible. Sisanya bergantung pada rule language-agnostic. [Matriks kapabilitas](docs/supported-languages.md) jujur per ekosistem.

## Lisensi

[MIT](LICENSE) © 2026 Lunar.JJO · Pemberitahuan pihak ketiga: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
