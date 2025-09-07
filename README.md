# OPSEC Recon Suite

Small, fast Bash utilities to **install** a lean recon toolkit & **deploy** an end‑to‑end, one‑command OPSEC recon against a target domain, saving a timestamped txt report.

> **Why?** Many distros ship without a practical security recon stack by default, or come bloated. This repo gives you a clean, predictable install path & a portable deploy script you can run anywhere.

## Contents

- `scripts/opsecsuite.sh` — idempotent installer for a minimal recon stack (Ubuntu/Debian family). Installs: curl, git, jq, unzip, Python 3 + pip, Go, nmap, whatweb, nikto, gobuster (via Go), httpx (via Go), dirsearch (pip), SecLists clone
- `scripts/opsecdeploy.sh` — target recon runner with live spinner, timeouts, timestamps & tidy output. Produces `{target}_opsec_YYYY-MM-DD_HHMMSS.txt`
- `examples/` — usage examples & placeholder for sample reports (e.g., `github.com` report)

## Quickstart

```bash
# 1) Install the suite (Ubuntu/Mint/Debian)
bash scripts/opsecsuite.sh

# start a new shell to pick up PATH updates, or:
source ~/.bashrc

# 2) Run a recon report
bash scripts/opsecdeploy.sh github.com
# → writes ./github.com_opsec_YYYY-MM-DD_HHMMSS.txt
```

> **Note:** The deploy script will try to install missing system deps with `apt` if needed. On non‑Debian systems, install equivalents manually before use.

## Features

- Live ASCII spinner & per‑step durations with `tee`’d clean logs
- Safe timeouts for long steps (nmap/httpx/curl/openssl)
- TLS quick & deep checks (cipher enum, cert issuer/subject/SAN, expiry days)
- HTTP(S) headers & key security headers presence
- WHOIS, DNS basics (A/AAAA/MX/TXT/NS) & DNSSEC DS signal
- Technology fingerprint via whatweb
- robots.txt & sitemap.xml sampling
- Common subdomain probe (best‑effort, never fails overall)
- nmap web scripts on 80/443, full TCP sweep, optional UDP top‑50 (root only)
- Email posture: MX resolve, SMTP banner checks, STARTTLS cert peek
- DMARC & DKIM TXT lookups

## Example: `github.com`

Documentation includes an example showing how to generate an OPSEC report for `github.com`. See [`examples/README.md`](examples/README.md). A placeholder file is included so you can keep your repo clean & add a real report when convenient.

## Output

- Human‑readable `.txt` with clear section headers, timestamps & durations
- Example filename: `github.com_opsec_2025-09-01_213011.txt`

## Templating & Path Hygiene

- Scripts avoid personal paths by using `$HOME` & `$PATH`
- Go & pip user installs go into `$HOME/go/bin` & `$HOME/.local/bin`
- SecLists cloned to `$HOME/SecLists` & symlinked at `$HOME/wordlists/SecLists`
- No user‑specific values are embedded; adjust tunables at the top of the scripts if you need different timeouts or paths

## OS Support

- **Primary:** Ubuntu, Linux Mint, Debian
- **Others:** Arch/Fedora/etc. are possible, but `opsecdeploy.sh` will not auto‑install deps. Ensure `nmap`, `curl`, `dig`, `whatweb`, `whois`, `openssl`, `nc` are present

## Legal & Ethics

Only run recon against systems you own or are explicitly authorized to test. Scans may trigger alerts. Use responsibly & comply with local law & your engagement rules.

## Contributing

PRs welcome: tidy flags, extra steps behind opt‑ins, better parsers, or portability improvements are great additions.

## License

MIT
