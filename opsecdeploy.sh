#!/usr/bin/env bash
# ============================================================================
# OPSEC Recon Suite — Deploy
# Repo: https://github.com/<your-user>/opsec-recon-suite (replace before publish)
# Purpose: Run a fast, end-to-end OPSEC recon against a domain & save a txt report.
# Usage:
#   bash scripts/opsecdeploy.sh <domain-or-url>
# Notes:
#   • Auto-installs minimal deps via apt when available
#   • Uses conservative timeouts; steps never block the whole run
#   • Output file: <target>_opsec_YYYY-MM-DD_HHMMSS.txt in CWD
#   • Run as root to enable SYN scan & UDP top-50
# ============================================================================
# OPSEC quick deploy: live progress (ASCII), timestamps, durations, timeouts & clean output

set -Eeuo pipefail
export LC_ALL=C LANG=C

usage() {
  cat <<'USAGE'
Usage: ./opsecdeploy.sh <domain-or-url>

Does:
- Installs missing deps via apt (whois, nmap, curl, dig/dnsutils, whatweb, openssl, netcat)
- DNS, WHOIS, HTTP headers, security headers, TLS (fast & deep), cert details & expiry days
- Tech fingerprint, robots, sitemap, light subdomain probe (never fails overall)
- nmap web scripts on 80/443, full TCP sweep (SYN if root, connect if not), optional UDP top-50 (sudo)
- MX posture, STARTTLS peek, DMARC & DKIM checks, DNSSEC signal
- Live ASCII spinner (stderr) with timestamps & durations
- Streams output to terminal & writes a timestamped report
USAGE
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${#}" -lt 1 ]] && { usage; exit 0; }

# ---------- tunables (timeouts in seconds) ----------
CURL_T=45          # each curl
WHATWEB_T=45       # whatweb time budget (used if supported)
NMAP_WEB_T=900     # nmap http scripts
NMAP_TLS_T=600     # nmap tls scripts
NMAP_FULL_T=2700   # full tcp sweep
UDP_T=900          # udp sweep

# ---------- utils ----------
SPIN_FRAMES=( "|" "/" "-" "\\" )   # ASCII-only
SPIN_PID=""
SPIN_TITLE=""
SPIN_T0=0

is_tty() { [[ -t 1 ]]; }
now_iso() { date -Is; }
log() { printf "%s\n" "$*" | tee -a "$out"; }
hr()  { printf -- "----------------------------------------------------------------\n" | tee -a "$out"; }

spinner_start() {
  SPIN_TITLE="$1"
  SPIN_T0=$(date +%s)
  [[ ! -t 1 ]] && { SPIN_PID=""; return 0; }
  (
    i=0
    while :; do
      frame="${SPIN_FRAMES[$(( i % ${#SPIN_FRAMES[@]} ))]}"
      elapsed=$(( $(date +%s) - SPIN_T0 ))
      # spinner → STDERR (keeps report clean)
      printf "\r%s %s (elapsed: %02dm%02ds)" "$frame" "$SPIN_TITLE" $((elapsed/60)) $((elapsed%60)) >&2
      sleep 0.2
      i=$((i+1))
    done
  ) &
  SPIN_PID=$!
  disown "$SPIN_PID" 2>/dev/null || true
}

spinner_stop() {
  local rc="$1"
  local t1 dur dur_fmt
  t1=$(date +%s)
  dur=$(( t1 - SPIN_T0 ))
  dur_fmt=$(printf "%02dm%02ds" $((dur/60)) $((dur%60)))
  if [[ -n "$SPIN_PID" ]] && kill -0 "$SPIN_PID" 2>/dev/null; then
    kill "$SPIN_PID" 2>/dev/null || true
    wait "$SPIN_PID" 2>/dev/null || true
    SPIN_PID=""
  fi
  [[ -t 1 ]] && printf "\r\033[K" >&2
  if (( rc == 0 )); then
    log "[OK] $SPIN_TITLE — ${dur_fmt}"
  else
    log "[FAIL] $SPIN_TITLE — ${dur_fmt} (exit: ${rc})"
  fi
  hr
}

run_step() {
  local title="$1"; shift
  log ">>> ${title} — START $(now_iso)"
  spinner_start "$title"
  set +e
  { "$@"; } 2>&1 | tee -a "$out"
  local rc="${PIPESTATUS[0]}"
  set -e
  spinner_stop "$rc"
  return "$rc"
}

maybe_timeout() {
  # usage: maybe_timeout SECONDS cmd args...
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout --preserve-status "${secs}" "$@"
  else
    "$@"
  fi
}

# ---------- deps ----------
ensure_deps() {
  local need=(bash nmap curl dig whatweb whois openssl nc)
  local missing=()
  local c
  for c in "${need[@]}"; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
  if ((${#missing[@]}==0)); then
    echo "### All deps present"
    return 0
  fi
  if command -v apt >/dev/null 2>&1 || command -v apt-get >/dev/null 2>&1; then
    echo "### Installing missing deps via apt: ${missing[*]}"
    local pkgs=()
    for c in "${missing[@]}"; do
      case "$c" in
        dig)     pkgs+=("dnsutils") ;;
        nc)      pkgs+=("netcat-openbsd") ;;
        whatweb) pkgs+=("whatweb") ;;
        whois)   pkgs+=("whois") ;;
        nmap)    pkgs+=("nmap") ;;
        curl)    pkgs+=("curl") ;;
        openssl) pkgs+=("openssl") ;;
        bash)    : ;;
        *)       pkgs+=("$c") ;;
      esac
    done
    mapfile -t pkgs < <(printf "%s\n" "${pkgs[@]}" | awk '!seen[$0]++')
    sudo apt update -y || echo "### Warning: apt update failed (continuing if possible)"
    sudo apt install -y "${pkgs[@]}" || echo "### Warning: some packages failed to install (continuing)"
  else
    echo "### apt not found. Please install manually: ${missing[*]}"
  fi
}

# ---------- normalize target & output ----------
raw="$1"
target="${raw#*://}"; target="${target%%/*}"; target="${target%%:*}"; target="${target,,}"
[[ -z "$target" ]] && { echo "### Could not parse target"; exit 1; }
stamp="$(date +%F_%H%M%S)"
out="${target}_opsec_${stamp}.txt"

# ---------- header ----------
echo "### OPSEC quick recon for: ${target}" | tee -a "$out"
echo "### Started: $(now_iso)" | tee -a "$out"
hr

# ---------- step functions ----------
dns_overview() {
  echo "# dig A:";     dig +short A "$target"
  echo; echo "# dig AAAA:";  dig +short AAAA "$target"
  echo; echo "# dig MX:";    dig +short MX "$target"
  echo; echo "# dig TXT:";   dig +short TXT "$target"
  echo; echo "# dig NS:";    dig +short NS "$target"
}

dnssec_signal() {
  echo "### DNSSEC signal (DS at parent)"
  dig +short DS "$target" || true
}

whois_brief() {
  if [[ "$target" =~ \.es$ ]]; then
    echo "This TLD may require NIC.es portal for full WHOIS -> https://www.nic.es/"
  fi
  whois "$target" 2>/dev/null | sed -n '1,200p' || true
}

http_headers() {
  local scheme
  for scheme in https http; do
    echo "### ${scheme^^} HEADERS"
    maybe_timeout "$CURL_T" curl -kLsS -I -L --compressed "${scheme}://${target}/" | sed 's/\r$//' || true
    echo
  done
}

sec_headers() {
  maybe_timeout "$CURL_T" curl -kLsS -D - -o /dev/null -L --compressed "https://${target}/" \
  | sed 's/\r$//' \
  | awk '
    BEGIN{
      want["content-security-policy"]=1
      want["strict-transport-security"]=1
      want["x-frame-options"]=1
      want["x-content-type-options"]=1
      want["referrer-policy"]=1
      want["permissions-policy"]=1
    }
    tolower($0) ~ /^[a-z0-9\-]+:/ {
      split($0,a,":"); key=tolower(a[1]); gsub(/^ +| +$/,"",key);
      if (key in want) { seen[key]=1; print $0 }
    }
    END{ for (h in want) if (!seen[h]) print "MISSING: " toupper(h) }
  '
}

tls_fast() { maybe_timeout "$NMAP_TLS_T" nmap -Pn -p 443 --script ssl-enum-ciphers "$target" -oN - || true; }

tls_cert() {
  # details
  local cert; cert="$(maybe_timeout "$CURL_T" openssl s_client -connect "${target}:443" -servername "${target}" </dev/null 2>/dev/null \
    | openssl x509 -noout -issuer -subject -dates -ext subjectAltName || true)"
  [[ -n "$cert" ]] && echo "$cert" || echo "(openssl failed)"

  # expiry days
  local end raw_end end_epoch now_epoch days
  raw_end="$(maybe_timeout "$CURL_T" openssl s_client -connect "${target}:443" -servername "${target}" </dev/null 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
  if [[ -n "$raw_end" ]]; then
    end_epoch=$(date -d "$raw_end" +%s 2>/dev/null || true)
    now_epoch=$(date +%s)
    if [[ -n "$end_epoch" ]]; then
      days=$(( (end_epoch - now_epoch) / 86400 ))
      echo "Expires in: ${days} days"
    fi
  fi
}

whatweb_fp() {
  # Detect supported flags
  local help
  help="$(whatweb -h 2>&1 || whatweb --help 2>&1 || true)"
  local args=( -a 4 --no-errors --color=never )
  if grep -q -- '--timeout' <<<"$help"; then
    args+=( --timeout "$WHATWEB_T" )
  else
    grep -q -- '--open-timeout' <<<"$help" && args+=( --open-timeout "$WHATWEB_T" )
    grep -q -- '--read-timeout'  <<<"$help" && args+=( --read-timeout  "$WHATWEB_T" )
  fi
  whatweb "${args[@]}" "https://${target}/" || true
}

robots_txt()  { maybe_timeout "$CURL_T" curl -kLsS -L --compressed "https://${target}/robots.txt" || echo "(no robots.txt)"; }
sitemap_xml() { maybe_timeout "$CURL_T" curl -kLsS -L --compressed "https://${target}/sitemap.xml" | head -n 200 || echo "(no sitemap.xml)"; }

subdomain_probe() {
  # never fail this step
  local s fqdn cname ips
  local list=(www api admin dev stage staging test portal app mail cdn static images img files assets shop blog auth admin2 beta)
  for s in "${list[@]}"; do
    fqdn="${s}.${target}"
    cname="$(dig +short CNAME "$fqdn" || true)"
    ips="$(dig +short A "$fqdn" || true)"
    if [[ -n "$cname" || -n "$ips" ]]; then
      [[ -n "$cname" ]] && printf "%s -> CNAME %s" "$fqdn" "$cname"
      if [[ -n "$ips" ]]; then
        [[ -n "$cname" ]] && printf "; "
        printf "%s -> %s" "$fqdn" "$(echo "$ips" | tr '\n' ' ')"
      fi
      printf "\n"
    fi
  done
  return 0
}

nmap_web()  { maybe_timeout "$NMAP_WEB_T" nmap -Pn -p 80,443 --script "http-title,http-headers,http-methods,http-cors,http-server-header,http-security-headers,vuln" "$target" -oN - || true; }
tls_deep()  { maybe_timeout "$NMAP_TLS_T" nmap -Pn -sV -p 443 --script "ssl-enum-ciphers,ssl-cert,ssl-dh-params" "$target" -oN - || true; }

mail_posture() {
  local mx m
  mx=$(dig +short MX "$target" | sort -n | awk '{print $2}' | sed 's/\.$//')
  if [[ -z "$mx" ]]; then echo "(No MX records found)"; return 0; fi
  while IFS= read -r m; do
    [[ -z "$m" ]] && continue
    echo "MX: $m"
    dig +short A "$m" | sed 's/^/  IP: /'
    echo "  Ports 25,465,587 (banner only, may be firewalled):"
    (maybe_timeout "$CURL_T" nc -vz "$m" 25 2>&1 | sed 's/^/   - /') || true
    (maybe_timeout "$CURL_T" nc -vz "$m" 465 2>&1 | sed 's/^/   - /') || true
    (maybe_timeout "$CURL_T" nc -vz "$m" 587 2>&1 | sed 's/^/   - /') || true
    echo "  STARTTLS cert peek (25):"
    maybe_timeout "$CURL_T" openssl s_client -starttls smtp -connect "${m}:25" -servername "$m" </dev/null 2>/dev/null \
      | openssl x509 -noout -issuer -subject -dates \
      | sed 's/^/    /' || echo "    (STARTTLS not available or blocked)"
  done <<< "$mx"
  return 0
}

dmarc_chk() { dig +short TXT _dmarc."$target" || true; }
dkim_chk()  { dig +short TXT default._domainkey."$target" || true; }

tcp_full()  {
  if [[ "$EUID" -eq 0 ]]; then
    maybe_timeout "$NMAP_FULL_T" nmap -Pn -sS -sV -sC -p- --min-rate 1000 --reason --open --defeat-rst-ratelimit "$target" -oN - || true
  else
    maybe_timeout "$NMAP_FULL_T" nmap -Pn -sT -sV -sC -p- --min-rate 1000 --reason --open --defeat-rst-ratelimit "$target" -oN - || true
  fi
}
udp_top50() { maybe_timeout "$UDP_T" nmap -Pn -sU --top-ports 50 --reason --open "$target" -oN - || true; }

# ---------- run ----------
log ">>> Ensure dependencies — START $(now_iso)"
t0=$(date +%s); ensure_deps; rc=$?; dur=$(( $(date +%s)-t0 )); dur_fmt=$(printf "%02dm%02ds" $((dur/60)) $((dur%60)))
if (( rc==0 )); then log "[OK] Ensure dependencies — ${dur_fmt}"; else log "[FAIL] Ensure dependencies — ${dur_fmt} (exit: $rc)"; fi
hr

run_step "DNS overview (A/AAAA/MX/TXT/NS)"                dns_overview
run_step "DNSSEC signal (DS)"                              dnssec_signal
run_step "WHOIS (registrar, dates, NS)"                    whois_brief
run_step "HTTP(S) headers (HTTPS & HTTP)"                  http_headers
run_step "Security headers (CSP/HSTS/XFO/XCTO/Referrer/Permissions)" sec_headers
run_step "TLS fast scan (ssl-enum-ciphers:443)"            tls_fast
run_step "TLS certificate (issuer/subject/validity/SAN & expiry days)" tls_cert
run_step "Technology fingerprint (whatweb -a 4, auto-timeout flags)"   whatweb_fp
run_step "robots.txt"                                      robots_txt
run_step "sitemap.xml (first 200 lines)"                   sitemap_xml
run_step "Common subdomain probe (A records/CNAMEs)"       subdomain_probe
run_step "nmap web scripts on 80 & 443"                    nmap_web
run_step "TLS deep detail (ssl-enum-ciphers, ssl-cert, ssl-dh-params)" tls_deep
run_step "Mail posture: MX resolve, 25/465/587, STARTTLS peek"         mail_posture
run_step "DMARC record"                                    dmarc_chk
run_step "DKIM record (selector: default)"                 dkim_chk
run_step "TCP full sweep (SYN if root, connect if not) — may take a while" tcp_full

if [[ "$EUID" -eq 0 ]]; then
  run_step "UDP top-50 (best-effort)"                      udp_top50
else
  log "### Skipped UDP scan (run with sudo to include it)"; hr
fi

log "### Finished: $(now_iso)"
log "### Report saved: $(realpath "$out")"
