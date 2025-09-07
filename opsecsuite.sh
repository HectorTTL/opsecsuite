#!/usr/bin/env bash
# ============================================================================
# OPSEC Recon Suite — Installer
# Repo: https://github.com/<your-user>/opsec-recon-suite (replace before publish)
# Purpose: Install a lean, reproducible recon toolkit on Ubuntu/Debian family.
# Usage:
#   bash scripts/opsecsuite.sh
# Notes:
#   • Adds $HOME/.local/bin & $HOME/go/bin to PATH
#   • Installs gobuster & httpx via Go, dirsearch via pip --user, SecLists via git
#   • Idempotent: safe to re-run
# ============================================================================
# ============================================================================
# OPSEC Recon Suite Installer (Ubuntu/Mint)                                     ### Installs core recon tools & their dependencies in a clean, repeatable way
# ============================================================================
set -Eeuo pipefail

### --- Safety & UX flags
export DEBIAN_FRONTEND=noninteractive                                              ### Avoid interactive apt prompts
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'

say(){ printf "%s\n" "$@"; }
ok(){  printf "%s\n" "${GREEN}[OK]${RESET} $*"; }
warn(){printf "%s\n" "${YELLOW}[WARN]${RESET} $*"; }
die(){ printf "%s\n" "${RED}[ERR]${RESET} $*"; exit 1; }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Missing $1. Please run again."; }

### --- Ensure sudo exists (most installs need it)
command -v sudo >/dev/null 2>&1 || die "sudo not found. Install sudo first."

### --- Update apt cache
say "==> Updating system packages..."                                               ### Refresh package lists so we get latest metadata & security fixes
sudo apt update -y

### --- Base packages
say "==> Installing base packages (curl, git, jq, unzip, build tools, Python, etc.)"
sudo apt install -y --no-install-recommends \
  curl git jq unzip ca-certificates \
  build-essential pkg-config \
  python3 python3-pip python3-venv \
  nmap whatweb nikto \
  golang-go                                                                       ### Provide Go toolchain so we can install latest gobuster & httpx

ok "Base packages installed."

### --- Ensure user-local bin paths are in PATH for future shells
if ! grep -qs 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc"; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"                 ### Put pip --user binaries onto PATH
fi
if ! grep -qs 'export PATH="$HOME/go/bin:$PATH"' "$HOME/.bashrc"; then
  echo 'export PATH="$HOME/go/bin:$PATH"' >> "$HOME/.bashrc"                     ### Put Go-installed binaries onto PATH
fi
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"                                ### Make it effective for this session too

### --- Install dirsearch (Python) user-local
say "==> Installing dirsearch via pip (user scope)"
python3 -m pip install --user --upgrade pip                                      ### Upgrade pip so wheels resolve cleanly
python3 -m pip install --user dirsearch
ok "dirsearch installed to $HOME/.local/bin"

### --- Install gobuster v3+ (modern syntax) via Go
say "==> Installing gobuster (latest) via Go"
GO111MODULE=on go install github.com/OJ/gobuster/v3@latest                       ### v3 CLI: 'gobuster dns -d domain -w wordlist'
need_cmd gobuster
ok "gobuster: $(gobuster -v 2>/dev/null || true)"

### --- Install httpx (fast tech detect & probing) via Go
say "==> Installing httpx (ProjectDiscovery) via Go"
GO111MODULE=on go install github.com/projectdiscovery/httpx/cmd/httpx@latest     ### Great for tech detection & liveness checks
need_cmd httpx
ok "httpx: $(httpx -version 2>/dev/null || true)"

### --- Get SecLists (wordlists). Use git clone if not present, else pull.
SECLISTS_DIR="$HOME/SecLists"
if [ ! -d "$SECLISTS_DIR/.git" ]; then
  say "==> Cloning SecLists into $SECLISTS_DIR"
  git clone --depth=1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" || warn "Could not clone SecLists. You can clone later."
else
  say "==> Updating SecLists..."
  git -C "$SECLISTS_DIR" pull --ff-only || warn "SecLists update skipped."
fi

### --- Symlink a convenient wordlists path
mkdir -p "$HOME/wordlists"
[ -d "$SECLISTS_DIR" ] && ln -sf "$SECLISTS_DIR" "$HOME/wordlists/SecLists"

### --- Print final status & quick tips
say ""
ok "Installation finished."
say "Open a fresh terminal to pick PATH changes, or run: source ~/.bashrc"      ### Ensure current shell sees ~/.bashrc updates
say ""
say "Quick sanity tests:"
say "  whatweb https://example.com"
say "  gobuster dns -d example.com -w \$HOME/wordlists/SecLists/Discovery/DNS/dns-Jhaddix.txt"
say "  dirsearch -u https://example.com -e php,html,txt -t 50"
say "  httpx -version"
say "  nmap -sV example.com"
