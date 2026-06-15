#!/usr/bin/env bash
# WP-Arsenal install.sh — Set up the toolkit on any machine
# Usage: bash install.sh
# Works on: macOS, Linux, WSL, Windows (Git Bash)

set -euo pipefail

echo "════════════════════════════════════════════════════════════"
echo "  WP-Arsenal — WordPress AI Security Toolkit"
echo "════════════════════════════════════════════════════════════"
echo

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Python check ───────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found."
    echo "Install from https://www.python.org/downloads/ (3.9+)"
    exit 1
fi
PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "  Python $PYTHON_VER found"

# ── pip check ─────────────────────────────────────────────────────────────
if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null; then
    echo "ERROR: pip not found. Install pip: https://pip.pypa.io/en/stable/installation/"
    exit 1
fi
PIP="python3 -m pip"

# ── Install Python dependencies ────────────────────────────────────────────
echo "  Installing dependencies..."
$PIP install paramiko --quiet
# PyYAML is optional (enables --config flag)
$PIP install pyyaml --quiet 2>/dev/null && echo "  PyYAML installed (config file support enabled)" || \
    echo "  PyYAML not installed — you must pass all values as CLI flags (no --config)"

# ── Make scripts executable ────────────────────────────────────────────────
find "$REPO_DIR/scripts" -name "*.py" -exec chmod +x {} \;
echo "  Scripts marked executable"

# ── Create config from template ────────────────────────────────────────────
CFG="$REPO_DIR/config/config.yaml"
if [ ! -f "$CFG" ]; then
    cp "$REPO_DIR/config/config.example.yaml" "$CFG"
    echo "  Created config/config.yaml — fill in your site credentials"
else
    echo "  config/config.yaml already exists"
fi

# ── Create ISP map from template ──────────────────────────────────────────
ISP="$REPO_DIR/config/isp-map.yaml"
if [ ! -f "$ISP" ]; then
    cp "$REPO_DIR/config/isp-map.example.yaml" "$ISP"
    echo "  Created config/isp-map.yaml — add attacker ISP mappings"
fi

# ── Create sites/ directory ────────────────────────────────────────────────
mkdir -p "$REPO_DIR/config/sites"
mkdir -p "$REPO_DIR/memory"
mkdir -p "$REPO_DIR/logs"

# ── .gitignore ────────────────────────────────────────────────────────────
if [ ! -f "$REPO_DIR/.gitignore" ]; then
    cat > "$REPO_DIR/.gitignore" << 'EOF'
config/config.yaml
config/isp-map.yaml
config/sites/
memory/site-credentials.md
memory/secrets.md
*.pyc
__pycache__/
logs/
*.tar.gz
.env
EOF
fi

echo
echo "  ✓ WP-Arsenal ready"
echo
echo "  Next steps:"
echo "  1. Edit config/config.yaml with your site credentials"
echo "  2. Run a fast scan:"
echo "     python scripts/security/wp-scan.py --config config/config.yaml"
echo
echo "  For multiple sites, create one config per site:"
echo "     cp config/config.example.yaml config/sites/site2.yaml"
echo "     python scripts/security/wp-scan.py --config config/sites/site2.yaml"
echo
echo "  Full documentation: see CLAUDE.md"
echo "════════════════════════════════════════════════════════════"
