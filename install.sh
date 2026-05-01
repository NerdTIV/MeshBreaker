#!/usr/bin/env bash
# MeshBreaker — one-shot installer
# Usage: ./install.sh
#
# What it does:
#   1. Checks Docker, installs it if missing
#   2. Adds your user to the docker group
#   3. Builds the meshbreaker Docker image
#   4. Installs a `meshbreaker` command in ~/.local/bin

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/bin"
WRAPPER="$BIN_DIR/meshbreaker"

echo ""
echo "  MeshBreaker — installer"
echo "  ========================"
echo ""

# ── 1. Docker ─────────────────────────────────────────────────────────────────
_install_docker() {
    if command -v apt-get &>/dev/null; then
        # Debian / Ubuntu / Kali — disable broken Docker CE repo if present
        while IFS= read -r f; do
            if grep -q "download.docker.com" "$f" 2>/dev/null; then
                case "$f" in
                    *.list)    sudo sed -i 's/^deb /#deb /g' "$f" ;;
                    *.sources) grep -q "^Enabled:" "$f" \
                                   && sudo sed -i 's/^Enabled:.*/Enabled: no/' "$f" \
                                   || echo "Enabled: no" | sudo tee -a "$f" >/dev/null ;;
                esac
                echo "[*] Disabled incompatible Docker CE repo: $f"
            fi
        done < <(find /etc/apt/sources.list.d/ -name "*.list" -o -name "*.sources" 2>/dev/null)
        sudo apt-get update -qq
        sudo apt-get install -y docker.io

    elif command -v dnf &>/dev/null; then
        # Fedora / RHEL / CentOS Stream
        sudo dnf install -y docker
        sudo systemctl enable --now docker

    elif command -v yum &>/dev/null; then
        # Older RHEL / CentOS
        sudo yum install -y docker
        sudo systemctl enable --now docker

    elif command -v pacman &>/dev/null; then
        # Arch Linux / Manjaro
        sudo pacman -Sy --noconfirm docker

    elif command -v zypper &>/dev/null; then
        # openSUSE
        sudo zypper install -y docker

    else
        echo "[!] Unsupported package manager. Install Docker manually:"
        echo "    https://docs.docker.com/engine/install/"
        exit 1
    fi

    sudo systemctl enable --now docker 2>/dev/null || true
}

if ! command -v docker &>/dev/null; then
    echo "[*] Docker not found. Installing..."
    _install_docker
    echo "[+] Docker installed."
else
    echo "[+] Docker found: $(docker --version | cut -d' ' -f3 | tr -d ',')"
fi

# ── 2. docker group ───────────────────────────────────────────────────────────
if ! groups "$USER" | grep -q '\bdocker\b'; then
    echo "[*] Adding $USER to docker group..."
    sudo usermod -aG docker "$USER"
    NEED_RELOGIN=1
fi

# Figure out how to call docker (may need sudo until relogin)
DOCKER="docker"
if ! docker info &>/dev/null 2>&1; then
    DOCKER="sudo docker"
fi

# ── 3. Build image ────────────────────────────────────────────────────────────
echo "[*] Building meshbreaker image (first run ~2 min)..."
$DOCKER build -t meshbreaker:latest "$SCRIPT_DIR"
echo "[+] Image built."

# ── 4. output/ with correct owner ─────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/output"
# Docker runs as root inside; pre-create so host user owns it
if [ "$(stat -c '%U' "$SCRIPT_DIR/output")" != "$USER" ]; then
    sudo chown "$USER":"$USER" "$SCRIPT_DIR/output"
fi

# ── 5. Install wrapper ────────────────────────────────────────────────────────
mkdir -p "$BIN_DIR"
cat > "$WRAPPER" << 'WRAPPER_EOF'
#!/usr/bin/env bash
DOCKER="docker"
if ! docker info &>/dev/null 2>&1; then
    if sudo docker info &>/dev/null 2>&1; then
        DOCKER="sudo docker"
    else
        echo "[!] Cannot reach Docker daemon."
        echo "    Try: sudo meshbreaker  or  newgrp docker && meshbreaker"
        exit 1
    fi
fi

# Auto-mount any path arg (absolute or relative) that exists on the host.
# Relative paths are resolved to absolute so the container sees them.
EXTRA_MOUNTS=()
SEEN_DIRS=()
FINAL_ARGS=()
for arg in "$@"; do
    resolved="$(realpath "$arg" 2>/dev/null)"
    if [ -n "$resolved" ] && [ -e "$resolved" ]; then
        dir="$(dirname "$resolved")"
        already=0
        for d in "${SEEN_DIRS[@]}"; do [ "$d" = "$dir" ] && already=1 && break; done
        if [ "$already" = "0" ]; then
            EXTRA_MOUNTS+=("-v" "$dir:$dir:ro")
            SEEN_DIRS+=("$dir")
        fi
        FINAL_ARGS+=("$resolved")
    else
        FINAL_ARGS+=("$arg")
    fi
done

exec $DOCKER run --rm -it \
    --privileged \
    --network host \
    -v /var/run/dbus:/var/run/dbus \
    -v "##OUTPUT_DIR##:/app/output" \
    "${EXTRA_MOUNTS[@]}" \
    meshbreaker:latest "${FINAL_ARGS[@]}"
WRAPPER_EOF

sed -i "s|##OUTPUT_DIR##|${SCRIPT_DIR}/output|g" "$WRAPPER"
chmod +x "$WRAPPER"
echo "[+] Installed: $WRAPPER"

# ── 6. PATH check ─────────────────────────────────────────────────────────────
echo ""
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "[!] ~/.local/bin is not in your PATH. Add this to ~/.bashrc or ~/.zshrc:"
    echo ""
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "    Then reload: source ~/.bashrc"
    echo ""
fi

if [ "${NEED_RELOGIN:-0}" = "1" ]; then
    echo "[!] You were added to the docker group."
    echo "    Run this to apply without logging out:"
    echo ""
    echo "    newgrp docker"
    echo ""
fi

echo "[+] Done. Usage:"
echo ""
echo "    meshbreaker --help"
echo "    meshbreaker recon --time 10"
echo "    meshbreaker firmware /path/to/firmware.bin"
echo "    meshbreaker cve-check --kernel 5.4.47 --bluez 5.72"
echo ""
