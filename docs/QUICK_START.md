# Quick Start

## Installation

```bash
git clone https://github.com/yourusername/MeshBreaker.git
cd MeshBreaker
bash install.sh
```

`install.sh` detects your package manager, installs Docker if it is not already present, builds the image, and adds `meshbreaker` to `~/.local/bin`.

Restart your terminal, or run `source ~/.bashrc` / `source ~/.zshrc` to pick up the new command.

## Basic Usage

```bash
# Scan for BLE devices nearby
meshbreaker recon

# Scan and fingerprint a specific target
meshbreaker recon -t AA:BB:CC:DD:EE:FF

# Enumerate GATT services on a target
meshbreaker enumerate -t AA:BB:CC:DD:EE:FF

# Fuzz GATT characteristics
meshbreaker fuzz --type gatt -t AA:BB:CC:DD:EE:FF

# Fuzz L2CAP PSMs
meshbreaker fuzz --type l2cap -t AA:BB:CC:DD:EE:FF

# Analyze a firmware binary
meshbreaker firmware /path/to/firmware.bin

# Passive capture (Ctrl-C to stop)
meshbreaker capture --duration 60

# Generate a report from the current session
meshbreaker report --format html
```

Results are saved to `./output/`.

## Requirements

- Linux (any distro with bash)
- USB Bluetooth adapter (for BLE commands)
- Root or `sudo` access (for Bluetooth raw socket access)

Docker handles all Python dependencies automatically.

## Common Issues

**`meshbreaker: command not found`**
Make sure `~/.local/bin` is in your PATH. Add this to `~/.bashrc` or `~/.zshrc`:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

**`No Bluetooth adapter found`**
Plug in a USB Bluetooth dongle and check `hciconfig`.

**Permission denied on Bluetooth socket**
Run with `sudo meshbreaker ...` or grant your user access to the `bluetooth` group:
```bash
sudo usermod -aG bluetooth $USER
```
