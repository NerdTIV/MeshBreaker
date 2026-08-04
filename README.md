# MeshBreaker

BLE Mesh security research tool : scan, capture, enumerate, fuzz, analyze firmware, check CVEs, generate reports.

Built for authorized testing on BLE Mesh deployments: industrial gateways, smart lighting controllers, sensor networks, and anything running SIG Mesh, Wirepas, Thread, or a custom BLE stack.

> **For authorized testing only.** Do not use against systems you do not own or have written permission to test.

---

## How it works

```
meshbreaker recon        →  Scan nearby BLE devices, fingerprint the protocol
meshbreaker capture      →  Passive listen: decode beacons, map the mesh topology
meshbreaker enumerate    →  Connect to target, dump all GATT services + SDP
meshbreaker firmware     →  Feed a binary: arch, RTOS, keys, credentials, URLs
meshbreaker fuzz         →  Send malformed packets to GATT, L2CAP, SDP, or Mesh
meshbreaker cve-check    →  Match kernel + BlueZ version against 46 known CVEs
meshbreaker report       →  Export everything as Markdown, HTML, or JSON
```

Everything runs inside Docker, no Python dependency hell, no distro-specific setup.

---

## Requirements

- **Linux or Windows**
- **USB Bluetooth dongle** - for BLE commands (recon, fuzz, enumerate, capture)
- **Python 3.10+** - Windows only (Linux uses Docker, Python is inside the image)

---

## Install

### Linux

> **Do not run `install.sh` with sudo.** The script calls sudo itself where needed. Running it as root breaks the user setup.

```bash
git clone https://github.com/NerdTIV/MeshBreaker
cd MeshBreaker
bash install.sh
```

`install.sh` will:
1. Detect your package manager (apt, dnf, pacman, zypper...)
2. Install Docker if missing — uses sudo internally, you will be prompted for your password
3. Add your user to the `docker` group so you don't need sudo to run Docker
4. Build the image (~2 min, only once)
5. Install a `meshbreaker` command in `~/.local/bin`

**After install:** log out and back in (or run `newgrp docker`) so the group change takes effect. Until you do, the wrapper falls back to `sudo docker` automatically — it still works either way.

If `meshbreaker` is not found after relogging:
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Windows

```powershell
git clone https://github.com/NerdTIV/MeshBreaker
cd MeshBreaker
.\install.ps1
```

`install.ps1` does everything automatically — no admin rights required:
1. Looks for Python 3.10+. If missing, installs it via `winget` (built into Windows 10/11) or Chocolatey if available. Falls back to a direct download link only if both fail.
2. Installs all Python dependencies
3. Creates a `meshbreaker` command in your PATH

Restart your terminal after install.

**What works on Windows:**

| Command | Status |
|---|---|
| `recon`, `capture`, `enumerate` | ✅ via Windows BLE (WinRT) |
| `fuzz --type gatt` | ✅ |
| `firmware`, `cve-check`, `report`, `session` | ✅ |
| `fuzz --type l2cap` / `fuzz --type sdp` | ❌ raw BT sockets — Linux only |

---

## Commands

### Recon

```bash
# Scan for BLE devices nearby (default 10 seconds)
meshbreaker recon

# Scan for longer and save a target
meshbreaker recon --time 30

# Scan and lock onto a specific MAC
meshbreaker recon -t AA:BB:CC:DD:EE:FF

# Save the target for all subsequent commands
meshbreaker set-target AA:BB:CC:DD:EE:FF
```

`recon` scans with the local BT adapter, decodes advertising data (AD types), and runs the protocol fingerprinter to identify whether the target is running SIG Mesh, Wirepas, Thread, or a proprietary BLE stack. Confidence score is shown for each match.

**Example output:**
```
14:22:03 [INF] BLE scan (15s, active)…
14:22:18 [OK ] Scan complete — 4 devices found

14:22:18 [INF] Protocol fingerprinting…

╭──────────────────── Protocol Identification ─────────────────────────────────╮
│ Protocol              Confidence                    Evidence                  │
│ SIG Mesh              ████████████████░░░░ 80%      service UUID 1827;        │
│                                                     service UUID 1828         │
│ Wirepas               ██████░░░░░░░░░░░░░░ 35%      company ID 0x0077         │
│ Thread / OpenThread   ██░░░░░░░░░░░░░░░░░░ 10%      name match 'ot'           │
╰──────────────────────────────────────────────────────────────────────────────╯

14:22:18 [TGT] Target: AA:BB:CC:DD:EE:FF  RSSI -61 dBm  (SolidSense-n6gsdl)
```

---

### Capture

```bash
# Passive capture for 60 seconds
meshbreaker capture --duration 60

# Reload and decode an existing capture file
meshbreaker parse-capture output/capture_20250101_120000.json
```

`capture` listens passively — no connection, nothing sent. Decodes BLE Mesh beacons (Secure Network Beacon, Unprovisioned Device Beacon) and builds a topology map: which nodes are provisioned, which are relays, which are proxies.

---

### Enumerate

```bash
# Enumerate GATT services on target
meshbreaker enumerate

# Enumerate with a specific target
meshbreaker enumerate -t AA:BB:CC:DD:EE:FF

# Also run an SDP service browse (Bluetooth Classic)
meshbreaker enumerate --sdp
```

Connects to the target and dumps all GATT services, characteristics, and descriptors. Reads values from readable characteristics. Highlights writable characteristics - those are the attack surface for fuzzing. Also runs `sdptool browse` if `--sdp` is passed.

---

### Firmware

```bash
# Analyze a firmware binary
meshbreaker firmware /path/to/firmware.bin

# The path can be anywhere on your machine — it gets mounted automatically
meshbreaker firmware ~/Downloads/router_fw_v2.3.1.bin
```

Static analysis only — no emulation, no execution. Detects:
- **Format**: ELF, raw binary, Intel HEX, gzip, SquashFS, U-Boot image, UF2, and more
- **Architecture**: ARM32, ARM64, MIPS, x86, RISC-V, Xtensa (ESP32), PowerPC, AVR, and more
- **RTOS**: FreeRTOS, Zephyr, VxWorks, ThreadX, mbed OS, BusyBox/Linux, and more
- **SoC**: nRF52/53, ESP32, STM32, TI CC26xx, EFR32, and more
- **Secrets**: AES keys (entropy scan), hardcoded passwords, private keys, BLE Mesh network keys, URLs, IP addresses

**Example output:**
```
14:23:11 [INF] Loaded: router_fw_v2.3.1.bin  (4,194,304 bytes)
14:23:11 [INF] Format detected: elf
14:23:11 [INF] ELF 32 little-endian arch=arm32
14:23:11 [INF] Strings extracted: 2847
14:23:11 [OK ] RTOS detected: BusyBox / Embedded Linux
14:23:11 [OK ] SoC detected: NXP i.MX (score=3)

╭──────────────── Firmware Report — router_fw_v2.3.1.bin ─────────────────────╮
│ Field                Value                                                    │
│ Path                 /firmware/router_fw_v2.3.1.bin                          │
│ Size                 4,194,304 bytes                                          │
│ Format               elf                                                      │
│ Architecture         arm32 (little-endian)                                   │
│ RTOS                 BusyBox / Embedded Linux                                 │
│ SoC                  NXP i.MX                                                 │
│ Encrypted            No  (entropy 4.31)                                       │
│ Compressed           No                                                       │
│ Strings              2847                                                     │
│ URLs                 8                                                        │
│ IPs                  3                                                        │
│ Credentials          2                                                        │
│ AES key candidates   0                                                        │
│ BLE Mesh keys        0                                                        │
╰─────────────────────────────────────────────────────────────────────────────╯

14:23:12 [INF] URLs:
14:23:12 [INF]   http://kapua.example.io/api/v1
14:23:12 [INF]   mqtt://broker.example.io:1883
14:23:12 [WRN] Credentials found:
14:23:12 [WRN]   admin:admin
14:23:12 [WRN]   user:default123
14:23:12 [OK ] Analysis exported → output/router_fw_v2.3.1_analysis.json
```

Results go to `output/`.

---

### Fuzz

```bash
# Fuzz all GATT writable characteristics
meshbreaker fuzz --type gatt

# Fuzz L2CAP PSMs (common ones by default)
meshbreaker fuzz --type l2cap

# Fuzz specific L2CAP PSMs
meshbreaker fuzz --type l2cap --psm 1,3,5,7

# Fuzz SDP
meshbreaker fuzz --type sdp

# Fuzz BLE Mesh (proxy PDUs)
meshbreaker fuzz --type mesh
```

Sends a set of crafted payloads per target. Payloads include: empty, max-size, all-zeros, all-0xFF, cyclic patterns (AAAB AAAC...), format string probes, malformed protocol headers. Crashes are flagged when the device resets or goes silent. Results go to `output/`.

**Example output (GATT):**
```
14:31:07 [INF] GATT fuzzer → AA:BB:CC:DD:EE:FF
14:31:08 [OK ] Connected — enumerating writable characteristics…
14:31:08 [INF]   Fuzzing [0x0012] 0000ffe1-0000-1000-8000-00805f9b34fb (14 payloads)
14:31:09 [DBG]     [00]  512B → ACK
14:31:09 [DBG]     [01]  512B → ACK
14:31:10 [DBG]     [02]  512B → ACK
14:31:10 [DBG]     [03]    4B → ACK
14:31:11 [DBG]     [04]    4B → ACK
14:31:11 [DBG]     [05]    4B → ACK
14:31:12 [DBG]     [06]  200B → ACK
14:31:12 [WRN]     [07]    0B → CRASH: Disconnected: [org.bluez.Error.Failed]
14:31:12 [WRN] CRASH on handle 0x0012 len=0
14:31:12 [OK ] Fuzzing complete — 8 payloads sent, 1 crash
```

---

### Exploit

```bash
# Check if BleedingTooth A2MP surface is reachable
meshbreaker exploit --method bleedingtooth

# Run SDP buffer overflow probe
meshbreaker exploit --method sdp-bof

# Run all exploit probes in sequence
meshbreaker exploit --method all

# Run a custom plugin
meshbreaker exploit --method plugin --plugin-name my_attack
```

---

### CVE Check

```bash
# Auto-detect from firmware analysis (run firmware first)
meshbreaker cve-check

# Override manually if you know the versions
meshbreaker cve-check --kernel 5.4.47 --bluez 5.72

# Add extra tags (protocols present on target)
meshbreaker cve-check --tags wirepas,kura,mqtt
```

If you ran `meshbreaker firmware` first, the kernel and BlueZ versions are extracted automatically from the binary strings (`Linux version X.X.X`, `bluetoothd X.X`) and reused here — no manual input needed.

If the firmware doesn't contain those strings (stripped binary, custom build), provide the versions manually. You can get them from:
- An SSH session on the device: `uname -r` and `bluetoothd --version`
- An SDP or HTTP banner if exposed
- The device's documentation or release notes

Matches against a local CVE database (`data/cve_db.json`) covering BlueZ, Linux kernel BT stack, and SIG Mesh protocol weaknesses.

---

### Report

```bash
# Generate all formats
meshbreaker report --format all

# Markdown only
meshbreaker report --format md

# HTML (dark theme, self-contained)
meshbreaker report --format html

# Machine-readable JSON
meshbreaker report --format json
```

Aggregates all results from the current session into a structured report. Saved in `output/reports/`.

---

### Session

```bash
# Show current session (target, protocol, results summary)
meshbreaker session

# Set a target MAC (persists across commands)
meshbreaker set-target AA:BB:CC:DD:EE:FF

# Set a target IP (for network-based exploits)
meshbreaker set-ip 192.168.1.100
```

---

## Writing your own attack — plugins

Drop a `.py` file into `src/plugins/` and it is automatically loaded at startup.

```python
# src/plugins/my_attack.py
from src.core.plugin_base import PluginBase, PluginMeta

class MyAttack(PluginBase):
    meta = PluginMeta(
        name        = "my_attack",
        version     = "1.0",
        description = "My custom attack",
        author      = "T.I.V.",
        category    = "exploit",   # recon | fuzz | exploit | post
    )

    def run(self) -> dict:
        # self.target  → MAC address of the target
        # self.adapter → BT adapter in use (e.g. "hci0")
        # self.session → results from previous phases

        # do your attack here
        return {"result": "found something"}
```

Run it:
```bash
meshbreaker exploit --method plugin --plugin-name my_attack
```

Three ready-to-copy templates are in `src/plugins/`:
- `template_recon.py` — passive info gathering
- `template_firmware.py` — firmware binary analysis
- `template_mesh_attack.py` — active attack over BLE Mesh Proxy

Files starting with `template_` are skipped at load time. Rename yours.

---

## Output structure

```
output/
├── session.json                  ← current session state (target, results)
└── reports/
    ├── report_TIMESTAMP.md
    ├── report_TIMESTAMP.html     ← dark-theme, self-contained
    └── report_TIMESTAMP.json
```

---

## Troubleshooting

**`meshbreaker: command not found`**
`~/.local/bin` is not in your PATH. Fix:
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

**`permission denied while trying to connect to the Docker daemon`**
You haven't relogged since install. Either log out and back in, or run:
```bash
newgrp docker
```
After that, `meshbreaker` works without sudo.

**`No Bluetooth adapter found`**
Plug in a USB Bluetooth dongle — internal laptop adapters don't pass through into Docker. Check the dongle is seen by the host:
```bash
hciconfig
```
You should see `hci0` listed. If not, try `sudo hciconfig hci0 up`.

**`Permission denied` on Bluetooth socket / BT errors inside the container**
The Bluetooth service may not be running on the host. Start it:
```bash
sudo systemctl start bluetooth
```
This is the only time you need sudo after the initial install.

**Output files owned by root**
Docker writes output as root. Fix permissions once:
```bash
sudo chown -R $USER:$USER output/
```

---

## For developers

Edit code locally without rebuilding the image on every change:

```bash
docker compose --profile dev run dev recon --time 10
docker compose --profile dev run dev firmware /firmware/fw.bin

# Mount a firmware directory
FIRMWARE_DIR=/path/to/firmwares docker compose --profile dev run dev firmware /firmware/fw.bin
```

Rebuild after changes to `requirements.txt` or `Dockerfile`:
```bash
docker compose build
```

---

## License

MIT. Use responsibly.

---

Built by **T.I.V.**
