# MeshBreaker

BLE Mesh security research tool : scan, capture, enumerate, fuzz, analyze firmware, check CVEs, generate reports.

Built for authorized testing on BLE Mesh deployments: industrial gateways, smart lighting controllers, sensor networks, and anything running SIG Mesh, Wirepas, Thread, or a custom BLE stack.

> **For authorized testing only.** Do not use against systems you do not own or have written permission to test.

---

## How it works

```
meshbreaker setup        →  What hardware do I have? Adapters, sniffers, tools
meshbreaker recon        →  Scan nearby BLE devices, fingerprint the protocol
meshbreaker capture      →  Passive listen: decode beacons, map the mesh topology
meshbreaker hci-capture  →  Full AD payloads incl. mesh types (Linux, root)
meshbreaker sniff        →  Parallel multi-adapter capture, or drive a real sniffer
meshbreaker enumerate    →  Connect to target, dump all GATT services + SDP
meshbreaker provisioning →  Audit how nodes join the mesh — the NetKey handover
meshbreaker df           →  Audit Mesh 1.1 Directed Forwarding routing exposure
meshbreaker channels     →  BLE channel reference + hop prediction from CONNECT_IND
meshbreaker firmware     →  Feed a binary: arch, RTOS, keys, credentials, URLs
meshbreaker fuzz         →  Send malformed packets to GATT, L2CAP, SDP, or Mesh
meshbreaker cve-check    →  Match kernel + BlueZ version against 55 known CVEs
meshbreaker report       →  Export everything as Markdown, HTML, or JSON

meshbreaker auto         →  Run the whole chain in order, one command
```

Everything runs inside Docker, no Python dependency hell, no distro-specific setup.

**Start here:** `meshbreaker setup` tells you what your hardware can and cannot
do, then `meshbreaker auto` runs the full passive assessment without touching
the target.

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
| `fuzz -m gatt` | ✅ |
| `firmware`, `cve-check`, `report`, `session` | ✅ |
| `channels`, `df`, `provisioning --no-gatt` | ✅ offline analysis, no radio needed |
| `hci-capture` | ❌ Linux kernel interface — use Sniffle instead |
| `auto` | ✅ phases that need raw sockets are skipped |
| `sniff --backend sniffle` | ✅ if the dongle enumerates as a COM port |
| `setup` | ⚠️ adapter list is empty — it reads `hciconfig` |
| `sniff --backend hci` (multi-adapter) | ❌ needs BlueZ adapter names |
| `fuzz -m l2cap` / `fuzz -m sdp` | ❌ raw BT sockets — Linux only |

---

## Commands

### Auto — the whole chain

```bash
# Full passive assessment: recon, capture, enumerate, provisioning, DF, CVE, report
meshbreaker auto

# With a known target and a firmware image
meshbreaker auto -t AA:BB:CC:DD:EE:FF --firmware ~/fw/gateway.bin

# Include fuzzing (this can crash the target — see the warning below)
meshbreaker auto --active

# Just the mesh security phases
meshbreaker auto --from 4 --to 5

# Skip phases by name
meshbreaker auto --skip capture,fuzz
```

`auto` runs each phase in order and hands the results to the next one, which is
the point: the protocol fingerprint from `recon` tells `fuzz` what to send, and
the kernel and BlueZ versions pulled out of `firmware` are what `cve-check`
matches against. A phase that fails is reported and the chain keeps going.

| # | Phase | What it does |
|---|-------|--------------|
| 1 | `recon` | BLE scan + protocol fingerprint |
| 2 | `capture` | Passive capture + topology map |
| 3 | `enumerate` | GATT services (needs a target) |
| 4 | `provisioning` | PB-ADV / PB-GATT audit |
| 5 | `directed-forwarding` | Mesh 1.1 routing exposure |
| 6 | `firmware` | Static analysis (needs `--firmware`) |
| 7 | `fuzz` | **Active** — only with `--active` |
| 8 | `cve-check` | CVE matching |
| 9 | `report` | Markdown + HTML + JSON |

> **Passive by default.** Phases 1-6, 8 and 9 send nothing to the target beyond
> normal BLE scanning and GATT reads. Fuzzing is the only active phase and it
> stays off unless you pass `--active`, because a tool that silently starts
> crashing a customer's lighting controller is a tool nobody should ship.

**Example output:**
```
19:20:22 [INF] Chain start — phases 1 to 9, passive only

── Phase 4: Provisioning security audit (PB-ADV and PB-GATT) ──
19:20:22 [WRN] Provisioning session observed — link ID 0x12345678
19:20:22 [WRN]   Auth method negotiated: No OOB
19:20:22 [WRN] CRITICAL: Provisioning negotiated with No OOB authentication

╭─────────────────────────── Chain Summary ────────────────────────────────────╮
│ #  Phase                 Status    Time    Detail                             │
│ 1  recon                 ok        15.2s   4 devices, protocol sig_mesh       │
│ 2  capture               ok        30.1s   6 nodes mapped                     │
│ 3  enumerate             ok         3.4s   9 services, 3 writable chars       │
│ 4  provisioning          ok         1.1s   1 PB-ADV sessions                  │
│ 5  directed-forwarding   ok         0.2s   present                            │
│ 6  firmware              skipped     —     no firmware path set               │
│ 7  fuzz                  skipped     —     active phase — rerun with --active │
│ 8  cve-check             ok         0.1s   8 CVE matches                      │
│ 9  report                ok         0.1s   3 reports written                  │
╰──────────────────────────────────────────────────────────────────────────────╯
```

---

### Setup — what can my hardware actually do

```bash
meshbreaker setup
```

Lists your HCI adapters (scored, so it can pick a default), any sniffer
hardware it recognises over USB, and which external tools are on your PATH.

Worth being blunt about the difference, because it decides what you can do:

- **HCI adapters** — any USB dongle. They scan, connect and enumerate. BlueZ
  hops them across the three advertising channels and gives you no say in it,
  so you **cannot** pin one to a channel or follow a connection.
- **Sniffers** — an nRF52840 running [Sniffle](https://github.com/nccgroup/Sniffle)
  (~20 EUR) or an Ubertooth One (~120 EUR). These expose the raw radio: pick a
  channel, catch a `CONNECT_IND`, follow the hop sequence.

Everything except channel-level work runs fine on a plain dongle.

---

### What your adapter can actually see

Worth understanding before you trust a "nothing found" result, because it
decides which findings are reachable with which hardware.

**BlueZ chooses what an application sees.** Through bleak you get names,
service UUIDs, service data and manufacturer data. Mesh traffic lives in AD
types BlueZ never surfaces:

| AD type | Carries | Visible to bleak? |
|---|---|---|
| `0x29` | PB-ADV — provisioning | ❌ |
| `0x2A` | Mesh Message — network PDUs | ❌ |
| `0x2B` | Mesh Beacon | ❌ |
| `0x16` | Service Data — mesh 0x1827 / 0x1828 | ✅ |

So a capture taken with `meshbreaker capture` **cannot contain provisioning
traffic**, however much is in the air. That is not a bug, it is where the
BlueZ D-Bus API draws the line. MeshBreaker now says so explicitly rather than
reporting a clean-looking zero — a silent false negative is the worst failure
mode an audit tool has, because it looks exactly like a pass.

Three ways to get mesh visibility, cheapest first:

```bash
# 1. Service data only — works with any adapter, no root
meshbreaker capture -d 60 && meshbreaker provisioning

# 2. Full AD payloads — any adapter, Linux, needs root
sudo meshbreaker hci-capture -d 60
meshbreaker provisioning --capture output/hci_capture_*.json

# 3. Channel-level — nRF52840 with Sniffle (~20 EUR)
meshbreaker sniff --backend sniffle --channel 38
```

| | Standard adapter | + root (Linux) | + Sniffle / Ubertooth |
|---|---|---|---|
| Unprovisioned nodes (0x1827) | ✅ | ✅ | ✅ |
| Proxy nodes, Network ID (0x1828) | ✅ | ✅ | ✅ |
| PB-ADV provisioning exchange | ❌ | ✅ | ✅ |
| Mesh network PDUs, beacons | ❌ | ✅ | ✅ |
| Channel selection, CONNECT_IND, following | ❌ | ❌ | ✅ |
| GATT: enumerate, fuzz, PB-GATT probe, DF injection | ✅ | ✅ | ✅ |

---

### HCI capture — full AD payloads without a sniffer

```bash
# Needs root; drives its own scan
sudo meshbreaker hci-capture -d 60

# Something else is already scanning
sudo meshbreaker hci-capture -d 60 --no-scan
```

Reads the HCI monitor socket — the interface `btmon` uses — and parses the AD
structures itself, so it recovers the mesh AD types BlueZ filters out. Linux
only and privileged, but it needs no extra hardware, and the capture it writes
feeds straight into `provisioning`, `df` and `parse-capture`.

It is still one radio hopping the three advertising channels, so it does not
give you channel selection or connection following. For that you still want
Sniffle.

> Python's own `bind()` cannot reach the monitor channel: CPython hardcodes
> `HCI_CHANNEL_RAW` for `BTPROTO_HCI` and rejects `bind((dev, channel))`. The
> module builds the `sockaddr_hci` itself and calls `bind(2)` through libc.

---

### Provisioning — the NetKey handover

```bash
# Audit the last capture in the session
meshbreaker provisioning

# Audit a specific capture file
meshbreaker provisioning --capture output/capture_1234.json

# Also probe a live target for an exposed PB-GATT service
meshbreaker provisioning -t AA:BB:CC:DD:EE:FF
```

Provisioning is how a blank node joins a mesh and receives the NetKey. It is
the highest-value phase to watch, and there is a detail that makes it
practical: **the early provisioning PDUs are not encrypted.** Invite,
Capabilities, Start and Public Key all travel in the clear, because at that
point there is no shared key yet — that is the whole point of the exchange.

So a passive capture tells you exactly which authentication method was
negotiated, without attacking anything:

| Negotiated method | What it means |
|---|---|
| `No OOB` | Nothing authenticates either peer. A machine-in-the-middle can complete provisioning with both sides and walk away with the NetKey. |
| `Static OOB` | Strongest. A pre-shared value out of band. |
| `Output` / `Input OOB` | Strength depends on size — 4 digits is brute-forceable offline from the Confirmation PDU. |

Two bearers carry it. **PB-ADV** (AD type `0x29`) is broadcast and sniffable.
**PB-GATT** is the GATT service `0x1827` — and finding that still exposed on a
deployed node is itself a finding, since a provisioned node should be showing
the Proxy Service `0x1828` instead.

Maps onto CVE-2020-26556, -26557, -26558, -26559, -26560 and the Zephyr mesh
provisioning issues, all in the local CVE database.

**Example output:**
```
19:20:22 [WRN] Provisioning session observed — link ID 0x12345678
19:20:22 [INF]   Capabilities: 1 elements, static OOB=no
19:20:22 [WRN]   Auth method negotiated: No OOB

╭─────────────────────── Provisioning Findings ────────────────────────────────╮
│ Severity   Finding                                        CVE                 │
│ CRITICAL   Provisioning negotiated with No OOB auth       CVE-2020-26560      │
│ HIGH       Device does not support Static OOB             —                   │
│ LOW        Only the Mesh 1.0 provisioning algorithm       —                   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

---

### Directed Forwarding — Mesh 1.1 routing

```bash
# Look for Directed Forwarding symbols in a firmware image
meshbreaker df --firmware ~/fw/node.bin

# Heuristic pass over a capture
meshbreaker df --capture output/capture_1234.json

# Exact answer, if you hold the DevKey for the node
meshbreaker df --composition 0a005900...
```

Classic Bluetooth Mesh routes by *managed flooding*: every relay rebroadcasts
everything. Crude, but there is no routing state for anyone to lie about.
Mesh Protocol 1.1 added **Directed Forwarding**, which builds real paths:

```
Path Origin  --PATH_REQUEST-->  relays  -->  Path Target
             <---PATH_REPLY----
      then only nodes on that path forward its traffic
```

That saves bandwidth, and it creates a routing control plane. Nodes now accept
messages that change who forwards what, so a party holding a valid NetKey —
including a compromised, salvaged or resold node — can make itself the
forwarder for a chosen destination and then drop that traffic.

This is the surface studied in **"Tous les chemins mènent à DROP : une
évaluation de la sécurité d'un mécanisme de routage du Bluetooth Mesh"** by
Elies Tali, Romain Cayre, Vincent Nicomette and Guillaume Auriol (LAAS-CNRS),
presented at [SSTIC 2025](https://www.sstic.org/2025/presentation/).

**On what this can and cannot see.** Directed Forwarding control messages ride
inside encrypted Network PDUs. You **cannot** read `PATH_REQUEST` opcodes off
the air without the NetKey, and any tool claiming otherwise is lying to you.
So this command audits *exposure* — is DF present, is the configuration server
reachable, which 1.1 hardening is missing alongside it — using model IDs
(`0x0007` / `0x0008`), firmware symbols, and traffic shape. When you do
legitimately hold the NetKey for your own test network, `decode_control_pdu()`
decodes the opcodes.

---

### Channels — 40 of them, not 80

```bash
# Reference table of all 40 channels with Wi-Fi collisions marked
meshbreaker channels

# Predict where a connection hops next, from a captured CONNECT_IND
meshbreaker channels --connect-ind 112233445566aabbccddeeff... --events 30

# Bluetooth 5.0+ uses a different algorithm
meshbreaker channels --connect-ind <hex> --algorithm 2
```

BLE has **40 channels of 2 MHz each**. 40 × 2 = 80 MHz of spectrum, which is
where the "80" people repeat comes from — it is the bandwidth, not a channel
count. Three of the 40 carry advertising (37, 38, 39), the other 37 carry
connection data.

Once two devices connect they hop across the data channels, and the entire hop
sequence is derived from the `CONNECT_IND` packet sent at connection setup.
Catch that one packet and you have everything:

| Field | What it gives you |
|---|---|
| Access Address | The filter that identifies this connection |
| CRCInit | Validates the data packets |
| hopIncrement | The step size for algorithm #1 |
| channelMap | Which of the 37 channels are actually in use |
| Interval | Timing between connection events |

Miss it and you cannot follow the connection — which is why sniffing during
the pairing window matters so much, and why `sniff --backend sniffle` exists.

Two algorithms: **#1** walks in fixed steps (`next = (prev + hopIncrement) mod 37`),
**#2** (Bluetooth 5.0+) hashes the event counter against a channel identifier
derived from the Access Address. Both are implemented, both are deterministic
once you have the CONNECT_IND, and both handle the remapping that happens when
the peers disable noisy channels.

One practical note the table will show you: channel 39 (2480 MHz) sits above
Wi-Fi 11, so it is usually the cleanest of the three advertising channels. If a
capture is coming up empty on 37 or 38, a busy access point is a likely reason.

---

### Sniff — coverage, and real sniffing

```bash
# Run every adapter that is up, in parallel
meshbreaker sniff -d 60

# Pick your adapters
meshbreaker sniff --adapters hci0,hci1 -d 60

# Real channel-level sniffing with an nRF52840 running Sniffle
meshbreaker sniff --backend sniffle --channel 38

# Ubertooth
meshbreaker sniff --backend ubertooth -d 120
```

The default `hci` backend runs several adapters at once and merges what they
see. Be clear about what that buys you: each adapter is still hopping 37/38/39
under BlueZ's control, so you are buying **coverage through parallelism**, not
channel assignment. It meaningfully reduces missed adverts, and comparing RSSI
across adapters gives you a rough idea where a device physically is. It is not
enough to follow a connection.

For that, use `--backend sniffle` or `--backend ubertooth`. Captures land in
`output/` and the resulting JSON is in the same shape as `capture`, so
`parse-capture` and `provisioning` can read it directly.

---

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

14:22:18 [TGT] Target: AA:BB:CC:DD:EE:FF  RSSI -61 dBm  (MeshGateway-A1B2)
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
meshbreaker fuzz -m gatt

# Fuzz L2CAP PSMs (common ones by default)
meshbreaker fuzz -m l2cap

# Fuzz specific L2CAP PSMs
meshbreaker fuzz -m l2cap --psm 1,3,5,7

# Fuzz SDP
meshbreaker fuzz -m sdp

# Fuzz BLE Mesh (proxy PDUs)
meshbreaker fuzz -m mesh
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

### Directed Forwarding path injection (plugin)

```bash
# Build the message and print it — transmits nothing
meshbreaker exploit -m plugin --plugin-name df_path_inject \
    --netkey 7dd7364cd842ad18c17c2b820c84c3d6 \
    --iv-index 0x12345678 \
    --opt mode=path_request --opt src=0x0001 --opt path_target=0x0005 \
    --opt dry_run=true

# Inject into a proxy node for real
meshbreaker exploit -m plugin --plugin-name df_path_inject \
    -t AA:BB:CC:DD:EE:FF \
    --netkey <32 hex chars> --iv-index 0x12345678 \
    --opt mode=path_request --opt path_target=0x0005

# Exact bytes, when you have the spec open
meshbreaker exploit -m plugin --plugin-name df_path_inject \
    --netkey <key> --opt opcode=0x02 --opt params=deadbeef
```

`df` audits whether Directed Forwarding is exposed. This plugin is the other
half: it builds a real, encrypted network control message carrying a path
discovery opcode and writes it to a proxy node's Mesh Proxy Data In
characteristic, which the node processes as if it came from the mesh.

**This needs the NetKey, and that requirement is the finding — not a
limitation of the tool.** Directed Forwarding trusts the *network*, not the
node. Every node holding a valid NetKey is trusted by every other node to tell
the truth about routes, so one compromised, salvaged or second-hand node is
enough to poison path state and black-hole traffic for a chosen destination.
One cheap node against the whole routing plane. That asymmetry is the point
made in the SSTIC 2025 work.

Use it on a network you own or have been contracted to test.

| Option | Meaning |
|---|---|
| `--netkey` | 16-byte NetKey, hex. Required. |
| `--iv-index` | Network IV index, e.g. `0x12345678` |
| `--opt mode=` | `path_request`, `path_reply`, `path_confirmation`, `path_echo_request`, `path_echo_reply`, `dependent_node_update`, `path_request_solicitation` |
| `--opt src=` / `dst=` | Source and destination unicast addresses |
| `--opt path_target=` | Destination the injected route claims to reach |
| `--opt seq=` / `ttl=` | Sequence number and TTL |
| `--opt params=` | Raw parameter bytes, hex — bypasses the builders |
| `--opt mtu=` | Force an ATT MTU instead of using the negotiated one |
| `--opt dry_run=true` | Build and print, transmit nothing |

Segmentation happens **after** connecting, against the MTU the link actually
negotiated (`client.mtu_size`), not the 23-byte BLE default. A proxy PDU has to
fit in `ATT_MTU - 3`, and one of those bytes is the proxy header, so each write
carries `ATT_MTU - 4` payload bytes — 19 at the default, 243 at a commonly
negotiated 247. Most path control messages that would need two writes at the
default go in a single write on a real link, which is one less chance for the
node's reassembly to time out. `--opt mtu=` overrides it when you want to force
segmentation and watch how the node copes.

The plugin prints the derived key material first. **If the NID does not match
what you see in captured traffic from that network, your NetKey is wrong** and
nothing after that will work.

**On trusting the output.** The network layer in `src/modules/mesh_crypto.py`
is byte-exact against the sample vectors published in Mesh Profile 1.0.1 —
`k2`, `k3`, `k4`, `s1`, encryption, MIC and header obfuscation all reproduce
the spec's sample message #1 exactly, and the test suite asserts it. The
Directed Forwarding *parameter layouts* are a different matter: they are
reconstructed from the Mesh Protocol 1.1 text and have no public test vector
to check against. A node rejecting your PATH_REQUEST may mean the layout is
wrong rather than that the node is hardened. When it matters, read
§4.3.3 and pass exact bytes with `--opt params=`.

Bearer is **GATT Proxy only**. The ADV bearer needs raw advertising
transmission, which bleak cannot do — that route needs WHAD or Mirage and is
not wired up yet.

---

### Exploit

```bash
# List what plugins are loaded
meshbreaker exploit --list-plugins
```

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
