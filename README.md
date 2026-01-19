# MeshBreaker

## Disclaimer

This software is intended for authorized security testing and educational use only. Do not use it on systems you do not have explicit permission to test. The authors are not responsible for misuse.

## Overview

MeshBreaker is a toolkit for BLE protocol testing and firmware analysis. It includes:

- Radio fuzzing and enumeration for BLE (GAP, GATT, L2CAP).
- Firmware analysis helpers for key and credential extraction.
- Hardware interface fuzzing (UART, SPI, I2C) when exposed.

## Platform Support

- Linux: full scan/enum; Scapy sniffing; raw radio fuzzing requires external hardware.
- Windows: scan/enum via Bleak; sniffing limited with standard adapters; raw radio fuzzing requires external hardware.

## Requirements

- Python 3.7+
- Optional: Npcap on Windows for Scapy-based sniffing
- Optional: External radios (nRF52840 dongle, Ubertooth) for raw packet injection
- Optional: `pyserial` for local UART fuzzing
- Optional: `pyftdi` for FTDI-based I2C/SPI adapters
- Optional (Linux): `smbus2` and `spidev` for native I2C/SPI access

## Installation

1) Clone the repository:
```bash
git clone https://github.com/NerdTIV/MeshBreaker.git
cd MeshBreaker
```

2) Create and activate a virtual environment:
```bash
python -m venv .venv
```
Linux/macOS:
```bash
source .venv/bin/activate
```
Windows (PowerShell):
```powershell
.\.venv\Scripts\Activate.ps1
```

3) Install dependencies:
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Linux full setup (system packages + Python deps):
```bash
bash tools/INSTALL.sh
```

Optional hardware extras:
```bash
pip install .[hardware]
```

4) Platform setup:
- Linux:
```bash
sudo apt-get install bluez bluez-tools bluetooth libbluetooth-dev libglib2.0-dev pkg-config build-essential python3-dev
sudo systemctl enable --now bluetooth
sudo setcap cap_net_raw+eip $(which python3)
```
- Windows:
  - Install Npcap if you want Scapy-based sniffing: https://npcap.com/
  - Built-in adapters support scan/enum via Bleak.

## Quick Start

All tools live under `src/`.
For best results (especially BLE radio access and sniffing), run the tools as Administrator/root (sudo).

### Enumerate BLE devices
Scans BLE devices and enumerates GATT services and characteristics.

```bash
cd src/radio_fuzzing/
python ble_service_enumerator.py --scan --backend bleak
python ble_service_enumerator.py -t AA:BB:CC:DD:EE:FF --backend bleak
```

### BLE packet sniffing
Captures BLE traffic and writes PCAP output (best on Linux with Scapy).

```bash
cd src/radio_fuzzing/
python ble_packet_sniffer.py -o capture.pcap -d 60
```

### GATT fuzzing
Sends malformed BLE traffic to test target stack robustness.

```bash
cd src/radio_fuzzing/
python ble_radio_fuzzer.py --device pc --backend bleak --target AA:BB:CC:DD:EE:FF
```

### Firmware analysis
Scans firmware binaries for potential keys, secrets, and certificates.

```bash
cd src/firmware_analysis/
python crypto_key_extractor.py /path/to/firmware.bin
```

### Network Hardware fuzzing 
Fuzzes exposed hardware interfaces over the network (UART, SPI, I2C gateways).

```bash
cd src/hardware_exploitation/
python network_to_hardware_fuzz.py -t 127.0.XXX.XXX -p XXXX
```

### Physical hardware fuzzing
Targets local adapters (USB-UART, USB-I2C, USB-SPI). Use the `uart`, `i2c`, or `spi` subcommands.

```bash
cd src/hardware_exploitation/
python physical_hardware_fuzz.py --help
```

## Troubleshooting

- Windows BLE tools: use `--backend bleak` with a standard adapter.
- Scapy sniffing: requires Npcap on Windows or full Linux support.
- Large firmware files: consider SSD and sufficient RAM.

## License

MIT License. See `LICENSE`.
