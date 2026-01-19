# MeshBreaker BLE Suite

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

## Installation

1) Clone the repository:
```bash
git clone https://github.com/yourusername/MeshBreaker.git
cd MeshBreaker
```

2) Install dependencies:
```bash
pip install -r requirements.txt
```

3) Platform setup:
- Linux:
```bash
sudo apt-get install bluez python3-bluez libbluetooth-dev
sudo setcap cap_net_raw+eip $(which python3)
```
- Windows:
  - Install Npcap if you want Scapy-based sniffing: https://npcap.com/
  - Built-in adapters support scan/enum via Bleak.

## Quick Start

All tools live under `src/script/`.

### Enumerate BLE devices
```bash
cd src/script/radio_fuzzing/
python ble_service_enumerator.py --scan --backend bleak
python ble_service_enumerator.py -t AA:BB:CC:DD:EE:FF --backend bleak
```

### GATT fuzzing (PC adapter with Bleak)
```bash
cd src/script/radio_fuzzing/
python ble_radio_fuzzer.py --device pc --backend bleak --target AA:BB:CC:DD:EE:FF
```

### Firmware analysis
```bash
cd src/script/firmware_analysis/
python crypto_key_extractor.py /path/to/firmware.bin
```

### Hardware fuzzing (if network-accessible)
```bash
cd src/script/hardware_exploitation/
python hardware_fuzzer.py -t 192.168.1.100 -p 8888
```

## Tools Included

- `ble_service_enumerator.py`: Scans for BLE devices and enumerates GATT services.
- `ble_packet_sniffer.py`: Captures BLE traffic to PCAP using Scapy (Linux); use `--scan` cross-platform.
- `ble_radio_fuzzer.py`: Sends malformed BLE packets; PC adapters can use Bleak for GATT fuzzing.
- `crypto_key_extractor.py`: Scans firmware for cryptographic keys and credentials.
- `hardware_fuzzer.py`: Fuzzes UART, SPI, and I2C endpoints.

## Project Layout

```
src/script/
  radio_fuzzing/
  firmware_analysis/
  hardware_exploitation/
tests/
docs/
```

## Troubleshooting

- Windows BLE tools: use `--backend bleak` with a standard adapter.
- Scapy sniffing: requires Npcap on Windows or full Linux support.
- Large firmware files: consider SSD and sufficient RAM.

## License

MIT License. See `LICENSE`.
