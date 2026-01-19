<<<<<<< HEAD
# MeshBreaker
=======
## Disclaimer

This software is intended for use in authorized security testing and educational environments only. Do not use it on systems you do not have explicit permission to test. The authors are not responsible for any misuse.

## Overview

This suite contains tools for two main areas of testing:

1.  **Radio Fuzzing (Over-the-Air):** Tools for fuzzing the BLE protocol stack (GAP, GATT, L2CAP) of a target device via radio. Raw packet injection requires compatible hardware like an nRF52840 dongle or Ubertooth. A standard PC adapter can scan and enumerate but cannot inject raw link-layer packets.

2.  **Hardware & Firmware Analysis:** Tools for analyzing firmware binaries and fuzzing hardware peripherals (UART, SPI, I2C, etc.) if a corresponding interface is exposed.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/MeshBreaker.git
    cd MeshBreaker
    ```

2.  Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  Platform-specific setup:
    - Linux:
      ```bash
      sudo apt-get install bluez python3-bluez libbluetooth-dev
      sudo setcap cap_net_raw+eip $(which python3)
      ```
    - Windows:
      - Install Npcap if you want Scapy-based sniffing: https://npcap.com/
      - Built-in adapters support scan/enum via Bleak.

## Platform Support

- Linux: full scan/enum support; packet sniffing via Scapy; raw radio fuzzing requires external hardware.
- Windows: scan/enum via Bleak; packet sniffing is limited with standard adapters; raw radio fuzzing requires external hardware.

## Usage

All tools are located in the `src/script/` directory, categorized by function.

### Example: Enumerate a BLE device
```bash
cd src/script/radio_fuzzing/
sudo python ble_service_enumerator.py --scan
sudo python ble_service_enumerator.py -t AA:BB:CC:DD:EE:FF
```
On Windows, use Bleak:
```bash
cd src/script/radio_fuzzing/
python ble_service_enumerator.py --scan --backend bleak
python ble_service_enumerator.py -t AA:BB:CC:DD:EE:FF --backend bleak
```

### Example: GATT fuzzing with a PC adapter (Bleak)
```bash
cd src/script/radio_fuzzing/
python ble_radio_fuzzer.py --device pc --backend bleak --target AA:BB:CC:DD:EE:FF
```

### Example: Scan then select a target to fuzz
```bash
cd src/script/radio_fuzzing/
python ble_radio_fuzzer.py --device pc --backend bleak --scan-select
```

### Example: Analyze a firmware file
```bash
cd src/script/firmware_analysis/
python crypto_key_extractor.py /path/to/firmware.bin
```

### Example: Fuzz hardware peripherals (if network-accessible)
```bash
cd src/script/hardware_exploitation/
python hardware_fuzzer.py -t 192.168.1.100 -p 8888
```

Refer to the source code of each tool for more detailed options.

## Tools Included

-   **`ble_service_enumerator.py`**: Scans for BLE devices and enumerates their GATT services.
-   **`ble_packet_sniffer.py`**: Captures BLE traffic to a PCAP file using Scapy (Linux); use `--scan` for cross-platform discovery.
-   **`ble_radio_fuzzer.py`**: Sends malformed BLE packets over the air to fuzz the protocol stack (external radio required); PC adapters can run GATT fuzzing via Bleak.
-   **`crypto_key_extractor.py`**: Scans a firmware binary for hardcoded cryptographic keys and credentials.
-   **`hardware_fuzzer.py`**: Fuzzes common hardware peripherals like UART, SPI, and I2C.
>>>>>>> 1f6a08a (Initial commit)
