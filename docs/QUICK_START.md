# Quick Start

## Installation

1.  **Install Dependencies**

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
    ```bash
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    ```

    Linux/macOS full setup (system packages + Python deps + venv):
    ```bash
    bash tools/INSTALL.sh
    ```

2.  **System Setup (Linux)**

    ```bash
    # Install Bluetooth libraries
    sudo apt-get install bluez bluez-tools bluetooth libbluetooth-dev libglib2.0-dev pkg-config build-essential python3-dev
    sudo systemctl enable --now bluetooth

    # Grant network capture permissions to Python
    sudo setcap cap_net_raw+eip $(which python3)
    ```

3.  **Hardware (for Radio Fuzzing)**

    For over-the-air fuzzing, you need a supported radio device like an nRF52840 dongle or an Ubertooth One. Ensure its drivers and firmware are correctly installed.

## Basic Usage

The tools are located in `src/`.
For best results (especially BLE radio access and sniffing), run the tools as Administrator/root (sudo).

### Radio Fuzzing

These tools interact with live BLE devices over the air.

1.  **Scan for devices:**
    ```bash
    python src/radio_fuzzing/ble_service_enumerator.py --scan --backend bleak
    ```

2.  **Enumerate a specific target's services:**
    ```bash
    python src/radio_fuzzing/ble_service_enumerator.py -t AA:BB:CC:DD:EE:FF --backend bleak
    ```

3.  **Sniff traffic to a PCAP file:**
    ```bash
    python src/radio_fuzzing/ble_packet_sniffer.py -o capture.pcap -d 60
    ```

4.  **Run the radio fuzzer against a target:**
    ```bash
    python src/radio_fuzzing/ble_radio_fuzzer.py --device pc --backend bleak --target AA:BB:CC:DD:EE:FF
    ```

### Firmware & Hardware Analysis

These tools perform static analysis on firmware or fuzz exposed hardware interfaces.

1.  **Extract secrets from a firmware binary:**
    ```bash
    python src/firmware_analysis/crypto_key_extractor.py /path/to/firmware.bin
    ```

2.  **Fuzz a network-accessible hardware interface:**
    ```bash
    python src/hardware_exploitation/network_to_hardware_fuzz.py -t 127.0.XXX.XXX -p XXXX
    ```

## Common Issues

-   **Permission Denied:** Most radio-related scripts require `sudo` to access Bluetooth hardware.
-   **bluepy not found:** Ensure you have installed the `bluepy` package and the system dependencies (`python3-bluez`, `libbluetooth-dev`) on Linux.
-   **No Devices Found:** Make sure your system's Bluetooth is enabled and the `hci` interface is up. You can check with `hciconfig`.
