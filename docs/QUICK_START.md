# Quick Start

## Installation

1.  **Install Dependencies**

    ```bash
    pip install -r requirements.txt
    ```

2.  **System Setup (Linux)**

    ```bash
    # Install Bluetooth libraries
    sudo apt-get install bluez python3-bluez libbluetooth-dev

    # Grant network capture permissions to Python
    sudo setcap cap_net_raw+eip $(which python3)
    ```

3.  **Hardware (for Radio Fuzzing)**

    For over-the-air fuzzing, you need a supported radio device like an nRF52840 dongle or an Ubertooth One. Ensure its drivers and firmware are correctly installed.

## Basic Usage

The tools are located in `src/script/`.

### Radio Fuzzing

These tools interact with live BLE devices over the air.

1.  **Scan for devices:**
    ```bash
    cd src/script/radio_fuzzing/
    sudo python ble_service_enumerator.py --scan
    ```

2.  **Enumerate a specific target's services:**
    ```bash
    sudo python ble_service_enumerator.py -t AA:BB:CC:DD:EE:FF
    ```

3.  **Sniff traffic to a PCAP file:**
    ```bash
    sudo python ble_packet_sniffer.py -o capture.pcap -d 60
    ```

4.  **Run the radio fuzzer against a target:**
    ```bash
    sudo python ble_radio_fuzzer.py --device nrf52840 --target AA:BB:CC:DD:EE:FF
    ```

### Firmware & Hardware Analysis

These tools perform static analysis on firmware or fuzz exposed hardware interfaces.

1.  **Extract secrets from a firmware binary:**
    ```bash
    cd src/script/firmware_analysis/
    python crypto_key_extractor.py /path/to/firmware.bin
    ```

2.  **Fuzz a network-accessible hardware interface:**
    ```bash
    cd src/script/hardware_exploitation/
    python hardware_fuzzer.py -t 192.168.1.50 -p 8888
    ```

## Common Issues

-   **Permission Denied:** Most radio-related scripts require `sudo` to access Bluetooth hardware.
-   **bluepy not found:** Ensure you have installed the `bluepy` package and the system dependencies (`python3-bluez`, `libbluetooth-dev`) on Linux.
-   **No Devices Found:** Make sure your system's Bluetooth is enabled and the `hci` interface is up. You can check with `hciconfig`.
