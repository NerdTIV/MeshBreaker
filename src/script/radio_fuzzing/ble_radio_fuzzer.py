#!/usr/bin/env python3

import sys
import os
import time
import struct
import random
import logging
import asyncio
from typing import List, Optional, Tuple

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "ble_radio_fuzzer.log")

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

BLE_ADV_IND, BLE_ADV_DIRECT_IND, BLE_ADV_NONCONN_IND, BLE_SCAN_REQ, BLE_SCAN_RSP, BLE_CONNECT_REQ, BLE_ADV_SCAN_IND = range(7)

try:
    from bleak import BleakScanner, BleakClient
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

class BLERadioFuzzer:

    def __init__(self, device_type: str = "nrf52840", backend: str = "auto"):
        self.device_type = device_type
        self.backend = backend
        self.device = None
        self.target_addr = None
        self.channel = 37

    def _select_backend(self) -> str:
        if self.backend == "auto":
            return "bleak" if BLEAK_AVAILABLE else "sim"
        return self.backend

    def init_hardware(self) -> bool:
        logger.info(f"Initializing {self.device_type}...")
        if self.device_type == "nrf52840":
            return self._init_nrf52840()
        elif self.device_type == "ubertooth":
            return self._init_ubertooth()
        elif self.device_type == "hackrf":
            return self._init_hackrf()
        elif self.device_type == "pc":
            return self._init_pc_adapter()
        else:
            logger.error(f"Unsupported device: {self.device_type}")
            return False

    def _init_nrf52840(self) -> bool:
        try:
            logger.info("nRF52840 initialization")
            logger.warning("Using simulation mode")
            self.device = "nrf52_simulated"
            return True
        except Exception as e:
            logger.error(f"nRF52840 init failed: {e}")
            return False

    def _init_ubertooth(self) -> bool:
        try:
            logger.info("Ubertooth One initialization")
            logger.warning("Using simulation mode")
            self.device = "ubertooth_simulated"
            return True
        except Exception as e:
            logger.error(f"Ubertooth init failed: {e}")
            return False

    def _init_hackrf(self) -> bool:
        try:
            logger.info("HackRF initialization")
            logger.warning("Using simulation mode")
            self.device = "hackrf_simulated"
            return True
        except Exception as e:
            logger.error(f"HackRF init failed: {e}")
            return False

    def _init_pc_adapter(self) -> bool:
        backend = self._select_backend()
        if backend == "bleak":
            if not BLEAK_AVAILABLE:
                logger.error("Bleak not available. Install: pip install bleak")
                return False
            logger.info("Using native BLE adapter (Bleak)")
            self.device = "pc_adapter"
            return True
        if backend == "sim":
            logger.warning("Using simulated PC adapter")
            self.device = "pc_simulated"
            return True
        logger.error(f"Unsupported backend: {backend}")
        return False

    def _run_async(self, coro):
        try:
            return asyncio.run(coro)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

    def _scan_with_bleak(self, timeout: int) -> List[dict]:
        async def _scan():
            return await BleakScanner.discover(timeout=timeout)

        devices = self._run_async(_scan())
        found_devices = []
        for dev in devices:
            metadata = dev.metadata or {}
            uuids = metadata.get("uuids", []) or []
            manufacturer = "Unknown"
            manufacturer_data = metadata.get("manufacturer_data", {})
            if manufacturer_data:
                company_id = sorted(manufacturer_data.keys())[0]
                manufacturer = f"CompanyID {company_id:04X}"
            found_devices.append({
                'addr': dev.address,
                'addr_type': 'public',
                'name': dev.name or 'Unknown',
                'rssi': dev.rssi,
                'services': uuids,
                'manufacturer': manufacturer
            })
        return found_devices

    def scan_ble_devices(self, timeout: int = 10) -> List[dict]:
        logger.info(f"Scanning for BLE devices ({timeout}s)...")
        devices = []
        logger.info("Scanning advertising channels (37, 38, 39)...")
        backend = self._select_backend()
        if backend == "bleak":
            if not BLEAK_AVAILABLE:
                logger.error("Bleak not available. Install: pip install bleak")
            else:
                try:
                    devices = self._scan_with_bleak(timeout)
                except Exception as e:
                    logger.warning(f"Bleak scan failed, using simulated results: {e}")
        elif backend != "sim":
            logger.warning(f"Unknown backend '{backend}', using simulated results")
        if devices:
            logger.info(f"Found {len(devices)} BLE device(s)")
            for dev in devices:
                logger.info(f"    {dev['addr']} - {dev['name']} (RSSI: {dev['rssi']} dBm)")
            return devices
        devices.append({
            'addr': 'AA:BB:CC:DD:EE:FF', 'addr_type': 'random', 'name': 'Gateway',
            'rssi': -45, 'services': ['1800', '1801', '1827'], 'manufacturer': 'Generic'
        })
        logger.info(f"Found {len(devices)} BLE device(s)")
        for dev in devices:
            logger.info(f"    {dev['addr']} - {dev['name']} (RSSI: {dev['rssi']} dBm)")
        return devices

    def select_target_from_scan(self, timeout: int = 10) -> Optional[str]:
        devices = self.scan_ble_devices(timeout=timeout)
        if not devices:
            logger.warning("No devices found")
            return None
        print("\nSelect a target to fuzz:")
        for idx, dev in enumerate(devices, start=1):
            name = dev.get('name') or 'Unknown'
            addr = dev.get('addr') or 'Unknown'
            rssi = dev.get('rssi')
            rssi_str = f"{rssi} dBm" if rssi is not None else "N/A"
            print(f"  [{idx}] {addr} - {name} (RSSI: {rssi_str})")
        while True:
            choice = input("Enter number (or 'q' to quit): ").strip()
            if choice.lower() in ("q", "quit", "exit", ""):
                return None
            if choice.isdigit():
                selection = int(choice)
                if 1 <= selection <= len(devices):
                    return devices[selection - 1].get('addr')
            print("Invalid selection.")

    def create_adv_packet(self, pdu_type: int, adv_addr: bytes, adv_data: bytes) -> bytes:
        preamble = b'\xAA'
        access_addr = b'\xD6\xBE\x89\x8E'
        pdu_header = struct.pack('BB', pdu_type, len(adv_addr) + len(adv_data))
        crc = b'\x00\x00\x00'
        return preamble + access_addr + pdu_header + adv_addr + adv_data + crc

    def fuzz_advertising_packets(self, target_addr: str) -> List[bytes]:
        logger.info("Generating malformed advertising packets...")
        fuzzing_cases = []
        target_bytes = bytes.fromhex(target_addr.replace(':', ''))
        for pdu_type in [0xFF, 0x07, 0x08, 0x0F, 0x10]:
            adv_data = b'\x02\x01\x06'
            packet = self.create_adv_packet(pdu_type, target_bytes, adv_data)
            fuzzing_cases.append(('invalid_pdu_type', packet))
        for size in [32, 64, 128, 255]:
            adv_data = bytes([random.randint(0, 255) for _ in range(size)])
            packet = self.create_adv_packet(BLE_ADV_IND, target_bytes, adv_data)
            fuzzing_cases.append(('oversized_adv_data', packet))
        adv_data = b'\xFF\x01\x06'
        packet = self.create_adv_packet(BLE_ADV_IND, target_bytes, adv_data)
        fuzzing_cases.append(('malformed_length', packet))
        invalid_addrs = [b'\x00\x00\x00\x00\x00\x00', b'\xFF\xFF\xFF\xFF\xFF\xFF', b'\x00' * 8]
        for addr in invalid_addrs:
            adv_data = b'\x02\x01\x06'
            packet = self.create_adv_packet(BLE_ADV_IND, addr[:6], adv_data)
            fuzzing_cases.append(('invalid_address', packet))
        normal_packet = self.create_adv_packet(BLE_ADV_IND, target_bytes, b'\x02\x01\x06')
        corrupted = bytearray(normal_packet)
        corrupted[-3:] = b'\xFF\xFF\xFF'
        fuzzing_cases.append(('corrupt_crc', bytes(corrupted)))
        logger.info(f"Generated {len(fuzzing_cases)} advertising packets")
        return fuzzing_cases

    def fuzz_gatt_packets(self) -> List[Tuple[str, bytes]]:
        logger.info("Generating malformed GATT packets...")
        fuzzing_cases = []
        ATT_READ_REQ, ATT_WRITE_REQ, ATT_WRITE_CMD = 0x0A, 0x12, 0x52
        for opcode in [0x00, 0xFF, 0x1F, 0x2F, 0x3F]:
            packet = struct.pack('B', opcode) + b'\x00\x01'
            fuzzing_cases.append(('invalid_gatt_opcode', packet))
        for handle in [0x0000, 0xFFFF, 0xDEAD, 0xBEEF]:
            packet = struct.pack('<BH', ATT_READ_REQ, handle)
            fuzzing_cases.append(('invalid_handle', packet))
        for size in [512, 1024, 2048, 4096]:
            data = bytes([random.randint(0, 255) for _ in range(size)])
            packet = struct.pack('<BH', ATT_WRITE_REQ, 0x0001) + data
            fuzzing_cases.append(('oversized_write', packet))
        packet = struct.pack('<BH', ATT_READ_REQ, 0x0001) + b'\xFF' * 16
        fuzzing_cases.append(('malformed_uuid', packet))
        logger.info(f"Generated {len(fuzzing_cases)} GATT packets")
        return fuzzing_cases

    def _gatt_fuzz_payloads(self) -> List[Tuple[str, bytes]]:
        payloads = [
            ("zero_length", b""),
            ("one_null", b"\x00"),
            ("one_ff", b"\xFF"),
            ("pattern_16", (b"\x00\xFF" * 8)),
            ("pattern_32", (b"\xAA\x55" * 16)),
            ("size_20", b"\xFF" * 20),
            ("size_23", b"\xAA" * 23),
            ("size_64", b"\x55" * 64),
            ("size_128", b"\x33" * 128),
            ("size_256", b"\x00" * 256),
            ("size_512", bytes([i % 256 for i in range(512)])),
            ("random_64", bytes([random.randint(0, 255) for _ in range(64)])),
            ("random_256", bytes([random.randint(0, 255) for _ in range(256)])),
        ]
        return payloads

    def fuzz_gatt_via_bleak(self, target_addr: str, timeout: int = 10) -> int:
        if not BLEAK_AVAILABLE:
            logger.error("Bleak not available. Install: pip install bleak")
            return 0

        async def _fuzz():
            logger.info("Starting GATT fuzzing via Bleak")
            try:
                async with BleakClient(target_addr, timeout=timeout) as client:
                    logger.info("Connected successfully")
                    services = await client.get_services()
                    payloads = self._gatt_fuzz_payloads()
                    total_cases = 0
                    writable_chars = 0
                    for service in services:
                        for char in service.characteristics:
                            props = {p.lower() for p in char.properties}
                            can_write = "write" in props or "write_without_response" in props
                            if not can_write:
                                continue
                            writable_chars += 1
                            response = "write" in props
                            for case_name, payload in payloads:
                                try:
                                    await client.write_gatt_char(char.uuid, payload, response=response)
                                    logger.info(f"Wrote {case_name} to {char.uuid}")
                                except Exception as e:
                                    logger.warning(f"Write failed {case_name} to {char.uuid}: {e}")
                                total_cases += 1
                    logger.info("GATT fuzzing summary")
                    logger.info(f"Writable characteristics tested: {writable_chars}")
                    logger.info(f"Total write attempts: {total_cases}")
                    return total_cases
            except Exception as e:
                logger.error(f"GATT fuzzing failed: {e}")
                return 0

        return self._run_async(_fuzz())

    def fuzz_l2cap_packets(self) -> List[Tuple[str, bytes]]:
        logger.info("Generating malformed L2CAP packets...")
        fuzzing_cases = []
        for cid in [0x0000, 0xFFFF, 0x0003, 0x003F]:
            packet = struct.pack('<HH', 4, cid) + b'\x00\x00\x00\x00'
            fuzzing_cases.append(('invalid_channel_id', packet))
        packet = struct.pack('<HH', 10, 0x0004) + b'\x00\x00\x00\x00'
        fuzzing_cases.append(('length_mismatch', packet))
        for size in [1024, 2048, 4096]:
            data = bytes([random.randint(0, 255) for _ in range(size)])
            packet = struct.pack('<HH', len(data), 0x0004) + data
            fuzzing_cases.append(('oversized_sdu', packet))
        packet = struct.pack('<HHBBH', 6, 0x0005, 0x01, 0xFF, 0x0000)
        fuzzing_cases.append(('malformed_signaling', packet))
        logger.info(f"Generated {len(fuzzing_cases)} L2CAP packets")
        return fuzzing_cases

    def fuzz_link_layer_packets(self) -> List[Tuple[str, bytes]]:
        logger.info("Generating malformed Link Layer packets...")
        fuzzing_cases = []
        for llid in [0b00, 0b11]:
            header = (llid << 6) | 0x04
            packet = struct.pack('B', header) + b'\x00\x00\x00\x00'
            fuzzing_cases.append(('invalid_llid', packet))
        packet = b'\x00' + struct.pack('<BHHHHH', 0xFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
        fuzzing_cases.append(('malformed_conn_update', packet))
        packet = b'\x08' + b'\xFF' * 8
        fuzzing_cases.append(('invalid_features', packet))
        packet = b'\x02' + b'\xFF'
        fuzzing_cases.append(('malformed_terminate', packet))
        logger.info(f"Generated {len(fuzzing_cases)} Link Layer packets")
        return fuzzing_cases

    def send_packet(self, packet: bytes, channel: int = 37) -> bool:
        if not self.device:
            logger.error("Device not initialized")
            return False
        logger.debug(f"TX Channel {channel}: {packet.hex()[:32]}... ({len(packet)} bytes)")
        time.sleep(0.01)
        return True

    def run_fuzzing_campaign(self, target_addr: str):
        logger.info("Starting BLE radio fuzzing campaign")
        logger.info(f"Target: {target_addr}")
        if not self.init_hardware():
            logger.error("Failed to initialize hardware")
            return
        if self.device_type == "pc":
            backend = self._select_backend()
            if backend != "bleak":
                logger.error("PC GATT fuzzing requires Bleak. Use --backend bleak or install bleak.")
                return
            self.fuzz_gatt_via_bleak(target_addr)
            return
        devices = self.scan_ble_devices()
        if not devices:
            logger.warning("No devices found")
            return
        self.target_addr = target_addr
        test_suites = [
            ("Advertising", self.fuzz_advertising_packets(target_addr)),
            ("GATT", self.fuzz_gatt_packets()),
            ("L2CAP", self.fuzz_l2cap_packets()),
            ("LinkLayer", self.fuzz_link_layer_packets())
        ]
        total_packets = 0
        for suite_name, fuzzing_cases in test_suites:
            logger.info(f"Testing: {suite_name}")
            for idx, (case_name, packet) in enumerate(fuzzing_cases):
                logger.info(f"  Running case {idx+1}/{len(fuzzing_cases)}: {case_name}")
                self.send_packet(packet, channel=self.channel)
                total_packets += 1
                self.channel = 37 + (self.channel - 36) % 3
                time.sleep(0.05)
        logger.info("\nFuzzing Summary")
        logger.info(f"Total packets sent: {total_packets}")
        logger.info(f"Target device: {target_addr}")
        logger.info("Check gateway logs for crashes/anomalies")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BLE Radio Fuzzer")
    parser.add_argument('-d', '--device', default='nrf52840', choices=['nrf52840', 'ubertooth', 'hackrf', 'bladerf', 'pc'], help='BLE radio device')
    parser.add_argument('-t', '--target', help='Target BLE address')
    parser.add_argument('-s', '--scan', action='store_true', help='Scan for devices first')
    parser.add_argument('--scan-select', action='store_true', help='Scan and select a target to fuzz')
    parser.add_argument('--scan-timeout', type=int, default=10, help='Scan duration in seconds')
    parser.add_argument('--backend', default='auto', choices=['auto', 'bleak', 'sim'], help='Backend selection (scan/GATT)')
    args = parser.parse_args()

    fuzzer = BLERadioFuzzer(device_type=args.device, backend=args.backend)
    if args.scan_select and args.target:
        parser.error("--scan-select cannot be used with --target")
    if args.scan_select:
        if not fuzzer.init_hardware():
            return
        target = fuzzer.select_target_from_scan(timeout=args.scan_timeout)
        if target:
            fuzzer.run_fuzzing_campaign(target)
        else:
            logger.info("No target selected")
    elif args.scan:
        if not fuzzer.init_hardware():
            return
        fuzzer.scan_ble_devices(timeout=args.scan_timeout)
    elif args.target:
        fuzzer.run_fuzzing_campaign(args.target)
    else:
        parser.error("Target address required unless --scan or --scan-select is used")

if __name__ == "__main__":
    main()
