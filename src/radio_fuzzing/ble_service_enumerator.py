#!/usr/bin/env python3

import sys
import os
import time
import struct
import logging
import asyncio
import platform
from typing import List, Dict, Optional
from collections import defaultdict

try:
    from bluepy.btle import Scanner, Peripheral, UUID, DefaultDelegate, BTLEException
    BLUEPY_AVAILABLE = True
except ImportError:
    BLUEPY_AVAILABLE = False

try:
    from bleak import BleakScanner, BleakClient
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "ble_service_enum.log")

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

GATT_SERVICES = {
    0x1800: "Generic Access", 0x1801: "Generic Attribute", 0x1802: "Immediate Alert",
    0x1803: "Link Loss", 0x1804: "Tx Power", 0x1805: "Current Time Service",
    0x1806: "Reference Time Update Service", 0x180A: "Device Information", 0x180D: "Heart Rate",
    0x180F: "Battery Service", 0x1810: "Blood Pressure", 0x1811: "Alert Notification Service",
    0x1812: "Human Interface Device", 0x1813: "Scan Parameters", 0x1814: "Running Speed and Cadence",
    0x1815: "Automation IO", 0x1816: "Cycling Speed and Cadence", 0x1818: "Cycling Power",
    0x1819: "Location and Navigation", 0x181A: "Environmental Sensing", 0x181B: "Body Composition",
    0x181C: "User Data", 0x181D: "Weight Scale", 0x1827: "Mesh Provisioning Service",
    0x1828: "Mesh Proxy Service",
}

GATT_CHARACTERISTICS = {
    0x2A00: "Device Name", 0x2A01: "Appearance", 0x2A02: "Peripheral Privacy Flag",
    0x2A03: "Reconnection Address", 0x2A04: "Peripheral Preferred Connection Parameters",
    0x2A05: "Service Changed", 0x2A19: "Battery Level", 0x2A23: "System ID",
    0x2A24: "Model Number String", 0x2A25: "Serial Number String", 0x2A26: "Firmware Revision String",
    0x2A27: "Hardware Revision String", 0x2A28: "Software Revision String",
    0x2A29: "Manufacturer Name String", 0x2A37: "Heart Rate Measurement",
    0x2A49: "Blood Pressure Feature", 0x2A4D: "Report", 0x2A6E: "Temperature", 0x2A6F: "Humidity",
}

CHAR_PROPS = {
    0x01: "BROADCAST", 0x02: "READ", 0x04: "WRITE_WITHOUT_RESPONSE", 0x08: "WRITE",
    0x10: "NOTIFY", 0x20: "INDICATE", 0x40: "AUTHENTICATED_SIGNED_WRITES",
    0x80: "EXTENDED_PROPERTIES",
}


class BLEServiceEnumerator:

    def __init__(self, target_addr: str, addr_type: str = "public", backend: str = "auto"):
        self.target_addr = target_addr
        self.addr_type = addr_type
        self.peripheral = None
        self.services = {}
        self.characteristics = {}
        self.descriptors = {}
        self.backend = backend

        if self.backend == "auto":
            if BLEAK_AVAILABLE and platform.system() in ("Windows", "Darwin"):
                self.backend = "bleak"
            elif BLUEPY_AVAILABLE:
                self.backend = "bluepy"
            elif BLEAK_AVAILABLE:
                self.backend = "bleak"
            else:
                logger.error("Neither bluepy nor bleak is available.")
                sys.exit(1)

        if self.backend == "bluepy":
            if not BLUEPY_AVAILABLE:
                logger.error("bluepy not available!")
                sys.exit(1)
            if platform.system() != "Linux":
                logger.error("bluepy backend is supported on Linux only.")
                sys.exit(1)
        elif self.backend == "bleak":
            if not BLEAK_AVAILABLE:
                logger.error("bleak not available!")
                sys.exit(1)
        else:
            logger.error(f"Unsupported backend: {self.backend}")
            sys.exit(1)
        logger.info(f"Using backend: {self.backend}")

    def _run_async(self, coro):
        try:
            return asyncio.run(coro)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

    def _uuid_to_short(self, uuid_str: str) -> Optional[int]:
        try:
            if len(uuid_str) == 36:
                uuid_16bit = int(uuid_str.split('-')[0], 16)
                if uuid_16bit < 0x10000:
                    return uuid_16bit
        except Exception:
            return None
        return None

    def _scan_devices_bleak(self, timeout: int = 10) -> List[Dict]:
        async def _scan():
            try:
                return await BleakScanner.discover(timeout=timeout, return_adv=True)
            except TypeError:
                return await BleakScanner.discover(timeout=timeout)

        results = self._run_async(_scan())
        found_devices = []

        if isinstance(results, dict):
            items = results.values()
        else:
            items = results or []

        for item in items:
            if isinstance(item, tuple) and len(item) == 2:
                dev, adv = item
            else:
                dev, adv = item, None

            if dev is None:
                continue

            metadata = getattr(dev, "metadata", None) or {}
            name = dev.name or metadata.get("name") or "Unknown"

            service_uuids = []
            if adv is not None:
                if hasattr(adv, "service_uuids") and adv.service_uuids:
                    service_uuids = list(adv.service_uuids)
                elif isinstance(adv, dict):
                    service_uuids = adv.get("service_uuids", []) or adv.get("uuids", []) or []
            if not service_uuids:
                service_uuids = metadata.get("service_uuids", []) or metadata.get("uuids", []) or []

            rssi = getattr(dev, "rssi", None)
            if rssi is None and adv is not None:
                rssi = getattr(adv, "rssi", None)
                if rssi is None and isinstance(adv, dict):
                    rssi = adv.get("rssi")

            connectable = True
            if adv is not None:
                if hasattr(adv, "connectable"):
                    connectable = bool(adv.connectable)
                elif isinstance(adv, dict) and "connectable" in adv:
                    connectable = bool(adv.get("connectable"))

            device_info = {
                'addr': dev.address,
                'addr_type': 'public',
                'rssi': rssi,
                'connectable': connectable,
                'scan_data': {
                    'name': name,
                    'uuids': service_uuids
                }
            }
            found_devices.append(device_info)

            rssi_display = rssi if rssi is not None else "N/A"
            logger.info(f"  {dev.address} (public) RSSI={rssi_display}")
            if name and name != "Unknown":
                logger.info(f"    Name: {name}")

        return found_devices

    def _run_full_enumeration_bleak(self, export_json: str = None) -> bool:
        async def _enumerate():
            logger.info(f"Connecting to {self.target_addr}...")
            try:
                async with BleakClient(self.target_addr) as client:
                    logger.info("Connected successfully")
                    services = None
                    if hasattr(client, "get_services"):
                        try:
                            services = await client.get_services()
                        except Exception as e:
                            logger.debug(f"Bleak get_services failed: {e}")
                    if services is None:
                        services = getattr(client, "services", None)
                    if services is None:
                        logger.error("Service discovery failed.")
                        return False
            except Exception as e:
                logger.error(f"Connection failed: {e}")
                return False

            self.services = {}
            self.characteristics = {}
            self.descriptors = {}

            for service in services:
                uuid_str = str(service.uuid)
                uuid_short = self._uuid_to_short(uuid_str)
                service_name = GATT_SERVICES.get(uuid_short, "Unknown Service") if uuid_short else "Custom Service"
                service_info = {
                    'uuid': uuid_str,
                    'uuid_short': uuid_short,
                    'name': service_name,
                    'handle_start': 0,
                    'handle_end': 0,
                    'characteristics': []
                }
                self.services[uuid_str] = service_info
                logger.info(f"  Service: {uuid_str}")
                logger.info(f"    Name: {service_name}")

                for char in service.characteristics:
                    char_uuid = str(char.uuid)
                    char_short = self._uuid_to_short(char_uuid)
                    char_name = GATT_CHARACTERISTICS.get(char_short, "Unknown Characteristic") if char_short else "Custom Characteristic"
                    props = [p.upper().replace('-', '_') for p in char.properties]
                    handle = char.handle if isinstance(char.handle, int) else 0
                    char_key = handle if handle else f"{uuid_str}:{char_uuid}"
                    char_info = {
                        'uuid': char_uuid,
                        'uuid_short': char_short,
                        'name': char_name,
                        'handle': handle,
                        'value_handle': handle,
                        'properties': props,
                        'properties_raw': None
                    }
                    self.characteristics[char_key] = char_info
                    service_info['characteristics'].append(char_info)
                    logger.info(f"  Characteristic: {char_uuid}")
                    logger.info(f"    Name: {char_name}")
                    logger.info(f"    Properties: {', '.join(props)}")

                    for desc in char.descriptors:
                        desc_handle = desc.handle if isinstance(desc.handle, int) else 0
                        desc_key = desc_handle if desc_handle else f"{char_key}:{desc.uuid}"
                        desc_info = {
                            'uuid': str(desc.uuid),
                            'handle': desc_handle
                        }
                        self.descriptors[desc_key] = desc_info

            return True

        ok = self._run_async(_enumerate())
        if not ok:
            return False
        self.generate_attack_surface_map()
        if export_json:
            self.export_to_json(export_json)
        return True

    def scan_devices(self, timeout: int = 10) -> List[Dict]:
        logger.info(f"Scanning for BLE devices ({timeout}s)...")
        if self.backend == "bleak":
            return self._scan_devices_bleak(timeout)
        try:
            scanner = Scanner()
            devices = scanner.scan(timeout)

            found_devices = []
            for dev in devices:
                device_info = {
                    'addr': dev.addr,
                    'addr_type': dev.addrType,
                    'rssi': dev.rssi,
                    'connectable': dev.connectable,
                    'scan_data': {}
                }
                for (adtype, desc, value) in dev.getScanData():
                    device_info['scan_data'][desc] = value
                found_devices.append(device_info)

                logger.info(f"  {dev.addr} ({dev.addrType}) RSSI={dev.rssi}")
                if 'Complete Local Name' in device_info['scan_data']:
                    logger.info(f"    Name: {device_info['scan_data']['Complete Local Name']}")
            return found_devices
        except BTLEException as e:
            logger.error(f"Scan error: {e}")
            return []

    def connect(self) -> bool:
        logger.info(f"Connecting to {self.target_addr}...")
        try:
            self.peripheral = Peripheral(self.target_addr, self.addr_type)
            logger.info(f"Connected successfully")
            return True
        except BTLEException as e:
            logger.error(f"Connection failed: {e}")
            return False

    def disconnect(self):
        if self.peripheral:
            try:
                self.peripheral.disconnect()
                logger.info("Disconnected")
            except:
                pass

    def enumerate_services(self) -> Dict:
        if not self.peripheral:
            logger.error("Not connected")
            return {}
        logger.info("Enumerating services...")
        try:
            services = self.peripheral.getServices()
            for service in services:
                uuid_str = str(service.uuid)
                uuid_short = None
                try:
                    if len(uuid_str) == 36:
                        uuid_16bit = int(uuid_str.split('-')[0], 16)
                        if uuid_16bit < 0x10000:
                            uuid_short = uuid_16bit
                except:
                    pass
                service_name = GATT_SERVICES.get(uuid_short, "Unknown Service") if uuid_short else "Custom Service"
                self.services[service.hndl] = {
                    'uuid': uuid_str,
                    'uuid_short': uuid_short,
                    'name': service_name,
                    'handle_start': service.hndlStart,
                    'handle_end': service.hndlEnd,
                    'characteristics': []
                }
                logger.info(f"  Service: {uuid_str}")
                logger.info(f"    Name: {service_name}")
                logger.info(f"    Handles: 0x{service.hndlStart:04X} - 0x{service.hndlEnd:04X}")
            logger.info(f"Found {len(self.services)} services")
            return self.services
        except BTLEException as e:
            logger.error(f"Service enumeration error: {e}")
            return {}

    def enumerate_characteristics(self) -> Dict:
        if not self.peripheral or not self.services:
            logger.error("Services not enumerated")
            return {}
        logger.info("Enumerating characteristics...")
        try:
            characteristics = self.peripheral.getCharacteristics()
            for char in characteristics:
                uuid_str = str(char.uuid)
                uuid_short = None
                try:
                    if len(uuid_str) == 36:
                        uuid_16bit = int(uuid_str.split('-')[0], 16)
                        if uuid_16bit < 0x10000:
                            uuid_short = uuid_16bit
                except:
                    pass
                char_name = GATT_CHARACTERISTICS.get(uuid_short, "Unknown Characteristic") if uuid_short else "Custom Characteristic"
                props = []
                for bit, name in CHAR_PROPS.items():
                    if char.properties & bit:
                        props.append(name)
                char_info = {
                    'uuid': uuid_str,
                    'uuid_short': uuid_short,
                    'name': char_name,
                    'handle': char.getHandle(),
                    'value_handle': char.valHandle,
                    'properties': props,
                    'properties_raw': char.properties
                }
                self.characteristics[char.getHandle()] = char_info
                for svc_handle, svc_info in self.services.items():
                    if svc_info['handle_start'] <= char.getHandle() <= svc_info['handle_end']:
                        svc_info['characteristics'].append(char_info)
                        break
                logger.info(f"  Characteristic: {uuid_str}")
                logger.info(f"    Name: {char_name}")
                logger.info(f"    Handle: 0x{char.getHandle():04X}")
                logger.info(f"    Properties: {', '.join(props)}")
            logger.info(f"Found {len(self.characteristics)} characteristics")
            return self.characteristics
        except BTLEException as e:
            logger.error(f"Characteristic enumeration error: {e}")
            return {}

    def read_characteristic(self, handle: int) -> Optional[bytes]:
        try:
            char = self.peripheral.getCharacteristics(uuid=None, forUUID=None)[0]
            value = self.peripheral.readCharacteristic(handle)
            return value
        except BTLEException as e:
            logger.debug(f"Cannot read handle 0x{handle:04X}: {e}")
            return None

    def enumerate_descriptors(self) -> Dict:
        if not self.peripheral:
            logger.error("Not connected")
            return {}
        logger.info("Enumerating descriptors...")
        try:
            descriptors = self.peripheral.getDescriptors()
            for desc in descriptors:
                desc_info = {
                    'uuid': str(desc.uuid),
                    'handle': desc.handle
                }
                self.descriptors[desc.handle] = desc_info
                logger.debug(f"  Descriptor: {desc.uuid} @ 0x{desc.handle:04X}")
            logger.info(f"Found {len(self.descriptors)} descriptors")
            return self.descriptors
        except BTLEException as e:
            logger.error(f"Descriptor enumeration error: {e}")
            return {}

    def generate_attack_surface_map(self):
        logger.info("\n" + "="*80)
        logger.info("Attack Surface Map")
        logger.info("="*80)

        writable_chars = []
        readable_chars = []
        notify_chars = []
        custom_services = []

        for svc_handle, svc_info in self.services.items():
            if svc_info['uuid_short'] is None or svc_info['name'] == "Custom Service":
                custom_services.append(svc_info)
            for char in svc_info['characteristics']:
                if 'WRITE' in char['properties'] or 'WRITE_WITHOUT_RESPONSE' in char['properties']:
                    writable_chars.append(char)
                if 'READ' in char['properties']:
                    readable_chars.append(char)
                if 'NOTIFY' in char['properties'] or 'INDICATE' in char['properties']:
                    notify_chars.append(char)

        logger.info(f"\nCustom Services: {len(custom_services)}")
        for svc in custom_services:
            logger.info(f"  {svc['uuid']} (0x{svc['handle_start']:04X}-0x{svc['handle_end']:04X})")

        logger.info(f"\nWritable Characteristics: {len(writable_chars)}")
        for char in writable_chars:
            logger.info(f"  [0x{char['handle']:04X}] {char['name']}")
            logger.info(f"    UUID: {char['uuid']}")
            logger.info(f"    Properties: {', '.join(char['properties'])}")

        logger.info(f"\nReadable Characteristics: {len(readable_chars)}")
        for char in readable_chars[:10]:
            logger.info(f"  [0x{char['handle']:04X}] {char['name']}")

        logger.info(f"\nNotify/Indicate Characteristics: {len(notify_chars)}")
        for char in notify_chars[:10]:
            logger.info(f"  [0x{char['handle']:04X}] {char['name']}")
        logger.info("\n" + "="*80)

    def export_to_json(self, output_file: str):
        import json
        export_data = {
            'target': self.target_addr,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'services': self.services,
            'characteristics': self.characteristics,
            'descriptors': self.descriptors
        }
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        logger.info(f"Exported to {output_file}")

    def run_full_enumeration(self, export_json: str = None):
        logger.info("="*80)
        logger.info("BLE Service Enumerator")
        logger.info(f"Target: {self.target_addr}")
        logger.info("="*80)
        if self.backend == "bleak":
            return self._run_full_enumeration_bleak(export_json)
        if not self.connect():
            return False
        try:
            self.enumerate_services()
            self.enumerate_characteristics()
            self.enumerate_descriptors()
            self.generate_attack_surface_map()
            if export_json:
                self.export_to_json(export_json)
            return True
        finally:
            self.disconnect()

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BLE Service Enumerator (bluepy/bleak)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:\n  sudo python ble_service_enumerator.py --scan\n  sudo python ble_service_enumerator.py -t AA:BB:CC:DD:EE:FF\n  python ble_service_enumerator.py --scan --backend bleak"""
    )
    parser.add_argument('--scan', action='store_true', help='Scan for BLE devices')
    parser.add_argument('--scan-timeout', type=int, default=15, help='Scan duration in seconds')
    parser.add_argument('-t', '--target', help='Target BLE address (AA:BB:CC:DD:EE:FF)')
    parser.add_argument('-a', '--addr-type', default='public', choices=['public', 'random'], help='Address type (default: public)')
    parser.add_argument('-o', '--output', help='Export to JSON file')
    parser.add_argument('--backend', default='auto', choices=['auto', 'bluepy', 'bleak'], help='BLE backend')
    args = parser.parse_args()

    def require_root_if_needed(backend: str):
        if backend == "bluepy" and hasattr(os, "geteuid") and os.geteuid() != 0:
            print("This backend requires root privileges.")
            print("Run with: sudo python ble_service_enumerator.py")
            sys.exit(1)

    if args.scan:
        enumerator = BLEServiceEnumerator("00:00:00:00:00:00", backend=args.backend)
        require_root_if_needed(enumerator.backend)
        devices = enumerator.scan_devices(timeout=args.scan_timeout)
        print(f"\nFound {len(devices)} device(s)")
        print("\nTo enumerate a device, run:")
        cmd_prefix = "sudo python" if enumerator.backend == "bluepy" else "python"
        for dev in devices:
            print(f"  {cmd_prefix} ble_service_enumerator.py -t {dev['addr']}")
    elif args.target:
        enumerator = BLEServiceEnumerator(args.target, args.addr_type, backend=args.backend)
        require_root_if_needed(enumerator.backend)
        enumerator.run_full_enumeration(export_json=args.output)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
