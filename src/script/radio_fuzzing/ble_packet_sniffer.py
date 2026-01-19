#!/usr/bin/env python3

import sys
import os
import time
import struct
import asyncio
from datetime import datetime
from collections import defaultdict
import logging

try:
    from scapy.all import *
    from scapy.layers.bluetooth import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from bleak import BleakScanner
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "ble_sniffer.log")

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

BLE_PDU_TYPES = {
    0x00: "ADV_IND", 0x01: "ADV_DIRECT_IND", 0x02: "ADV_NONCONN_IND", 0x03: "SCAN_REQ",
    0x04: "SCAN_RSP", 0x05: "CONNECT_REQ", 0x06: "ADV_SCAN_IND",
}

ATT_OPCODES = {
    0x01: "ATT_ERROR_RSP", 0x02: "ATT_EXCHANGE_MTU_REQ", 0x03: "ATT_EXCHANGE_MTU_RSP",
    0x04: "ATT_FIND_INFORMATION_REQ", 0x05: "ATT_FIND_INFORMATION_RSP",
    0x06: "ATT_FIND_BY_TYPE_VALUE_REQ", 0x07: "ATT_FIND_BY_TYPE_VALUE_RSP",
    0x08: "ATT_READ_BY_TYPE_REQ", 0x09: "ATT_READ_BY_TYPE_RSP", 0x0A: "ATT_READ_REQ",
    0x0B: "ATT_READ_RSP", 0x0C: "ATT_READ_BLOB_REQ", 0x0D: "ATT_READ_BLOB_RSP",
    0x12: "ATT_WRITE_REQ", 0x13: "ATT_WRITE_RSP", 0x52: "ATT_WRITE_CMD",
    0x1B: "ATT_HANDLE_VALUE_NTF", 0x1D: "ATT_HANDLE_VALUE_IND",
}

class BLEPacketSniffer:

    def __init__(self, interface: str = "hci0", output_pcap: str = None):
        self.interface = interface
        self.output_pcap = output_pcap
        self.packets_captured = 0
        self.packet_buffer = []
        self.statistics = defaultdict(int)
        self.devices_seen = {}
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available!")
            sys.exit(1)

    def parse_advertising_packet(self, packet):
        try:
            if packet.haslayer('BTLE_ADV'):
                adv_pdu = packet.getlayer('BTLE_ADV')
                info = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'advertising',
                    'pdu_type': BLE_PDU_TYPES.get(adv_pdu.PDU_type, f'Unknown({adv_pdu.PDU_type})'),
                    'tx_add': adv_pdu.TxAdd,
                    'rx_add': adv_pdu.RxAdd,
                    'length': adv_pdu.Length,
                    'adv_addr': None,
                    'data': {}
                }
                if hasattr(adv_pdu, 'AdvA'):
                    info['adv_addr'] = adv_pdu.AdvA
                if packet.haslayer('BTLE_ADV_IND'):
                    adv_data = packet.getlayer('BTLE_ADV_IND')
                    if hasattr(adv_data, 'data'):
                        info['data'] = self.parse_adv_data(bytes(adv_data.data))
                return info
        except Exception as e:
            logger.error(f"Error parsing advertising packet: {e}")
        return None

    def parse_adv_data(self, data: bytes) -> dict:
        parsed = {
            'flags': None, 'name': None, 'services': [], 'manufacturer': None,
            'tx_power': None, 'raw': data.hex()
        }
        offset = 0
        while offset < len(data):
            if offset + 1 > len(data): break
            length = data[offset]
            if length == 0: break
            if offset + 1 + length > len(data): break
            ad_type = data[offset + 1]
            ad_data = data[offset + 2:offset + 1 + length]

            if ad_type == 0x01:
                parsed['flags'] = ad_data[0] if len(ad_data) > 0 else None
            elif ad_type == 0x09:
                try: parsed['name'] = ad_data.decode('utf-8')
                except: parsed['name'] = ad_data.hex()
            elif ad_type == 0x08:
                if not parsed['name']:
                    try: parsed['name'] = ad_data.decode('utf-8')
                    except: parsed['name'] = ad_data.hex()
            elif ad_type == 0x03:
                for i in range(0, len(ad_data), 2):
                    if i + 2 <= len(ad_data):
                        uuid = struct.unpack('<H', ad_data[i:i+2])[0]
                        parsed['services'].append(f'{uuid:04X}')
            elif ad_type == 0x07:
                for i in range(0, len(ad_data), 16):
                    if i + 16 <= len(ad_data):
                        uuid = ad_data[i:i+16].hex()
                        parsed['services'].append(uuid)
            elif ad_type == 0xFF:
                if len(ad_data) >= 2:
                    company_id = struct.unpack('<H', ad_data[0:2])[0]
                    parsed['manufacturer'] = {'company_id': f'{company_id:04X}', 'data': ad_data[2:].hex()}
            elif ad_type == 0x0A:
                if len(ad_data) > 0:
                    parsed['tx_power'] = struct.unpack('b', ad_data[0:1])[0]
            offset += 1 + length
        return parsed

    def parse_att_packet(self, packet):
        try:
            if packet.haslayer('ATT_Hdr'):
                att = packet.getlayer('ATT_Hdr')
                info = {
                    'timestamp': datetime.now().isoformat(), 'type': 'att',
                    'opcode': ATT_OPCODES.get(att.opcode, f'Unknown({att.opcode:02X})'),
                    'opcode_raw': att.opcode,
                }
                if att.opcode == 0x0A:
                    if hasattr(att, 'gatt_handle'): info['handle'] = att.gatt_handle
                elif att.opcode == 0x0B:
                    if hasattr(att, 'value'): info['value'] = bytes(att.value).hex()
                elif att.opcode == 0x12:
                    if hasattr(att, 'gatt_handle'): info['handle'] = att.gatt_handle
                    if hasattr(att, 'data'): info['data'] = bytes(att.data).hex()
                elif att.opcode == 0x52:
                    if hasattr(att, 'gatt_handle'): info['handle'] = att.gatt_handle
                    if hasattr(att, 'data'): info['data'] = bytes(att.data).hex()
                elif att.opcode == 0x01:
                    if hasattr(att, 'request'): info['request_opcode'] = att.request
                    if hasattr(att, 'handle'): info['error_handle'] = att.handle
                    if hasattr(att, 'ecode'): info['error_code'] = att.ecode
                return info
        except Exception as e:
            logger.error(f"Error parsing ATT packet: {e}")
        return None

    def packet_callback(self, packet):
        self.packets_captured += 1
        parsed = None
        if packet.haslayer('BTLE_ADV'):
            parsed = self.parse_advertising_packet(packet)
            self.statistics['advertising'] += 1
            if parsed and parsed.get('adv_addr'):
                addr = parsed['adv_addr']
                if addr not in self.devices_seen:
                    self.devices_seen[addr] = {
                        'first_seen': datetime.now(), 'last_seen': datetime.now(),
                        'packet_count': 0, 'name': parsed['data'].get('name'),
                        'services': parsed['data'].get('services', [])
                    }
                else:
                    self.devices_seen[addr]['last_seen'] = datetime.now()
                    self.devices_seen[addr]['packet_count'] += 1
                    if parsed['data'].get('name'):
                        self.devices_seen[addr]['name'] = parsed['data']['name']
        elif packet.haslayer('ATT_Hdr'):
            parsed = self.parse_att_packet(packet)
            self.statistics['att'] += 1
        elif packet.haslayer('L2CAP_Hdr'):
            self.statistics['l2cap'] += 1
        else:
            self.statistics['other'] += 1

        if parsed:
            self.display_packet(parsed)
        if self.output_pcap:
            self.packet_buffer.append(packet)
            if len(self.packet_buffer) >= 100:
                self.write_pcap()

    def display_packet(self, info: dict):
        if info['type'] == 'advertising':
            logger.info(f"ADV: {info['pdu_type']}")
            if info.get('adv_addr'): logger.info(f"    Addr: {info['adv_addr']}")
            if info['data'].get('name'): logger.info(f"    Name: {info['data']['name']}")
            if info['data'].get('services'): logger.info(f"    Services: {', '.join(info['data']['services'])}")
            if info['data'].get('manufacturer'): logger.info(f"    Manufacturer: {info['data']['manufacturer']['company_id']}")
        elif info['type'] == 'att':
            logger.info(f"ATT: {info['opcode']}")
            if info.get('handle'): logger.info(f"    Handle: 0x{info['handle']:04X}")
            if info.get('value'): logger.info(f"    Value: {info['value'][:32]}...")
            if info.get('data'): logger.info(f"    Data: {info['data'][:32]}...")

    def write_pcap(self):
        if self.packet_buffer:
            wrpcap(self.output_pcap, self.packet_buffer, append=True)
            logger.info(f"Wrote {len(self.packet_buffer)} packets to {self.output_pcap}")
            self.packet_buffer = []

    def start_sniffing(self, duration: int = 0, packet_count: int = 0):
        logger.info("="*80)
        logger.info("BLE Packet Sniffer")
        logger.info(f"Interface: {self.interface}")
        if self.output_pcap:
            logger.info(f"Output: {self.output_pcap}")
        logger.info("Starting capture... (Ctrl+C to stop)\n")
        try:
            sniff(
                iface=self.interface, prn=self.packet_callback, store=0,
                timeout=duration if duration > 0 else None,
                count=packet_count if packet_count > 0 else 0
            )
        except KeyboardInterrupt:
            logger.info("\nCapture stopped by user")
        except PermissionError:
            logger.error("Permission denied. Run with sudo/admin privileges")
        except Exception as e:
            logger.error(f"Error during capture: {e}")
        finally:
            self.stop_sniffing()

    def stop_sniffing(self):
        if self.packet_buffer:
            self.write_pcap()
        logger.info("\n" + "="*80)
        logger.info("Capture Summary")
        logger.info("="*80)
        logger.info(f"Total packets: {self.packets_captured}")
        logger.info(f"Advertising: {self.statistics['advertising']}")
        logger.info(f"ATT: {self.statistics['att']}")
        logger.info(f"L2CAP: {self.statistics['l2cap']}")
        logger.info(f"Other: {self.statistics['other']}")
        logger.info(f"\nDevices seen: {len(self.devices_seen)}")
        for addr, info in self.devices_seen.items():
            logger.info(f"  {addr}")
            if info['name']: logger.info(f"    Name: {info['name']}")
            if info['services']: logger.info(f"    Services: {', '.join(info['services'])}")
            logger.info(f"    Packets: {info['packet_count']}")
        if self.output_pcap:
            logger.info(f"\nPCAP saved to: {self.output_pcap}")
            logger.info(f"Open with: wireshark {self.output_pcap}")
        logger.info("="*80)

def _run_async(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

def scan_ble_devices(timeout: int = 10):
    if not BLEAK_AVAILABLE:
        logger.error("Bleak not available. Install: pip install bleak")
        return []

    async def _scan():
        return await BleakScanner.discover(timeout=timeout)

    devices = _run_async(_scan())
    results = []
    logger.info(f"Scanning for BLE devices ({timeout}s)...")
    for dev in devices:
        metadata = dev.metadata or {}
        uuids = metadata.get("uuids", []) or []
        manufacturer = "Unknown"
        manufacturer_data = metadata.get("manufacturer_data", {})
        if manufacturer_data:
            company_id = sorted(manufacturer_data.keys())[0]
            manufacturer = f"CompanyID {company_id:04X}"
        info = {
            'addr': dev.address,
            'name': dev.name or 'Unknown',
            'rssi': dev.rssi,
            'services': uuids,
            'manufacturer': manufacturer
        }
        results.append(info)
        logger.info(f"  {info['addr']} - {info['name']} (RSSI: {info['rssi']} dBm)")
    return results

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BLE Packet Sniffer & Analyzer (Scapy-based)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  sudo python ble_packet_sniffer.py -o capture.pcap\n  sudo python ble_packet_sniffer.py -d 60\n  python ble_packet_sniffer.py --scan"
    )
    parser.add_argument('-i', '--interface', default='hci0', help='Bluetooth interface (default: hci0)')
    parser.add_argument('-o', '--output', help='Output PCAP file')
    parser.add_argument('-d', '--duration', type=int, default=0, help='Capture duration in seconds (0 = infinite)')
    parser.add_argument('-c', '--count', type=int, default=0, help='Stop after N packets (0 = infinite)')
    parser.add_argument('--scan', action='store_true', help='Scan only (cross-platform via Bleak)')
    parser.add_argument('--scan-timeout', type=int, default=10, help='Scan duration in seconds')
    args = parser.parse_args()

    if args.scan:
        if not BLEAK_AVAILABLE:
            print("Bleak not installed. Install: pip install bleak")
            sys.exit(1)
        scan_ble_devices(timeout=args.scan_timeout)
        return

    if not SCAPY_AVAILABLE:
        print("Scapy not installed. Install: pip install scapy")
        sys.exit(1)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("This script requires root privileges.")
        print("Run with: sudo python ble_packet_sniffer.py")
        sys.exit(1)

    sniffer = BLEPacketSniffer(interface=args.interface, output_pcap=args.output)
    sniffer.start_sniffing(duration=args.duration, packet_count=args.count)

if __name__ == "__main__":
    main()
