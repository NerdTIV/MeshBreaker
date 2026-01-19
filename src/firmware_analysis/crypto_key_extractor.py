#!/usr/bin/env python3

import sys
import os
import re
import struct
import hashlib
import logging
import math
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

try:
    from Crypto.PublicKey import RSA, ECC
    from Crypto.Cipher import AES
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("pycryptodome not installed. Install: pip install pycryptodome")

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "crypto_extractor.log")

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
])

SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
]

BLE_MESH_LABEL_UUID = bytes.fromhex("00000000-0000-0000-0000-000000000000".replace('-', ''))


class CryptoKeyExtractor:

    def __init__(self, firmware_path: str):
        self.firmware_path = firmware_path
        self.firmware_data = None
        self.size = 0
        self.findings = {
            'aes_keys': [],
            'rsa_keys': [],
            'ecc_keys': [],
            'ble_mesh_keys': [],
            'passwords': [],
            'certificates': [],
            'entropy_regions': []
        }

    def load_firmware(self) -> bool:
        try:
            with open(self.firmware_path, 'rb') as f:
                self.firmware_data = f.read()
            self.size = len(self.firmware_data)
            logger.info(f"Loaded firmware: {self.size:,} bytes")
            return True
        except Exception as e:
            logger.error(f"Error loading firmware: {e}")
            return False

    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0

        entropy = 0.0
        byte_counts = [0] * 256

        for byte in data:
            byte_counts[byte] += 1

        for count in byte_counts:
            if count == 0:
                continue
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

        return entropy

    def find_high_entropy_regions(self, block_size: int = 32, threshold: float = 7.0) -> List[Dict]:
        logger.info(f"Scanning for high entropy regions (threshold: {threshold})...")

        high_entropy_regions = []

        for offset in range(0, len(self.firmware_data) - block_size, block_size):
            block = self.firmware_data[offset:offset + block_size]
            entropy = self.calculate_entropy(block)

            if entropy >= threshold:
                if block != b'\x00' * block_size and block != b'\xff' * block_size:
                    high_entropy_regions.append({
                        'offset': offset,
                        'size': block_size,
                        'entropy': entropy,
                        'data': block
                    })

        merged = []
        if high_entropy_regions:
            current = high_entropy_regions[0].copy()

            for region in high_entropy_regions[1:]:
                if region['offset'] == current['offset'] + current['size']:
                    current['size'] += region['size']
                    current['data'] += region['data']
                    current['entropy'] = max(current['entropy'], region['entropy'])
                else:
                    merged.append(current)
                    current = region.copy()

            merged.append(current)

        logger.info(f"Found {len(merged)} high entropy regions")
        return merged

    def find_aes_keys(self) -> List[Dict]:
        logger.info("Searching for AES keys...")

        aes_keys = []
        key_sizes = [16, 24, 32]

        sbox_offsets = []
        for i in range(len(self.firmware_data) - len(AES_SBOX)):
            if self.firmware_data[i:i+len(AES_SBOX)] == AES_SBOX:
                sbox_offsets.append(i)
                logger.info(f"  Found AES S-box at 0x{i:08X}")

        for offset in range(0, len(self.firmware_data) - 32, 4):
            for key_size in key_sizes:
                if offset + key_size > len(self.firmware_data):
                    continue

                key_candidate = self.firmware_data[offset:offset + key_size]
                entropy = self.calculate_entropy(key_candidate)
                unique_bytes = len(set(key_candidate))

                if entropy >= 4.5 and unique_bytes >= key_size // 2:
                    if key_candidate != bytes([key_candidate[0]]) * key_size:
                        near_sbox = any(abs(offset - sbox_off) < 1024 for sbox_off in sbox_offsets)
                        context = self.firmware_data[max(0, offset-100):min(len(self.firmware_data), offset+100)]
                        has_crypto_string = any(x in context.lower() for x in [b'key', b'aes', b'cipher', b'crypt'])

                        confidence = 0
                        if near_sbox:
                            confidence += 40
                        if has_crypto_string:
                            confidence += 30
                        if entropy >= 7.0:
                            confidence += 20
                        if unique_bytes == key_size:
                            confidence += 10

                        if confidence >= 30:
                            aes_keys.append({
                                'offset': offset,
                                'size': key_size,
                                'type': f'AES-{key_size*8}',
                                'key': key_candidate,
                                'key_hex': key_candidate.hex(),
                                'entropy': entropy,
                                'confidence': confidence,
                                'near_sbox': near_sbox,
                                'has_crypto_context': has_crypto_string
                            })

        seen_keys = set()
        unique_keys = []
        for key in aes_keys:
            if key['key_hex'] not in seen_keys:
                seen_keys.add(key['key_hex'])
                unique_keys.append(key)

        logger.info(f"Found {len(unique_keys)} potential AES keys")
        return unique_keys

    def find_rsa_keys(self) -> List[Dict]:
        logger.info("Searching for RSA keys...")

        rsa_keys = []

        pem_patterns = [
            b'-----BEGIN RSA PRIVATE KEY-----',
            b'-----BEGIN PRIVATE KEY-----',
            b'-----BEGIN EC PRIVATE KEY-----',
        ]

        for pattern in pem_patterns:
            offset = 0
            while True:
                offset = self.firmware_data.find(pattern, offset)
                if offset == -1:
                    break

                end_pattern = pattern.replace(b'BEGIN', b'END')
                end_offset = self.firmware_data.find(end_pattern, offset)

                if end_offset != -1:
                    pem_data = self.firmware_data[offset:end_offset + len(end_pattern)]

                    rsa_keys.append({
                        'offset': offset,
                        'type': 'RSA PEM',
                        'data': pem_data,
                        'size': len(pem_data)
                    })

                    logger.info(f"  Found RSA key (PEM) at 0x{offset:08X}")

                offset += len(pattern)

        der_pattern = b'\x30\x82'

        offset = 0
        while True:
            offset = self.firmware_data.find(der_pattern, offset)
            if offset == -1:
                break

            try:
                if offset + 4 > len(self.firmware_data):
                    break

                length = struct.unpack('>H', self.firmware_data[offset+2:offset+4])[0]

                if length > 100 and length < 10000:
                    key_data = self.firmware_data[offset:offset+4+length]

                    if b'\x02\x01\x00' in key_data[:20]:
                        rsa_keys.append({
                            'offset': offset,
                            'type': 'RSA DER',
                            'data': key_data,
                            'size': len(key_data)
                        })

                        logger.info(f"  Found RSA key (DER) at 0x{offset:08X}")
            except:
                pass

            offset += 1

        return rsa_keys

    def find_ble_mesh_keys(self) -> List[Dict]:
        logger.info("Searching for BLE Mesh keys...")

        mesh_keys = []
        mesh_keywords = [b'netkey', b'appkey', b'devkey', b'mesh', b'provision']

        for keyword in mesh_keywords:
            offset = 0
            while True:
                offset = self.firmware_data.find(keyword, offset)
                if offset == -1:
                    break

                search_start = max(0, offset - 64)
                search_end = min(len(self.firmware_data), offset + 128)

                for key_offset in range(search_start, search_end - 16):
                    key_candidate = self.firmware_data[key_offset:key_offset + 16]

                    entropy = self.calculate_entropy(key_candidate)
                    unique = len(set(key_candidate))

                    if entropy >= 3.5 and unique >= 8:
                        mesh_keys.append({
                            'offset': key_offset,
                            'type': f'BLE Mesh Key (near "{keyword.decode()}")', 'key': key_candidate,
                            'key_hex': key_candidate.hex(),
                            'entropy': entropy,
                            'context_offset': offset
                        })

                offset += len(keyword)

        seen = set()
        unique = []
        for key in mesh_keys:
            if key['key_hex'] not in seen:
                seen.add(key['key_hex'])
                unique.append(key)

        logger.info(f"Found {len(unique)} potential BLE Mesh keys")
        return unique

    def find_hardcoded_passwords(self) -> List[Dict]:
        logger.info("Searching for hardcoded credentials...")

        credentials = []
        patterns = [
            (rb'password[\s:=]+([a-zA-Z0-9!@#$%^&*]{4,32})', 'Password'),
            (rb'passwd[\s:=]+([a-zA-Z0-9!@#$%^&*]{4,32})', 'Password'),
            (rb'pwd[\s:=]+([a-zA-Z0-9!@#$%^&*]{4,32})', 'Password'),
            (rb'secret[\s:=]+([a-zA-Z0-9!@#$%^&*]{4,64})', 'Secret'),
            (rb'api[_-]?key[\s:=]+([a-zA-Z0-9]{16,64})', 'API Key'),
            (rb'token[\s:=]+([a-zA-Z0-9]{16,128})', 'Token'),
            (rb'admin:[a-zA-Z0-9]{4,32}', 'Admin Credentials'),
            (rb'root:[a-zA-Z0-9]{4,32}', 'Root Credentials'),
        ]

        for pattern, cred_type in patterns:
            matches = re.finditer(pattern, self.firmware_data, re.IGNORECASE)

            for match in matches:
                offset = match.start()
                matched_str = match.group(0)

                credentials.append({
                    'offset': offset,
                    'type': cred_type,
                    'data': matched_str,
                    'string': matched_str.decode('utf-8', errors='ignore')
                })

                logger.info(f"  Found {cred_type} at 0x{offset:08X}")

        return credentials

    def find_certificates(self) -> List[Dict]:
        logger.info("Searching for X.509 certificates...")

        certs = []
        cert_start = b'-----BEGIN CERTIFICATE-----'
        cert_end = b'-----END CERTIFICATE-----'

        offset = 0
        while True:
            offset = self.firmware_data.find(cert_start, offset)
            if offset == -1:
                break

            end_offset = self.firmware_data.find(cert_end, offset)
            if end_offset != -1:
                cert_data = self.firmware_data[offset:end_offset + len(cert_end)]

                certs.append({
                    'offset': offset,
                    'type': 'X.509 Certificate (PEM)',
                    'data': cert_data,
                    'size': len(cert_data)
                })

                logger.info(f"  Found certificate at 0x{offset:08X}")

            offset += len(cert_start)

        return certs

    def generate_report(self):
        logger.info("\n" + "="*80)
        logger.info("Crypto Key Extraction Report")
        logger.info("="*80)
        logger.info(f"Firmware: {os.path.basename(self.firmware_path)}")
        logger.info(f"Size: {self.size:,} bytes")
        logger.info("="*80)

        entropy_regions = self.find_high_entropy_regions(block_size=32, threshold=7.5)
        self.findings['entropy_regions'] = entropy_regions
        logger.info(f"\nHigh Entropy Regions: {len(entropy_regions)}")
        for region in entropy_regions[:5]:
            logger.info(f"  Offset: 0x{region['offset']:08X}, Size: {region['size']} bytes, Entropy: {region['entropy']:.2f}")

        aes_keys = self.find_aes_keys()
        self.findings['aes_keys'] = aes_keys
        logger.info(f"\nAES Keys Found: {len(aes_keys)}")
        for key in aes_keys[:10]:
            logger.info(f"  {key['type']} at 0x{key['offset']:08X}")
            logger.info(f"    Key: {key['key_hex']}")
            logger.info(f"    Entropy: {key['entropy']:.2f}")

        rsa_keys = self.find_rsa_keys()
        self.findings['rsa_keys'] = rsa_keys
        logger.info(f"\nRSA Keys Found: {len(rsa_keys)}")
        for key in rsa_keys:
            logger.info(f"  {key['type']} at 0x{key['offset']:08X} ({key['size']} bytes)")

        mesh_keys = self.find_ble_mesh_keys()
        self.findings['ble_mesh_keys'] = mesh_keys
        logger.info(f"\nBLE Mesh Keys Found: {len(mesh_keys)}")
        for key in mesh_keys[:10]:
            logger.info(f"  {key['type']} at 0x{key['offset']:08X}")
            logger.info(f"    Key: {key['key_hex']}")

        passwords = self.find_hardcoded_passwords()
        self.findings['passwords'] = passwords
        logger.info(f"\nHardcoded Credentials Found: {len(passwords)}")
        for cred in passwords[:10]:
            logger.info(f"  {cred['type']} at 0x{cred['offset']:08X}")
            logger.info(f"    {cred['string'][:64]}")

        certs = self.find_certificates()
        self.findings['certificates'] = certs
        logger.info(f"\nCertificates Found: {len(certs)}")
        for cert in certs:
            logger.info(f"  {cert['type']} at 0x{cert['offset']:08X}")

        logger.info("\n" + "="*80)

    def export_findings(self, output_file: str):
        import json

        exportable = {}
        for key, values in self.findings.items():
            exportable[key] = []
            for item in values:
                exported_item = item.copy()
                for k, v in exported_item.items():
                    if isinstance(v, bytes):
                        exported_item[k] = v.hex()
                exportable[key].append(exported_item)

        with open(output_file, 'w') as f:
            json.dump(exportable, f, indent=2)

        logger.info(f"Exported findings to {output_file}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Crypto Key Extractor from Firmware")
    parser.add_argument('firmware', help='Firmware binary file')
    parser.add_argument('-o', '--output', help='Export findings to JSON')

    args = parser.parse_args()

    if not os.path.exists(args.firmware):
        logger.error(f"Firmware not found: {args.firmware}")
        sys.exit(1)

    extractor = CryptoKeyExtractor(args.firmware)

    if not extractor.load_firmware():
        sys.exit(1)

    extractor.generate_report()

    if args.output:
        extractor.export_findings(args.output)


if __name__ == "__main__":
    main()
