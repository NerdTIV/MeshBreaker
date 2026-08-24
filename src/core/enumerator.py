import socket
import struct
from typing import Any

from bleak import BleakClient

from src.utils import logger

GATT_SERVICES: dict[str, str] = {
    "1800": "Generic Access",          "1801": "Generic Attribute",
    "180A": "Device Information",      "180F": "Battery Service",
    "1810": "Blood Pressure",          "1812": "HID",
    "181A": "Environmental Sensing",   "1826": "Fitness Machine",
    "FFE0": "HM-10 Serial",            "FFE1": "HM-10 Char",
    "FFF0": "Nordic UART (alt)",       "6E400001-B5A3-F393-E0A9-E50E24DCCA9E": "Nordic UART",
}
GATT_PROPS: dict[int, str] = {
    0x01: "BROADCAST",    0x02: "READ",          0x04: "WRITE_NO_RSP",
    0x08: "WRITE",        0x10: "NOTIFY",         0x20: "INDICATE",
    0x40: "AUTH_WRITE",   0x80: "EXTENDED_PROPS",
}

def _props_str(props: Any) -> str:
    if isinstance(props, int):
        return " | ".join(v for k, v in GATT_PROPS.items() if props & k)
    return " | ".join(str(p).upper() for p in props)

def _svc_name(uuid: str) -> str:
    key = uuid.upper().replace("-", "")[-4:]
    return GATT_SERVICES.get(key, GATT_SERVICES.get(uuid.upper(), "Unknown"))


class GATTEnumerator:
    def __init__(self, target: str, adapter: str = "hci0"):
        self.target  = target
        self.adapter = adapter
        self.results: dict[str, Any] = {}

    async def enumerate(self):
        logger.info(f"Connecting to {self.target} via GATT…")
        findings: dict[str, Any] = {"target": self.target, "services": [], "attack_surface": []}

        try:
            async with BleakClient(self.target) as client:
                logger.success(f"Connected — MTU {client.mtu_size}")
                for svc in client.services:
                    svc_info = {
                        "uuid":  str(svc.uuid),
                        "name":  _svc_name(str(svc.uuid)),
                        "handle": svc.handle,
                        "characteristics": [],
                    }
                    for char in svc.characteristics:
                        props_str = _props_str(char.properties)
                        char_info = {
                            "uuid":  str(char.uuid),
                            "handle": char.handle,
                            "props": props_str,
                            "value": None,
                            "descriptors": [],
                        }
                        if "READ" in props_str.upper():
                            try:
                                val = await client.read_gatt_char(char.handle)
                                char_info["value"] = val.hex()
                                logger.data(f"  [{char.handle:#06x}] {char.uuid} = {val.hex()}")
                            except Exception:
                                pass
                        for desc in char.descriptors:
                            try:
                                dval = await client.read_gatt_descriptor(desc.handle)
                                char_info["descriptors"].append({
                                    "uuid": str(desc.uuid),
                                    "handle": desc.handle,
                                    "value": dval.hex(),
                                })
                            except Exception:
                                char_info["descriptors"].append({
                                    "uuid": str(desc.uuid),
                                    "handle": desc.handle,
                                    "value": None,
                                })
                        if any(p in props_str.upper() for p in ("WRITE", "WRITE_NO_RSP")):
                            findings["attack_surface"].append({
                                "type": "WRITABLE_CHAR",
                                "uuid": str(char.uuid),
                                "handle": char.handle,
                                "props": props_str,
                            })
                        svc_info["characteristics"].append(char_info)
                    findings["services"].append(svc_info)
        except Exception as e:
            from src.core.adapter_manager import report_ble_error
            if not report_ble_error(e):
                logger.error(f"GATT enumeration failed: {e}")
                logger.info(f"  Check the target is in range and advertising: "
                            f"meshbreaker recon -t {self.target}")

        self.results = findings
        return findings


class SDPEnumerator:
    SDP_PSM = 1
    SDP_SERVICE_SEARCH_ATTR_REQ = 0x06
    TRANS_ID = 0x1234

    def __init__(self, target: str):
        self.target  = target
        self.results: list[dict] = []

    def _build_search_req(self):
        uuid_seq  = b"\x35\x03\x19\x01\x00"     # DataElem: UUID16 L2CAP
        max_attr  = struct.pack(">H", 0x0100)
        attr_list = b"\x35\x05\x0a\x00\x00\xff\xff"
        cont      = b"\x00"
        params    = uuid_seq + max_attr + attr_list + cont
        return struct.pack(">BHH", self.SDP_SERVICE_SEARCH_ATTR_REQ,
                           self.TRANS_ID, len(params)) + params

    def _parse_response(self, data: bytes):
        results: list[dict] = []
        if len(data) < 5:
            return results
        pdu_id = data[0]
        length = struct.unpack(">H", data[3:5])[0]
        payload = data[5:5 + length]
        results.append({"raw_pdu_id": pdu_id, "payload_hex": payload.hex(),
                         "payload_len": length})
        return results

    def enumerate(self, timeout: float = 8.0):
        logger.info(f"SDP enumeration on {self.target} (L2CAP PSM 1)…")
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET,
                                 socket.BTPROTO_L2CAP)
            sock.settimeout(timeout)
            sock.connect((self.target, self.SDP_PSM))
            logger.success("L2CAP SDP channel opened")
            pdu = self._build_search_req()
            sock.send(pdu)
            resp = sock.recv(4096)
            sock.close()
            self.results = self._parse_response(resp)
            logger.success(f"SDP response: {len(resp)} bytes")
        except OSError as e:
            logger.error(f"SDP connect failed: {e}")
            logger.warning("SDP requires Bluetooth Classic and root-level BT access")
        return self.results

    @staticmethod
    def browse(target: str):
        import subprocess
        try:
            out = subprocess.check_output(
                ["sdptool", "browse", "--tree", target],
                timeout=15, stderr=subprocess.STDOUT
            ).decode(errors="replace")
            logger.success(f"sdptool output:\n{out}")
        except FileNotFoundError:
            logger.error("sdptool not found — install bluez-tools")
        except subprocess.CalledProcessError as e:
            logger.warning(f"sdptool: {e.output.decode(errors='replace')}")
