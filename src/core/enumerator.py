import asyncio
import socket
import struct
from dataclasses import dataclass, field
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
                logger.error(f"GATT enumeration failed: {logger.describe(e)}")
                if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
                    logger.info("  A timeout here covers two very different cases:")
                    logger.info("    the target never answered — check it is advertising:")
                    logger.info(f"      meshbreaker recon -t {self.target}")
                    logger.info("    or the link came up and service discovery stalled,")
                    logger.info("    which is what a device with no usable ATT server does.")
                    logger.info("    Confirm which with:  sudo btmon")
                else:
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
        uuid_seq  = b"\x35\x03\x19\x01\x00"
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


@dataclass
class ProbeResult:
    """What one connect-and-look-around told us about a device."""

    mac: str = ""
    connected: bool = False
    mtu: int = 0
    services: int = 0
    characteristics: int = 0
    writable: list[dict] = field(default_factory=list)
    error: str = ""

    @property
    def fuzzable(self) -> bool:
        return self.connected and bool(self.writable)


async def probe_writable(mac: str, adapter: str = "hci0",
                         timeout: float = 20.0) -> ProbeResult:
    """Connect to one device and count what a fuzzer could write to.

    Scanning cannot answer this. Nothing in an advertisement says whether a
    device accepts connections, and the writable characteristics only exist
    once service discovery has run. So this connects, which is why the caller
    has to name the device explicitly rather than sweeping everything in
    range.
    """
    result = ProbeResult(mac=mac)
    try:
        async with BleakClient(mac, adapter=adapter, timeout=timeout) as client:
            result.connected = True
            result.mtu = getattr(client, "mtu_size", 0) or 0
            for service in client.services:
                result.services += 1
                for char in service.characteristics:
                    result.characteristics += 1
                    props = char.properties if isinstance(char.properties, (list, tuple)) \
                            else [char.properties]
                    if "WRITE" in " ".join(str(x) for x in props).upper():
                        result.writable.append({
                            "handle": char.handle,
                            "uuid": str(char.uuid),
                            "properties": [str(x) for x in props],
                        })
    except Exception as e:
        result.error = logger.describe(e)
    return result
