import socket
import struct
import time
from dataclasses import dataclass

from src.utils import logger


@dataclass
class L2CAPResult:
    psm:      int
    payload:  bytes
    crashed:  bool
    note:     str


class L2CAPFuzzer:

    def __init__(self, target: str, timeout: float = 5.0, delay: float = 0.1):
        self.target  = target
        self.timeout = timeout
        self.delay   = delay
        self.results: list[L2CAPResult] = []

    def _payloads(self, psm: int):
        return [
            b"",
            b"\x00",
            b"\xff" * 672,
            b"\x00" * 672,
            struct.pack("<HHI", psm, 0, 0),
            struct.pack("<HH", 0xFFFF, 0xFFFF) + b"\x41" * 100,
            struct.pack("<BBHH", 0x0A, 0xFF, 0, psm) + b"\x00" * 64,
            struct.pack("<HH", 0xFFFF, 0x0001) + b"\x42",
        ]

    def fuzz_psm(self, psm: int):
        results: list[L2CAPResult] = []
        payloads = self._payloads(psm)
        logger.info(f"L2CAP fuzzing PSM {psm} ({len(payloads)} payloads)…")

        for i, payload in enumerate(payloads):
            result = L2CAPResult(psm=psm, payload=payload, crashed=False, note="")
            try:
                sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET,
                                     socket.BTPROTO_L2CAP)
                sock.settimeout(self.timeout)
                sock.connect((self.target, psm))
                sock.send(payload)
                try:
                    resp = sock.recv(4096)
                    result.note = f"response={len(resp)}B"
                except socket.timeout:
                    result.note = "timeout (possible hang)"
                    result.crashed = True
                sock.close()
            except ConnectionResetError:
                result.note  = "ConnectionReset — possible crash"
                result.crashed = True
                logger.warning(f"  [{i:02d}] PSM {psm} {len(payload):>4}B → RESET (crash?)")
            except OSError as e:
                result.note = str(e)
                logger.debug(f"  [{i:02d}] PSM {psm} {len(payload):>4}B → {e}")

            if result.crashed:
                logger.warning(f"  [{i:02d}] CRASH on PSM {psm} len={len(payload)}")
            else:
                logger.debug(f"  [{i:02d}] {len(payload):>4}B → {result.note}")

            results.append(result)
            time.sleep(self.delay)

        return results

    def run(self, psms: list[int] | None = None):
        if psms is None:
            psms = [1, 3, 5, 7, 15, 17, 25, 27, 29, 31]
        for psm in psms:
            self.results.extend(self.fuzz_psm(psm))
        crashes = sum(1 for r in self.results if r.crashed)
        logger.success(f"L2CAP fuzzing done — {len(self.results)} tests, {crashes} crashes")
        return self.results
