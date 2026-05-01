import asyncio
import struct
import time
from dataclasses import dataclass
from typing import Callable

from bleak import BleakClient

from src.utils import logger


@dataclass
class FuzzResult:
    handle:   int
    uuid:     str
    payload:  bytes
    crashed:  bool
    response: str


def _cyclic(n: int) -> bytes:
    pattern = b""
    for a in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        for b_ in b"abcdefghijklmnopqrstuvwxyz":
            pattern += bytes([a, b_])
            if len(pattern) >= n:
                return pattern[:n]
    return pattern[:n]


def _payloads(max_size: int = 512) -> list[bytes]:
    return [
        b"\x00" * max_size,
        b"\xff" * max_size,
        b"\x41" * max_size,
        _cyclic(max_size),
        b"\x00\x00\x00\x00",
        b"\xff\xff\xff\xff",
        b"\x7f\xff\xff\xff",
        b"\x80\x00\x00\x00",
        b"%s" * 50,
        b"A" * 4 + b"\x00" * (max_size - 4),
        struct.pack(">I", 0xDEADBEEF) * (max_size // 4),
        b"\x0a" * max_size,
        b"\x00",
        b"",
    ]


class GATTFuzzer:
    def __init__(self, target: str, adapter: str = "hci0",
                 delay: float = 0.2, callback: Callable | None = None):
        self.target   = target
        self.adapter  = adapter
        self.delay    = delay
        self.callback = callback
        self.results:  list[FuzzResult] = []
        self.crashes:  list[FuzzResult] = []

    async def fuzz_characteristic(self, client: BleakClient,
                                   handle: int, uuid: str):
        results: list[FuzzResult] = []
        payloads = _payloads()
        logger.info(f"  Fuzzing [{handle:#06x}] {uuid} ({len(payloads)} payloads)")

        for i, payload in enumerate(payloads):
            result = FuzzResult(handle=handle, uuid=uuid,
                                payload=payload, crashed=False, response="")
            try:
                await client.write_gatt_char(handle, payload, response=True)
                result.response = "ACK"
                logger.debug(f"    [{i:02d}] {len(payload):>4}B → ACK")
            except Exception as e:
                err = str(e)
                result.response = err
                if any(x in err.lower() for x in ("disconnect", "reset", "timeout", "closed")):
                    result.crashed = True
                    self.crashes.append(result)
                    logger.warning(f"    [{i:02d}] {len(payload):>4}B → CRASH: {err}")
                    if self.callback:
                        self.callback(result)
                    results.append(result)
                    break
                logger.debug(f"    [{i:02d}] {len(payload):>4}B → {err[:60]}")
            results.append(result)
            await asyncio.sleep(self.delay)

        return results

    async def run(self):
        logger.info(f"GATT fuzzer → {self.target}")
        try:
            async with BleakClient(self.target) as client:
                logger.success(f"Connected — enumerating writable characteristics…")
                for svc in client.services:
                    for char in svc.characteristics:
                        props = char.properties if isinstance(char.properties, (list, tuple)) \
                                else [char.properties]
                        props_str = " ".join(str(p) for p in props).upper()
                        if "WRITE" in props_str:
                            res = await self.fuzz_characteristic(
                                client, char.handle, str(char.uuid))
                            self.results.extend(res)
        except Exception as e:
            logger.error(f"Fuzzer connection failed: {e}")

        total   = len(self.results)
        crashes = len(self.crashes)
        logger.success(f"Fuzzing complete — {total} payloads sent, {crashes} crashes")
        return self.results

    def fuzz_read_response(self):
        logger.warning("fuzz_read_response() requires GATT server mode.")
        logger.info("Use plugins/rogue_peripheral.py for rogue peripheral attacks.")
