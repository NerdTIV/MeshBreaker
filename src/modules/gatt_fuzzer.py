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


LINK_LOST_HINTS = (
    "disconnect", "reset", "timeout", "closed", "not connected",
    "service discovery has not been performed",
)


class GATTFuzzer:
    def __init__(self, target: str, adapter: str = "hci0",
                 delay: float = 0.2, callback: Callable | None = None):
        self.target   = target
        self.adapter  = adapter
        self.delay    = delay
        self.callback = callback
        self.results:  list[FuzzResult] = []
        self.crashes:  list[FuzzResult] = []
        self.skipped:  int = 0
        self.reconnects: int = 0

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
                err = logger.describe(e)
                result.response = err
                link_lost = (not client.is_connected
                             or any(x in err.lower() for x in LINK_LOST_HINTS))
                if link_lost:
                    result.crashed = True
                    self.crashes.append(result)
                    logger.warning(f"    [{i:02d}] {len(payload):>4}B → LINK LOST: {err}")
                    if self.callback:
                        self.callback(result)
                    results.append(result)
                    self.skipped += len(payloads) - i - 1
                    logger.warning(f"    target dropped the link — "
                                   f"{len(payloads) - i - 1} payload(s) not sent")
                    break
                logger.debug(f"    [{i:02d}] {len(payload):>4}B → {err[:60]}")
            results.append(result)
            await asyncio.sleep(self.delay)

        return results

    @staticmethod
    def _writable(client: BleakClient) -> list[tuple[int, str]]:
        found = []
        for svc in client.services:
            for char in svc.characteristics:
                props = char.properties if isinstance(char.properties, (list, tuple)) \
                        else [char.properties]
                if "WRITE" in " ".join(str(p) for p in props).upper():
                    found.append((char.handle, str(char.uuid)))
        return found

    async def run(self, max_reconnects: int = 3):
        """Fuzz every writable characteristic, reconnecting when the link drops.

        A target that terminates the connection on the first unauthorised
        write — which is what iOS does — used to leave the fuzzer writing into
        a dead client for the rest of the run. Every later payload failed with
        "Service Discovery has not been performed yet" and was still counted
        as sent, so the summary claimed hundreds of payloads that never left
        the machine.
        """
        logger.info(f"GATT fuzzer → {self.target}")
        targets: list[tuple[int, str]] = []
        index = 0

        while True:
            try:
                async with BleakClient(self.target) as client:
                    if not targets:
                        targets = self._writable(client)
                        logger.success(f"Connected — {len(targets)} writable "
                                       f"characteristic(s) to fuzz")
                        if not targets:
                            break

                    while index < len(targets):
                        handle, uuid = targets[index]
                        res = await self.fuzz_characteristic(client, handle, uuid)
                        self.results.extend(res)
                        index += 1
                        if not client.is_connected:
                            break

                    if index >= len(targets):
                        break
            except Exception as e:
                logger.error(f"Fuzzer connection failed: {logger.describe(e)}")
                break

            if self.reconnects >= max_reconnects:
                remaining = len(targets) - index
                logger.warning(f"Giving up after {max_reconnects} reconnects — "
                               f"{remaining} characteristic(s) left unfuzzed")
                break
            self.reconnects += 1
            backoff = 3.0 * self.reconnects
            logger.info(f"  reconnecting ({self.reconnects}/{max_reconnects}) "
                        f"in {backoff:.0f}s…")
            await asyncio.sleep(backoff)

        sent    = len(self.results)
        crashes = len(self.crashes)
        logger.success(f"Fuzzing complete — {sent} payload(s) sent, "
                       f"{crashes} link loss(es), {self.skipped} skipped")
        if crashes:
            logger.info("  A link loss is a finding: the target tore down the "
                        "connection rather than rejecting the write.")
        return self.results

    def fuzz_read_response(self):
        logger.warning("fuzz_read_response() requires GATT server mode.")
        logger.info("Use plugins/rogue_peripheral.py for rogue peripheral attacks.")
