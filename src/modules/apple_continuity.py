"""
Apple Continuity decoder.

Apple devices announce themselves through manufacturer-specific data under
company ID 0x004C. Inside that payload is a sequence of TLV messages —
one byte of type, one of length, then the body — and several can share a
single advertisement. The type tells you which proximity feature is talking:
Handoff, Find My, an AirPods pairing prompt, and so on.

The message types below are the ones established by public research, chiefly
Martin et al., "Handoff All Your Privacy" (PETS 2019), and the surveys that
followed it. None of this is documented by Apple, so treat the bodies as
observed rather than specified: this module decodes the fields it can stand
behind and hands back the raw bytes for the rest instead of guessing.

What it is good for is seeing what a device leaks by simply existing. Most of
these messages are unauthenticated and unencrypted, and several carry state
about the device and its owner — whether a phone is unlocked, whether AirPods
were just opened, whether a Find My network item is nearby.

Nothing here is Apple-specific tooling in the sense of an exploit. It is a
decoder: it turns bytes that already fly through the air into something
readable.
"""

import struct
from dataclasses import dataclass, field

from src.utils import logger

APPLE_COMPANY_ID = 0x004C

CONTINUITY_TYPES = {
    0x02: "iBeacon",
    0x03: "AirPrint",
    0x05: "AirDrop",
    0x06: "HomeKit",
    0x07: "Proximity Pairing",
    0x08: "Hey Siri",
    0x09: "AirPlay Target",
    0x0A: "AirPlay Source",
    0x0B: "MagicSwitch",
    0x0C: "Handoff",
    0x0D: "Tethering Target Presence",
    0x0E: "Tethering Source Presence",
    0x0F: "Nearby Action",
    0x10: "Nearby Info",
    0x12: "Find My",
}

PRIVACY_NOTES = {
    0x05: "AirDrop broadcasts truncated hashes of the owner's contact details",
    0x07: "Proximity Pairing carries the model and battery state of the buds",
    0x0C: "Handoff carries a sequence number that increments per device",
    0x0F: "Nearby Action can reveal an ongoing setup or transfer",
    0x10: "Nearby Info leaks device state, including lock status",
    0x12: "Find My rotates keys, but a stable field would make it trackable",
}


@dataclass
class ContinuityMessage:
    type_id: int = 0
    name: str = ""
    length: int = 0
    data: bytes = b""
    fields: dict = field(default_factory=dict)
    decoded: bool = False

    @property
    def privacy_note(self) -> str:
        return PRIVACY_NOTES.get(self.type_id, "")


def _decode_ibeacon(data: bytes) -> dict:
    if len(data) < 21:
        return {}
    uuid = data[0:16].hex()
    major, minor = struct.unpack(">HH", data[16:20])
    power = struct.unpack("b", data[20:21])[0]
    return {
        "uuid": f"{uuid[0:8]}-{uuid[8:12]}-{uuid[12:16]}-{uuid[16:20]}-{uuid[20:32]}",
        "major": major,
        "minor": minor,
        "measured_power_dbm": power,
    }


def _decode_handoff(data: bytes) -> dict:
    if len(data) < 4:
        return {}
    return {
        "clipboard_status": data[0],
        "sequence_number": struct.unpack("<H", data[1:3])[0],
        "auth_tag": data[3],
        "encrypted": data[4:].hex(),
    }


def _decode_nearby_info(data: bytes) -> dict:
    if len(data) < 2:
        return {}
    status = data[0]
    return {
        "action_code": (status >> 4) & 0x0F,
        "status_flags": status & 0x0F,
        "data_flags": data[1],
        "remainder": data[2:].hex(),
    }


def _decode_find_my(data: bytes) -> dict:
    if len(data) < 1:
        return {}
    out = {"status": data[0]}
    if len(data) >= 2:
        out["remainder"] = data[1:].hex()
    return out


def _decode_proximity_pairing(data: bytes) -> dict:
    if len(data) < 5:
        return {}
    return {
        "prefix": data[0],
        "device_model": f"0x{struct.unpack('>H', data[1:3])[0]:04X}",
        "status": data[3],
        "remainder": data[4:].hex(),
    }


DECODERS = {
    0x02: _decode_ibeacon,
    0x07: _decode_proximity_pairing,
    0x0C: _decode_handoff,
    0x10: _decode_nearby_info,
    0x12: _decode_find_my,
}


def parse_continuity(payload: bytes) -> list[ContinuityMessage]:
    """Split an Apple manufacturer payload into its Continuity messages.

    Pass the bytes *after* the 0x004C company ID.

    Devices pad the tail of an advertisement with zeros, which parse as an
    endless run of empty type-0 messages. A zero type ends the walk rather
    than producing noise.
    """
    messages: list[ContinuityMessage] = []
    offset = 0
    while offset + 2 <= len(payload):
        type_id = payload[offset]
        length = payload[offset + 1]
        if type_id == 0x00:
            break
        body = payload[offset + 2:offset + 2 + length]
        if len(body) < length:
            break
        message = ContinuityMessage(
            type_id=type_id,
            name=CONTINUITY_TYPES.get(type_id, f"Unknown (0x{type_id:02X})"),
            length=length,
            data=body,
        )
        decoder = DECODERS.get(type_id)
        if decoder:
            message.fields = decoder(body)
            message.decoded = bool(message.fields)
        messages.append(message)
        offset += 2 + length
    return messages


def from_manufacturer_data(raw: bytes) -> list[ContinuityMessage]:
    """Decode a manufacturer-data blob, tolerating the two framings we store.

    A sniffer capture keeps the AD structure whole, so the bytes start with
    the AD type 0xFF then the company ID. A bleak capture has already split
    the company ID out, so its blob starts at the company ID or at the body.
    """
    if not raw:
        return []
    if raw[0] == 0xFF:
        raw = raw[1:]
    if len(raw) >= 2 and struct.unpack("<H", raw[0:2])[0] == APPLE_COMPANY_ID:
        raw = raw[2:]
    return parse_continuity(raw)


def is_apple(raw: bytes) -> bool:
    if not raw:
        return False
    if raw[0] == 0xFF:
        raw = raw[1:]
    return len(raw) >= 2 and struct.unpack("<H", raw[0:2])[0] == APPLE_COMPANY_ID


@dataclass
class ContinuityReport:
    devices: dict = field(default_factory=dict)
    message_counts: dict = field(default_factory=dict)

    @property
    def total_messages(self) -> int:
        return sum(self.message_counts.values())


def analyse(entries: list[dict]) -> ContinuityReport:
    """Walk capture entries and collect every Continuity message seen."""
    report = ContinuityReport()
    for entry in entries:
        if entry.get("ad_type") not in (None, 0xFF):
            continue
        raw_hex = entry.get("raw") or ""
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            continue
        if not is_apple(raw):
            continue
        messages = from_manufacturer_data(raw)
        if not messages:
            continue
        mac = entry.get("mac", "?")
        report.devices.setdefault(mac, []).extend(messages)
        for message in messages:
            report.message_counts[message.name] = \
                report.message_counts.get(message.name, 0) + 1
    return report


def print_report(report: ContinuityReport):
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console(emoji=False)

    if not report.devices:
        logger.info("No Apple Continuity messages in this capture")
        return

    t = Table(title=f"Apple Continuity — {report.total_messages} messages from "
                    f"{len(report.devices)} device(s)",
              box=box.ROUNDED, border_style="magenta")
    t.add_column("Message", style="bold white", width=26)
    t.add_column("Seen", style="cyan", width=6)
    t.add_column("What it exposes", style="dim", width=44)
    for name, count in sorted(report.message_counts.items(), key=lambda kv: -kv[1]):
        type_id = next((k for k, v in CONTINUITY_TYPES.items() if v == name), None)
        t.add_row(name, str(count), PRIVACY_NOTES.get(type_id, ""))
    console.print(t)

    for mac, messages in report.devices.items():
        decoded = [m for m in messages if m.decoded]
        if not decoded:
            continue
        logger.data(f"{mac}")
        seen = set()
        for message in decoded:
            key = (message.type_id, str(message.fields))
            if key in seen:
                continue
            seen.add(key)
            logger.info(f"  {message.name}: " +
                        ", ".join(f"{k}={v}" for k, v in message.fields.items()))
