"""
Loading capture files, defensively.

Capture files are untrusted input. They get truncated when a tool is killed
mid-write, hand-edited, produced by a different version, or handed over by
someone else entirely. A parser that assumes the file is well formed turns a
bad file into a Python traceback, which tells the user nothing about what to
fix.

So every module that reads a capture goes through here. Bad frames are counted
and skipped rather than fatal — one corrupt advert in ten thousand should not
lose you the capture.

**One trap worth knowing about.** The `raw` field does not mean the same thing
in every capture:

    from `capture` / `sniff` (bleak)   raw = company ID (2 bytes) + payload,
                                       and `ad_type` says 0xFF
    from `hci-capture` or a sniffer    raw = AD type + payload, one entry per
                                       AD structure

So `raw[0]` is an AD type in the second case and a company ID byte in the
first. Always read `ad_type` when it is present; only fall back to `raw[0]`
when it is not.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from src.utils import logger

# The AD types mesh traffic actually travels in. BlueZ does not hand these to
# bleak, which is the whole reason profile_capture() exists.
MESH_AD_TYPES = {
    0x29: "PB-ADV (provisioning)",
    0x2A: "Mesh Message",
    0x2B: "Mesh Beacon",
}

AD_TYPE_NAMES = {
    0x01: "Flags",
    0x02: "Incomplete 16-bit UUIDs",
    0x03: "Complete 16-bit UUIDs",
    0x07: "Complete 128-bit UUIDs",
    0x08: "Shortened Local Name",
    0x09: "Complete Local Name",
    0x0A: "TX Power Level",
    0x16: "Service Data 16-bit UUID",
    0x21: "Service Data 128-bit UUID",
    0xFF: "Manufacturer Specific Data",
    **MESH_AD_TYPES,
}


def load_capture(path: str) -> list[dict] | None:
    """Read a capture file and return its frames.

    Accepts the three shapes we write or might be handed:
        [ {...}, {...} ]
        {"beacons": [...]}
        {"devices": [...]}

    Returns None — never raises — when the file cannot be used, having already
    logged what is wrong with it.
    """
    file_path = Path(path)

    if not file_path.exists():
        logger.error(f"Capture file not found: {path}")
        return None

    try:
        text = file_path.read_text()
    except OSError as e:
        logger.error(f"Cannot read capture file {path}: {e}")
        return None

    if not text.strip():
        logger.error(f"Capture file is empty: {path}")
        return None

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        logger.error(f"Capture file is not valid JSON: {path}")
        logger.info(f"  {e.msg} at line {e.lineno}, column {e.colno}")
        logger.info("  Expected a capture written by 'meshbreaker capture' or 'sniff'")
        return None

    if isinstance(data, dict):
        entries = data.get("beacons", data.get("devices", []))
    elif isinstance(data, list):
        entries = data
    else:
        logger.error(f"Capture file has an unexpected top-level type: "
                     f"{type(data).__name__}")
        return None

    if not isinstance(entries, list):
        logger.error("Capture file's frame list is not a list")
        return None

    # Drop anything that is not a frame object rather than letting it explode
    # later in whichever parser happens to touch it first.
    frames = [e for e in entries if isinstance(e, dict)]
    skipped = len(entries) - len(frames)
    if skipped:
        logger.warning(f"Skipped {skipped} malformed entries in {path}")

    return frames


def frame_bytes(entry: dict, field: str = "raw") -> bytes | None:
    """Decode a frame's hex payload, returning None if it is not usable.

    Odd-length and non-hex strings both show up in real files, usually from a
    capture that was cut off mid-write.
    """
    raw_hex = entry.get(field) or ""
    if not raw_hex:
        return None
    try:
        return bytes.fromhex(raw_hex.strip())
    except (ValueError, AttributeError):
        return None


def decode_frames(entries: list[dict], field: str = "raw") -> tuple[list[tuple[dict, bytes]], int]:
    """Decode every frame's payload, reporting how many were unusable.

    Returns (usable pairs, count of bad frames).
    """
    good: list[tuple[dict, bytes]] = []
    bad = 0
    for entry in entries:
        raw = frame_bytes(entry, field)
        if raw is None:
            if entry.get(field):
                bad += 1
            continue
        good.append((entry, raw))

    if bad:
        logger.warning(f"{bad} frames had unreadable hex and were skipped")
    return good, bad


@dataclass
class CaptureProfile:
    """What a capture file can and cannot tell you."""

    total: int = 0
    ad_types: dict[int, int] = field(default_factory=dict)
    mesh_frames: int = 0
    service_data_frames: int = 0
    source: str = "unknown"          # bleak | sniffer | unknown

    @property
    def carries_mesh_ad_types(self) -> bool:
        """Whether this capture *could* contain mesh traffic at all.

        The distinction that matters: a capture with no mesh frames might mean
        there is no mesh nearby, or it might mean the capture method is
        structurally incapable of seeing mesh. Those need different answers.
        """
        return any(t in MESH_AD_TYPES for t in self.ad_types)


def profile_capture(entries: list[dict]) -> CaptureProfile:
    """Work out what a capture contains and where it probably came from."""
    profile = CaptureProfile(total=len(entries))

    for entry in entries:
        if entry.get("service_data"):
            profile.service_data_frames += 1

        # The `ad_type` field is authoritative when present. Do not read it
        # off raw[0]: in a bleak capture `raw` starts with the manufacturer's
        # company ID, not an AD type, so raw[0] there is meaningless. Only
        # sniffer-produced frames put the AD type at the front of `raw`.
        raw = frame_bytes(entry)
        ad_type = entry.get("ad_type")
        if ad_type is None and raw:
            ad_type = raw[0]
        if ad_type is None:
            continue
        profile.ad_types[ad_type] = profile.ad_types.get(ad_type, 0) + 1
        if ad_type in MESH_AD_TYPES:
            profile.mesh_frames += 1

    seen = set(profile.ad_types)
    if profile.carries_mesh_ad_types:
        profile.source = "sniffer"
    elif seen and seen <= {0xFF}:
        # Only manufacturer data: the shape bleak/BlueZ can produce.
        profile.source = "bleak"
    return profile


def warn_if_mesh_blind(profile: CaptureProfile, looking_for: str) -> bool:
    """Say plainly when a capture cannot answer the question being asked.

    Returns True when the capture is blind to mesh, so the caller can report
    "cannot tell" instead of a clean-looking "nothing found".

    This exists because a silent false negative is the worst failure mode an
    audit tool has: it looks exactly like a passing result.
    """
    if profile.carries_mesh_ad_types:
        return False

    logger.warning(f"This capture cannot contain {looking_for}")
    if profile.source == "bleak":
        logger.info("  It was taken with a standard adapter through BlueZ, which only")
        logger.info("  exposes manufacturer data, service data, names and UUIDs. Mesh")
        logger.info(f"  lives in AD types {', '.join(f'0x{t:02X}' for t in MESH_AD_TYPES)}, "
                    "which BlueZ never hands over.")
    else:
        logger.info(f"  No frames carry AD types "
                    f"{', '.join(f'0x{t:02X}' for t in MESH_AD_TYPES)}.")
    logger.info("  A result of 'nothing found' here means 'cannot tell', not 'clean'.")
    logger.info("  To capture mesh traffic for real, use one of:")
    logger.info("    meshbreaker hci-capture          (Linux, root, standard adapter)")
    logger.info("    meshbreaker sniff --backend sniffle   (nRF52840 dongle)")
    return True


def print_profile(profile: CaptureProfile):
    """Show the AD type breakdown of a capture."""
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console()
    t = Table(title=f"Capture Contents — {profile.total} frames, source: {profile.source}",
              box=box.ROUNDED, border_style="cyan")
    t.add_column("AD type", style="bold white", width=9)
    t.add_column("Name", style="cyan", width=32)
    t.add_column("Frames", style="dim", width=8)
    t.add_column("Mesh", width=6)

    for ad_type, count in sorted(profile.ad_types.items(), key=lambda x: -x[1]):
        is_mesh = ad_type in MESH_AD_TYPES
        t.add_row(f"0x{ad_type:02X}",
                  AD_TYPE_NAMES.get(ad_type, "Unknown"),
                  str(count),
                  "[green]yes[/]" if is_mesh else "—")
    console.print(t)
