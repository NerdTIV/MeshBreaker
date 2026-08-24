"""
Address rotation and linkability.

BLE privacy rests on one idea: a device advertises under a random address
that changes every so often, so nobody can follow it around. The Core spec
suggests rotating roughly every fifteen minutes.

That only works if the *content* of the advertisement rotates with the
address. Anything that stays identical across a rotation ties the old
address to the new one, and the device is trackable again — the rotation
becomes decoration. A stable device name is the classic case, but a fixed
manufacturer blob, a serial number buried in service data, or a beacon
identifier all do the same job.

This module looks for exactly that: payloads that appear under more than one
address. It reports what carried the link so the finding can be judged rather
than trusted, because a shared payload is not proof on its own — two devices
of the same model can legitimately broadcast the same bytes.

Address types, from the two top bits of the most significant byte of a random
address (Core v5.4, Vol 6, Part B, 1.3):

    0b11  static random      stable until reboot
    0b01  resolvable private the one that is meant to rotate
    0b00  non-resolvable     rotates, and nobody can resolve it back
"""

from dataclasses import dataclass, field

from src.utils import logger

ADDR_PUBLIC = "public"
ADDR_STATIC = "static-random"
ADDR_RESOLVABLE = "resolvable-private"
ADDR_NON_RESOLVABLE = "non-resolvable"
ADDR_UNKNOWN = "unknown"

SPEC_ROTATION_SECONDS = 900

LOW_ENTROPY_AD_TYPES = {0x01, 0x0A}

MIN_EVIDENCE_BYTES = 4

AD_TYPE_LABELS = {
    0x02: "incomplete 16-bit UUIDs",
    0x03: "complete 16-bit UUIDs",
    0x06: "incomplete 128-bit UUIDs",
    0x07: "complete 128-bit UUIDs",
    0x08: "shortened name",
    0x09: "complete name",
    0x16: "service data",
    0x21: "service data 128-bit",
    0xFF: "manufacturer data",
}


def address_kind(mac: str, addr_type: int | None = None) -> str:
    """Classify an address. addr_type comes from the HCI report when we have it.

    Without it the address alone cannot tell public from random, so a
    non-random-looking address is reported as unknown rather than guessed
    at as public.
    """
    if addr_type == 0:
        return ADDR_PUBLIC
    try:
        msb = int(mac.split(":")[0], 16)
    except (ValueError, IndexError, AttributeError):
        return ADDR_UNKNOWN

    top = (msb >> 6) & 0x03
    if top == 0b11:
        return ADDR_STATIC
    if top == 0b01:
        return ADDR_RESOLVABLE
    if top == 0b00:
        return ADDR_NON_RESOLVABLE if addr_type == 1 else ADDR_UNKNOWN
    return ADDR_UNKNOWN


@dataclass
class AddressInfo:
    address: str = ""
    kind: str = ADDR_UNKNOWN
    first_seen: float = 0.0
    last_seen: float = 0.0
    frames: int = 0
    name: str = ""

    @property
    def lifetime(self) -> float:
        return self.last_seen - self.first_seen


STRONG_EVIDENCE_BYTES = 8
CROWD_THRESHOLD = 4


@dataclass
class LinkedGroup:
    """Addresses tied together by a payload they all broadcast."""

    addresses: list[str] = field(default_factory=list)
    ad_type: int = 0
    evidence: str = ""

    @property
    def label(self) -> str:
        return AD_TYPE_LABELS.get(self.ad_type, f"AD type 0x{self.ad_type:02X}")

    @property
    def evidence_bytes(self) -> int:
        return len(self.evidence) // 2

    @property
    def distinct_bytes(self) -> int:
        pairs = [self.evidence[i:i + 2] for i in range(0, len(self.evidence), 2)]
        return len(set(pairs))

    @property
    def strength(self) -> str:
        """How much weight this link deserves.

        A short payload, or one repeated across a crowd of addresses, is more
        likely a value every device of a model sends than a fingerprint of
        one device rotating its address.
        """
        if self.evidence_bytes < STRONG_EVIDENCE_BYTES:
            return "weak"
        if len(self.addresses) > CROWD_THRESHOLD:
            return "weak"
        if self.distinct_bytes < 4:
            return "weak"
        return "strong"

    @property
    def why_weak(self) -> str:
        if self.evidence_bytes < STRONG_EVIDENCE_BYTES:
            return f"only {self.evidence_bytes} bytes"
        if len(self.addresses) > CROWD_THRESHOLD:
            return f"seen under {len(self.addresses)} addresses"
        if self.distinct_bytes < 4:
            return "low entropy"
        return ""


@dataclass
class PrivacyReport:
    addresses: dict = field(default_factory=dict)
    groups: list = field(default_factory=list)
    duration: float = 0.0

    @property
    def rotating_addresses(self) -> list[str]:
        return [a for a, info in self.addresses.items()
                if info.kind == ADDR_RESOLVABLE]

    @property
    def too_short(self) -> bool:
        return self.duration < SPEC_ROTATION_SECONDS


def analyse(entries: list[dict]) -> PrivacyReport:
    """Find payloads shared by several addresses."""
    report = PrivacyReport()
    payload_owners: dict[tuple, set] = {}
    times = []

    for entry in entries:
        mac = entry.get("mac")
        if not mac:
            continue
        timestamp = float(entry.get("t") or 0.0)
        times.append(timestamp)

        info = report.addresses.get(mac)
        if info is None:
            info = AddressInfo(address=mac,
                               kind=address_kind(mac, entry.get("addr_type")),
                               first_seen=timestamp, last_seen=timestamp)
            report.addresses[mac] = info
        info.frames += 1
        info.first_seen = min(info.first_seen, timestamp)
        info.last_seen = max(info.last_seen, timestamp)
        if entry.get("name") and not info.name:
            info.name = entry["name"]

        ad_type = entry.get("ad_type")
        raw = entry.get("raw") or ""
        if ad_type is None or ad_type in LOW_ENTROPY_AD_TYPES:
            continue
        body = raw[2:] if len(raw) > 2 else ""
        if len(body) < MIN_EVIDENCE_BYTES * 2:
            continue
        payload_owners.setdefault((ad_type, body), set()).add(mac)

    if times:
        report.duration = max(times) - min(times)

    for (ad_type, body), owners in payload_owners.items():
        if len(owners) < 2:
            continue
        report.groups.append(LinkedGroup(addresses=sorted(owners),
                                         ad_type=ad_type, evidence=body))

    report.groups.sort(key=lambda g: (g.strength != "strong",
                                      -len(g.evidence),
                                      -len(g.addresses)))
    return report


def print_report(report: PrivacyReport):
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console(emoji=False)

    kinds: dict[str, int] = {}
    for info in report.addresses.values():
        kinds[info.kind] = kinds.get(info.kind, 0) + 1

    t = Table(title=f"Addresses — {len(report.addresses)} seen over "
                    f"{report.duration:.0f}s",
              box=box.ROUNDED, border_style="cyan")
    t.add_column("Type", style="bold white", width=20)
    t.add_column("Count", style="cyan", width=7)
    t.add_column("Meaning", style="dim", width=44)
    meanings = {
        ADDR_PUBLIC: "never rotates, tied to the manufacturer",
        ADDR_STATIC: "stable until the device reboots",
        ADDR_RESOLVABLE: "meant to rotate, resolvable by a bonded peer",
        ADDR_NON_RESOLVABLE: "rotates, resolvable by nobody",
        ADDR_UNKNOWN: "capture did not record the address type",
    }
    for kind, count in sorted(kinds.items(), key=lambda kv: -kv[1]):
        t.add_row(kind, str(count), meanings.get(kind, ""))
    console.print(t)

    if report.too_short:
        logger.warning(f"Capture covers {report.duration:.0f}s — a resolvable "
                       f"private address is only expected to rotate about "
                       f"every {SPEC_ROTATION_SECONDS // 60} minutes")
        logger.info("  Finding no rotation here means the capture was short, "
                    "not that the device stands still.")

    if not report.groups:
        logger.success("No payload seen under more than one address")
        return

    strong = [g for g in report.groups if g.strength == "strong"]
    logger.warning(f"{len(report.groups)} payload(s) shared across addresses, "
                   f"{len(strong)} of them strong")
    t = Table(title="Linkable Across Address Rotation",
              box=box.ROUNDED, border_style="magenta")
    t.add_column("Carried in", style="bold white", width=20)
    t.add_column("Strength", width=16)
    t.add_column("Addr", style="cyan", width=5)
    t.add_column("Evidence", style="dim", width=26)
    t.add_column("Linked", width=38)
    for group in report.groups[:15]:
        evidence = group.evidence[:24] + ("…" if len(group.evidence) > 24 else "")
        if group.strength == "strong":
            mark = "[red]strong[/]"
        else:
            mark = f"[dim]weak, {group.why_weak}[/]"
        t.add_row(group.label, mark, str(len(group.addresses)), evidence,
                  ", ".join(group.addresses[:2]) +
                  (" …" if len(group.addresses) > 2 else ""))
    console.print(t)

    logger.info("  Identical bytes under several addresses tie them together, "
                "which defeats the rotation.")
    logger.info("  It is not proof on its own: two devices of the same model "
                "can legitimately send the same payload.")
