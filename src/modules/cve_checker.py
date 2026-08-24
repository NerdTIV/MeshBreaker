import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from src.utils import logger

_CVE_DB_PATH = Path(__file__).parent.parent.parent / "data" / "cve_db.json"


@dataclass
class CVEMatch:
    cve_id: str
    name: str
    severity: str
    cvss: str
    description: str
    matched_on: list[str] = field(default_factory=list)
    affected_component: str = ""
    attack_vector: str = ""


class CVEChecker:
    def __init__(self):
        self._db = self._load_db()

    def check_all(self, context: dict):
        matches: list[CVEMatch] = []
        for entry in self._db.get("entries", []):
            m = self._match_entry(entry, context)
            if m:
                matches.append(m)
        matches.sort(key=lambda x: float(x.cvss or 0), reverse=True)
        _print_matches(matches)
        return matches

    def check_tags(self, tags: list[str]):
        tag_set = set(t.lower() for t in tags)
        matches = []
        for entry in self._db.get("entries", []):
            entry_tags = set(t.lower() for t in entry.get("tags", []))
            if tag_set & entry_tags:
                hint = list(tag_set & entry_tags)
                matches.append(CVEMatch(
                    cve_id=entry["cve_id"], name=entry["name"],
                    severity=entry.get("severity", "?"),
                    cvss=entry.get("cvss", "?"),
                    description=entry["description"],
                    matched_on=[f"tag: {t}" for t in hint],
                    affected_component=entry.get("affected_component", ""),
                    attack_vector=entry.get("attack_vector", ""),
                ))
        matches.sort(key=lambda x: float(x.cvss or 0), reverse=True)
        return matches

    def _match_entry(self, entry: dict, ctx: dict):
        matched_on: list[str] = []

        hints = entry.get("detection_hints", [])
        tags  = [t.lower() for t in entry.get("tags", [])]

        kv = ctx.get("kernel_version", "")
        if kv:
            for h in hints:
                if "kernel" in h.lower():
                    m = re.search(r"(\d+\.\d+)", h)
                    if m:
                        threshold = tuple(int(x) for x in m.group(1).split("."))
                        current   = _parse_version(kv)
                        if current and current < threshold:
                            matched_on.append(f"kernel {kv} < {m.group(1)}")

        bv = ctx.get("bluez_version", "")
        if bv:
            for h in hints:
                if "bluez" in h.lower():
                    m = re.search(r"(\d+\.\d+)", h)
                    if m:
                        threshold = tuple(int(x) for x in m.group(1).split("."))
                        current   = _parse_version(bv)
                        if current and current < threshold:
                            matched_on.append(f"BlueZ {bv} < {m.group(1)}")

        rv = ctx.get("runc_version", "")
        if rv and any("runc" in h.lower() for h in hints):
            matched_on.append(f"runc {rv} detected")

        proto_tags = set(t.lower() for t in ctx.get("protocol_tags", []))
        entry_tags = set(tags)
        overlap = proto_tags & entry_tags
        if overlap:
            matched_on.extend([f"tag: {t}" for t in overlap])

        custom = set(t.lower() for t in ctx.get("custom_tags", []))
        cust_overlap = custom & entry_tags
        if cust_overlap:
            matched_on.extend([f"custom: {t}" for t in cust_overlap])

        if not matched_on:
            return None

        return CVEMatch(
            cve_id      = entry["cve_id"],
            name        = entry["name"],
            severity    = entry.get("severity", "?"),
            cvss        = entry.get("cvss", "?"),
            description = entry["description"],
            matched_on  = matched_on,
            affected_component = entry.get("affected_component", ""),
            attack_vector      = entry.get("attack_vector", ""),
        )

    @staticmethod
    def _load_db() -> dict:
        try:
            return json.loads(_CVE_DB_PATH.read_text())
        except Exception:
            logger.warning("cve_db.json not found — CVE check disabled")
            return {"entries": []}


def _parse_version(vstring: str):
    m = re.search(r"(\d+)\.(\d+)", vstring)
    if m:
        return (int(m.group(1)), int(m.group(2)))
    return None


def _print_matches(matches: list[CVEMatch]):
    from rich.table import Table
    from rich import box
    from rich.console import Console
    console = Console()

    if not matches:
        logger.info("No CVE matches found for current context")
        return

    sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                 "LOW": "green", "?": "dim"}

    t = Table(title=f"CVE Matches ({len(matches)})", box=box.ROUNDED, border_style="red")
    t.add_column("CVE",        style="bold white", width=18)
    t.add_column("Severity",   style="bold",       width=10)
    t.add_column("CVSS",       style="cyan",       width=5)
    t.add_column("Name",       style="white",      width=40)
    t.add_column("Matched on", style="dim",        width=40)

    for m in matches:
        color = sev_color.get(m.severity, "white")
        t.add_row(m.cve_id,
                  f"[{color}]{m.severity}[/]",
                  m.cvss,
                  m.name[:40],
                  "; ".join(m.matched_on[:2])[:40])

    console.print(t)
