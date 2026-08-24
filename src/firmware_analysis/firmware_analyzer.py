import json
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from src.utils import logger
from src.firmware_analysis.crypto_key_extractor import CryptoKeyExtractor

_SIG_PATH = Path(__file__).parent.parent.parent / "data" / "firmware_signatures.json"


@dataclass
class FirmwareInfo:
    path: str
    size: int = 0
    fmt: str | None = None
    arch: str | None = None
    endian: str = "little"
    elf_type: str | None = None
    rtos: str | None = None
    rtos_version: str | None = None
    kernel_version: str | None = None
    bluez_version:  str | None = None
    soc: str | None = None
    soc_model: str | None = None
    is_compressed: bool = False
    is_encrypted: bool = False
    entropy_score: float = 0.0
    strings: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)
    crypto_keys: dict = field(default_factory=dict)


_ARCH_MAP: dict[int, str] = {
    0x28: "arm32",
    0xB7: "arm64",
    0x08: "mips",
    0x03: "x86",
    0x3E: "x86_64",
    0xF3: "riscv",
    0x5E: "xtensa",
    0x14: "ppc",
    0x15: "ppc64",
    0x53: "avr",
    0xA9: "renesas_rx",
    0x69: "msp430",
    0x2A: "superh",
    0x02: "sparc",
    0xA4: "rh850",
    0xDC: "csky",
}

_FORMATS: list[tuple[bytes, int, str]] = [
    (b"\x7fELF", 0, "elf"),
    (b"\x1f\x8b", 0, "gzip"),
    (b"sqsh", 0, "squashfs"),
    (b"hsqs", 0, "squashfs"),
    (b"\x85\x19", 0, "jffs2"),
    (b"\x19\x85", 0, "jffs2"),
    (b"\x31\x18\x10\x06", 0, "ubifs"),
    (b"\x06\x10\x18\x31", 0, "ubifs"),
    (b"C1\x00\x00", 0, "cramfs"),
    (b"\x27\x05\x19\x56", 0, "uboot"),
    (b"\xd0\x0d\xfe\xed", 0, "uboot_fit"),
    (b"BZh", 0, "bzip2"),
    (b"\xfd7zXZ\x00", 0, "xz"),
    (b"\x5d\x00\x00", 0, "lzma"),
    (b"\x04\x22\x4dh", 0, "lz4"),
    (b"\x28\xb5/\xfd", 0, "zstd"),
    (b"070701", 0, "cpio_newc"),
    (b"070702", 0, "cpio_crc"),
    (b"UF2\n", 0, "uf2"),
    (b"MZ", 0, "pe"),
    (b"\xce\xfa\xed\xfe", 0, "macho"),
    (b"x\x9c", 0, "zlib"),
    (b"x\xda", 0, "zlib"),
    (b"x\x01", 0, "zlib"),
]
_TEXT_FORMATS: list[tuple[str, str]] = [
    (":",  "ihex"),
    ("S0", "srec"),
    ("S1", "srec"),
]


class FirmwareAnalyzer:
    def __init__(self, firmware_path: str):
        self.path  = Path(firmware_path)
        self._data: bytes = b""
        self._sigs = _load_signatures()
        self.info  = FirmwareInfo(path=str(self.path))

    def load(self):
        if not self.path.exists():
            logger.error(f"Firmware not found: {self.path}")
            return False
        self._data = self.path.read_bytes()
        self.info.size = len(self._data)
        logger.info(f"Loaded: {self.path.name}  ({self.info.size:,} bytes)")
        return True

    def analyze(self):
        if not self._data:
            if not self.load():
                return self.info

        self._detect_format()
        self._extract_strings()
        self._detect_rtos()
        self._detect_soc()
        self._extract_urls_ips()
        self._detect_stack_versions()
        self._run_crypto_extractor()

        parts = [
            f"fmt={self.info.fmt}",
            f"arch={self.info.arch}",
            f"rtos={self.info.rtos or 'unknown'}",
            f"soc={self.info.soc or 'unknown'}",
        ]
        logger.success(f"Analysis complete — {', '.join(parts)}")
        return self.info

    def _detect_format(self):
        d = self._data

        for magic, offset, fmt_id in _FORMATS:
            if d[offset:offset + len(magic)] == magic:
                self.info.fmt = fmt_id
                self.info.is_compressed = fmt_id not in ("elf", "pe", "macho", "ihex", "srec")
                if fmt_id == "elf":
                    self._parse_elf(d)
                else:
                    logger.info(f"Format detected: {fmt_id}")
                return

        try:
            first = d[:4].decode("ascii", errors="ignore")
            for prefix, fmt_id in _TEXT_FORMATS:
                if first.startswith(prefix):
                    self.info.fmt = fmt_id
                    logger.info(f"Format detected: {fmt_id}")
                    return
        except Exception:
            pass

        tmp = CryptoKeyExtractor.__new__(CryptoKeyExtractor)
        tmp.firmware_data = d[:4096]
        ent = tmp.calculate_entropy(d[:4096])
        self.info.entropy_score = ent
        if ent > 7.5:
            self.info.is_encrypted = True
            logger.warning(f"Unknown format, high entropy ({ent:.2f}) — possibly encrypted")
        else:
            self.info.fmt = "raw_binary"
            logger.info("Format: raw binary")

    def _parse_elf(self, d: bytes):
        self.info.elf_type = "ELF"
        ei_class  = d[4]
        ei_data   = d[5]
        e_machine = struct.unpack("<H" if ei_data == 1 else ">H", d[18:20])[0]
        self.info.endian = "little" if ei_data == 1 else "big"
        self.info.arch   = _ARCH_MAP.get(e_machine, f"unknown({e_machine:#x})")
        bits = "32-bit" if ei_class == 1 else "64-bit"
        logger.info(f"ELF {bits} {self.info.endian}-endian arch={self.info.arch}")

    def _extract_strings(self, min_len: int = 5):
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        self.info.strings = [
            m.group().decode("ascii", errors="replace")
            for m in pattern.finditer(self._data)
        ]
        logger.info(f"Strings extracted: {len(self.info.strings)}")

    def _detect_rtos(self):
        if not self._sigs or not self.info.strings:
            return

        low_strings = {s.lower() for s in self.info.strings}
        scores: dict[str, int] = {}

        for entry in self._sigs.get("rtos", []):
            rid = entry["id"]
            if rid == "bare_metal":
                continue
            for pat in entry.get("patterns", []):
                if any(pat.lower() in s for s in low_strings):
                    scores[rid] = scores.get(rid, 0) + 1

        if not scores:
            self.info.rtos = "bare_metal"
            logger.info("RTOS: bare metal (no RTOS signatures found)")
            return

        best_id = max(scores, key=lambda k: scores[k])
        best_entry = next(e for e in self._sigs["rtos"] if e["id"] == best_id)
        self.info.rtos = best_id

        version = _extract_version(self.info.strings, best_entry["name"])
        if version:
            self.info.rtos_version = version

        logger.success(
            f"RTOS detected: {best_entry['name']} ({scores[best_id]} pattern hits)"
            + (f" v{version}" if version else "")
        )

    def _detect_soc(self):
        if not self._sigs or not self.info.strings:
            return

        low_strings = {s.lower() for s in self.info.strings}
        scores: dict[str, int] = {}

        for entry in self._sigs.get("soc", []):
            sid = entry["id"]
            for pat in entry.get("patterns", []):
                if any(pat.lower() in s for s in low_strings):
                    scores[sid] = scores.get(sid, 0) + 1

        if not scores:
            logger.info("SoC: not identified")
            return

        best_id = max(scores, key=lambda k: scores[k])
        best_entry = next(e for e in self._sigs["soc"] if e["id"] == best_id)
        self.info.soc = best_id

        for model in best_entry.get("models", []):
            if any(model.lower() in s for s in low_strings):
                self.info.soc_model = model
                break

        if not self.info.arch or self.info.arch.startswith("unknown"):
            soc_arch = best_entry.get("arch", "").split("/")[0].strip()
            if soc_arch:
                self.info.arch = soc_arch

        logger.success(
            f"SoC detected: {best_entry['name']}"
            + (f" ({self.info.soc_model})" if self.info.soc_model else "")
            + f" ({scores[best_id]} hits)"
        )

    def _extract_urls_ips(self):
        text = "\n".join(self.info.strings)
        urls  = re.findall(r"https?://[^\s\"'<>]+", text)
        mqtts = re.findall(r"mqtts?://[^\s\"'<>]+", text)
        ips   = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)

        self.info.urls = list(dict.fromkeys(urls + mqtts))
        self.info.ips  = list(dict.fromkeys(ips))

        if self.info.urls:
            logger.info(f"URLs: {len(self.info.urls)}")
            for u in self.info.urls[:10]:
                logger.info(f"  {u}")
        if self.info.ips:
            logger.info(f"IPs: {len(self.info.ips)}")

    def _detect_stack_versions(self):
        kpat  = re.compile(r"Linux version (\d+\.\d+[\.\d]*)", re.IGNORECASE)
        bzpat = re.compile(r"bluetoothd[\s/\\-]*(\d+\.\d+[\.\d]*)|BlueZ[\s/\\-]*(\d+\.\d+[\.\d]*)", re.IGNORECASE)
        for s in self.info.strings:
            if not self.info.kernel_version:
                m = kpat.search(s)
                if m:
                    self.info.kernel_version = m.group(1)
                    logger.info(f"Kernel version detected: {self.info.kernel_version}")
            if not self.info.bluez_version:
                m = bzpat.search(s)
                if m:
                    self.info.bluez_version = m.group(1) or m.group(2)
                    logger.info(f"BlueZ version detected: {self.info.bluez_version}")
            if self.info.kernel_version and self.info.bluez_version:
                break

    def _run_crypto_extractor(self):
        ext = CryptoKeyExtractor(str(self.path))
        if ext.load_firmware():
            ext.generate_report()
            self.info.crypto_keys  = ext.findings
            self.info.credentials  = ext.findings.get("passwords", [])

    def export(self, output_dir=None):
        dest_dir = Path(output_dir) if output_dir else self.path.parent / "analysis"
        dest_dir.mkdir(parents=True, exist_ok=True)
        out = dest_dir / f"{self.path.name}_analysis.json"

        exportable = {
            "path":          self.info.path,
            "size":          self.info.size,
            "format":        self.info.fmt,
            "arch":          self.info.arch,
            "endian":        self.info.endian,
            "rtos":          self.info.rtos,
            "rtos_version":  self.info.rtos_version,
            "kernel_version": self.info.kernel_version,
            "bluez_version":  self.info.bluez_version,
            "soc":           self.info.soc,
            "soc_model":     self.info.soc_model,
            "is_compressed": self.info.is_compressed,
            "is_encrypted":  self.info.is_encrypted,
            "entropy_score": self.info.entropy_score,
            "urls":          self.info.urls,
            "ips":           self.info.ips,
            "credentials":   self.info.credentials,
            "string_count":  len(self.info.strings),
            "crypto_keys": {
                k: [{kk: (vv.hex() if isinstance(vv, bytes) else vv)
                     for kk, vv in item.items()} for item in v]
                for k, v in self.info.crypto_keys.items()
            },
        }
        with open(out, "w") as f:
            json.dump(exportable, f, indent=2)
        logger.success(f"Analysis exported → {out}")
        return str(out)

    def print_report(self):
        from rich.table import Table
        from rich import box
        from rich.console import Console
        console = Console()

        t = Table(title=f"Firmware Report — {self.path.name}",
                  box=box.ROUNDED, border_style="magenta")
        t.add_column("Field",  style="bold white", width=20)
        t.add_column("Value",  style="cyan")

        rtos_str = self.info.rtos or "unknown"
        if self.info.rtos_version:
            rtos_str += f" v{self.info.rtos_version}"
        soc_str = self.info.soc or "unknown"
        if self.info.soc_model:
            soc_str += f" ({self.info.soc_model})"

        rows = [
            ("Path",         str(self.path)),
            ("Size",         f"{self.info.size:,} bytes"),
            ("Format",       self.info.fmt or "unknown"),
            ("Architecture", self.info.arch or "unknown"),
            ("Endianness",   self.info.endian),
            ("RTOS",         rtos_str),
            ("Kernel",       self.info.kernel_version or "not found"),
            ("BlueZ",        self.info.bluez_version  or "not found"),
            ("SoC / Chip",   soc_str),
            ("Compressed",   str(self.info.is_compressed)),
            ("Encrypted",    str(self.info.is_encrypted)),
            ("Entropy",      f"{self.info.entropy_score:.2f}"),
            ("Strings",      str(len(self.info.strings))),
            ("URLs",         str(len(self.info.urls))),
            ("Credentials",  str(len(self.info.credentials))),
        ]
        ck = self.info.crypto_keys
        rows += [
            ("AES keys",      str(len(ck.get("aes_keys", [])))),
            ("RSA keys",      str(len(ck.get("rsa_keys", [])))),
            ("BLE Mesh keys", str(len(ck.get("ble_mesh_keys", [])))),
            ("Certificates",  str(len(ck.get("certificates", [])))),
        ]
        for k, v in rows:
            t.add_row(k, v)
        console.print(t)


def _load_signatures():
    try:
        return json.loads(_SIG_PATH.read_text())
    except Exception:
        logger.warning("firmware_signatures.json not found — RTOS/SoC detection disabled")
        return {}


def _extract_version(strings, rtos_name):
    pat = re.compile(
        rf"{re.escape(rtos_name)}[^\d]{{0,10}}(\d+\.\d+[\.\d]*)",
        re.IGNORECASE
    )
    for s in strings:
        m = pat.search(s)
        if m:
            return m.group(1)
    return None
