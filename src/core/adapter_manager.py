"""
Bluetooth adapter and sniffer discovery.

Two different jobs get confused here, so keep them apart:

  **HCI adapters** (any USB dongle, your laptop's internal radio) talk to
  BlueZ. They scan, connect and enumerate. They do *not* let you pin a
  radio to one channel — BlueZ hops all three advertising channels for you
  and gives you no control over it.

  **Sniffers** (nRF52840 with Sniffle firmware, Ubertooth One, nRF Sniffer)
  expose the raw radio. Those are the ones that can sit on one channel,
  catch a CONNECT_IND, and follow a connection across its hop sequence.

You need the second kind for anything channel-level. This module finds both,
scores the HCI adapters so we pick a sensible default, and reports which
sniffer backends are actually installed.
"""

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from glob import glob
from pathlib import Path

from src.utils import logger

# USB VID:PID of hardware that can act as a real sniffer. Nordic dongles ship
# under a few different IDs depending on the board and the firmware on it.
SNIFFER_USB_IDS = {
    "1915:520f": "nRF52840 Dongle (Nordic)",
    "1915:521f": "nRF52840 Dongle (Nordic, DFU)",
    "2fe3:0100": "nRF52840 (Zephyr USB)",
    "2fe3:0001": "nRF52840 (Zephyr CDC ACM)",
    "2fe3:0004": "nRF52840 (Zephyr CDC ACM serial backend)",
    "239a:8029": "nRF52840 Express (Adafruit)",
    "1d50:6002": "Ubertooth One",
    "0451:16a8": "TI CC2531 (Zigbee/BLE sniffer)",
    "10c4:ea60": "CP210x UART bridge (possible sniffer board)",
}

# External tools we can drive if the user has them installed.
SNIFFER_TOOLS = {
    "sniff_receiver.py": "Sniffle (nRF52840) — channel select + connection following",
    "ubertooth-btle": "Ubertooth — passive BLE follow",
    "nrfutil": "Nordic nRF Util — flashing sniffer firmware",
    "btmon": "BlueZ HCI monitor — host-side trace, not over-the-air",
    "tshark": "Wireshark CLI — pcap parsing",
}


@dataclass
class Adapter:
    """One HCI adapter as BlueZ sees it."""

    name: str = ""              # hci0, hci1...
    address: str = ""
    bus: str = ""               # USB, UART, Virtual...
    is_up: bool = False
    manufacturer: str = ""
    score: int = 0


@dataclass
class SnifferHardware:
    usb_id: str = ""
    description: str = ""
    tool_available: bool = False
    port: str = ""              # /dev/ttyACM0 etc, when it exposes a serial link


@dataclass
class SerialDevice:
    """A USB serial port, with whatever the device says about itself.

    Sniffer firmware talks over one of these. Knowing the port exists is not
    enough — you also need to know it is writable, because a port owned by
    root with no dialout membership fails only once you try to drive it.
    """

    port: str = ""              # /dev/ttyACM0
    usb_id: str = ""            # vid:pid, lowercase
    manufacturer: str = ""
    product: str = ""
    serial: str = ""
    writable: bool = False


@dataclass
class HardwareReport:
    adapters: list[Adapter] = field(default_factory=list)
    sniffers: list[SnifferHardware] = field(default_factory=list)
    tools: dict[str, bool] = field(default_factory=dict)
    serial_devices: list[SerialDevice] = field(default_factory=list)
    best_adapter: str = "hci0"


# Things that go wrong before a scan even starts, and what to tell the user.
# BlueZ and bleak report these as raw D-Bus errors, which are useless to
# anyone who has not read the bleak source.
_BLE_ERROR_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("dbus-org.bluez", "nosuchunit", "no such unit", "org.bluez was not provided",
      "servicenotfound", "name org.bluez"),
     "The Bluetooth service is not running. Start it with:\n"
     "    sudo systemctl start bluetooth"),
    (("no bluetooth", "not available", "no adapter", "no such device",
      "no powered", "nosuchadapter"),
     "No Bluetooth adapter found. Plug in a USB dongle, then check it appears:\n"
     "    hciconfig          (bring it up with: sudo hciconfig hci0 up)"),
    (("permission denied", "access denied", "not authorized", "operation not permitted"),
     "Permission denied on the Bluetooth interface. Either run with sudo, or:\n"
     "    sudo usermod -aG bluetooth $USER   (then log out and back in)"),
    (("dbus",),
     "Could not talk to BlueZ over D-Bus. Inside a container, the host D-Bus\n"
     "    socket and /var/run/dbus need to be mounted, and the host must be\n"
     "    running bluetoothd."),
]


def explain_ble_error(exc: BaseException) -> str:
    """Turn a bleak or BlueZ exception into something actionable.

    Returns an empty string when we do not recognise it, so callers can
    re-raise rather than swallow a genuine bug.
    """
    text = f"{type(exc).__name__}: {exc}".lower()
    for needles, hint in _BLE_ERROR_HINTS:
        if any(n in text for n in needles):
            return hint
    return ""


def report_ble_error(exc: BaseException) -> bool:
    """Log a recognised BLE failure clearly. Returns False if unrecognised.

    Use it as:  if not report_ble_error(e): raise
    """
    hint = explain_ble_error(exc)
    if not hint:
        return False
    logger.error(f"Bluetooth unavailable — {exc}")
    for line in hint.splitlines():
        logger.info(f"  {line}")
    return True


def _run(cmd: list[str], timeout: int = 10) -> str:
    """Run a command and return stdout, empty string on any failure."""
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
        return out.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def list_adapters() -> list[Adapter]:
    """Enumerate HCI adapters via hciconfig.

    Output we parse looks like:

        hci0:   Type: Primary  Bus: USB
                BD Address: AA:BB:CC:DD:EE:FF  ACL MTU: 1021:8
                UP RUNNING
    """
    out = _run(["hciconfig", "-a"])
    if not out:
        logger.warning("hciconfig produced no output — is bluez installed?")
        return []

    adapters: list[Adapter] = []
    current: Adapter | None = None

    for line in out.splitlines():
        header = re.match(r"^(hci\d+):\s+Type:\s+(\S+)\s+Bus:\s+(\S+)", line)
        if header:
            if current:
                adapters.append(current)
            current = Adapter(name=header.group(1), bus=header.group(3))
            continue
        if current is None:
            continue
        addr = re.search(r"BD Address:\s+([0-9A-F:]{17})", line, re.I)
        if addr:
            current.address = addr.group(1)
        if "UP RUNNING" in line:
            current.is_up = True
        manu = re.search(r"Manufacturer:\s+(.+?)\s*$", line)
        if manu:
            current.manufacturer = manu.group(1).strip()

    if current:
        adapters.append(current)

    for a in adapters:
        a.score = _score_adapter(a)
    return adapters


def _score_adapter(adapter: Adapter) -> int:
    """Rank adapters so we can pick a default without asking.

    A USB dongle that is up beats the internal radio, because the internal one
    usually will not pass through into Docker and is often shared with Wi-Fi
    on a combo chip.
    """
    score = 0
    if adapter.is_up:
        score += 50
    if adapter.bus.upper() == "USB":
        score += 30
    if "nordic" in adapter.manufacturer.lower():
        score += 20
    if adapter.name == "hci0":
        score += 5           # tie-break only
    return score


def best_of(adapters: list[Adapter], default: str = "hci0") -> str:
    """Highest-scoring adapter from a list you already have."""
    if not adapters:
        return default
    return max(adapters, key=lambda a: a.score).name


def get_best_adapter(default: str = "hci0") -> str:
    """Pick the highest-scoring adapter, or fall back to the default name."""
    return best_of(list_adapters(), default)


# Vendors whose boards are worth reporting even on a product ID we do not
# recognise — firmware flashes change the PID, the vendor stays put.
SNIFFER_VENDOR_IDS = {
    "1915": "Nordic Semiconductor",
    "2fe3": "Zephyr / Nordic",
    "1d50": "Great Scott Gadgets",
    "239a": "Adafruit",
}


# Serial ports a sniffer board can show up on. ttyACM is the USB CDC class
# (Nordic dongles, Zephyr firmware); ttyUSB is a UART bridge (CP210x, FTDI).
SERIAL_PATTERNS = ("ttyACM*", "ttyUSB*")


def _read_sysfs(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def _usb_parent(tty_name: str) -> Path | None:
    """Walk up from /sys/class/tty/<name> to the USB device that owns it.

    `device` points at the USB *interface*, not the device, and for a UART
    bridge there are more levels in between — so climb until we find the
    node that carries idVendor.
    """
    node = Path(f"/sys/class/tty/{tty_name}/device")
    if not node.exists():
        return None
    try:
        node = node.resolve()
    except OSError:
        return None
    for _ in range(5):
        if (node / "idVendor").exists():
            return node
        if node.parent == node:
            break
        node = node.parent
    return None


def detect_serial_devices() -> list[SerialDevice]:
    """Enumerate USB serial ports and identify them from sysfs.

    lsusb tells you a board is plugged in; this tells you which port to
    point a sniffer tool at, which is the part you actually need to type.
    """
    found: list[SerialDevice] = []
    for pattern in SERIAL_PATTERNS:
        for port in sorted(glob(f"/dev/{pattern}")):
            name = Path(port).name
            dev = SerialDevice(port=port, writable=os.access(port, os.W_OK))
            usb = _usb_parent(name)
            if usb:
                vid = _read_sysfs(usb / "idVendor").lower()
                pid = _read_sysfs(usb / "idProduct").lower()
                if vid and pid:
                    dev.usb_id = f"{vid}:{pid}"
                dev.manufacturer = _read_sysfs(usb / "manufacturer")
                dev.product = _read_sysfs(usb / "product")
                dev.serial = _read_sysfs(usb / "serial")
            found.append(dev)
    return found


def detect_sniffer_hardware(
    serial_devices: list[SerialDevice] | None = None,
) -> list[SnifferHardware]:
    """Find hardware that can do channel-level sniffing.

    Two sources, because neither alone is enough. lsusb sees boards that
    expose no serial port (a dongle in DFU mode). Serial enumeration sees
    boards whose VID:PID we do not have in the table — firmware changes the
    product ID, so the list will always lag reality; a Nordic or Ubertooth
    VID on a serial port is worth reporting even when the exact PID is new.
    """
    if serial_devices is None:
        serial_devices = detect_serial_devices()

    found: dict[str, SnifferHardware] = {}

    out = _run(["lsusb"]).lower()
    for usb_id, description in SNIFFER_USB_IDS.items():
        if usb_id and usb_id in out:
            found[usb_id] = SnifferHardware(usb_id=usb_id, description=description)

    for dev in serial_devices:
        known = SNIFFER_USB_IDS.get(dev.usb_id)
        vendor = dev.usb_id.split(":")[0] if dev.usb_id else ""
        if not known and vendor not in SNIFFER_VENDOR_IDS:
            continue
        description = known or _describe_unknown(dev, vendor)
        entry = found.setdefault(
            dev.usb_id or dev.port,
            SnifferHardware(usb_id=dev.usb_id, description=description),
        )
        entry.port = entry.port or dev.port

    return list(found.values())



def _describe_unknown(dev: SerialDevice, vendor: str) -> str:
    """Best-effort label for a board on a known vendor but unknown product."""
    label = " ".join(x for x in (dev.manufacturer, dev.product) if x)
    vendor_name = SNIFFER_VENDOR_IDS.get(vendor, "unknown vendor")
    return f"{label or vendor_name} (unrecognised product ID)"


def detect_tools() -> dict[str, bool]:
    """Which sniffer/analysis tools are on PATH."""
    return {tool: shutil.which(tool) is not None for tool in SNIFFER_TOOLS}


def scan_hardware() -> HardwareReport:
    """Full inventory — adapters, sniffer hardware, and installed tools."""
    report = HardwareReport()
    report.adapters = list_adapters()
    report.serial_devices = detect_serial_devices()
    report.sniffers = detect_sniffer_hardware(report.serial_devices)
    report.tools = detect_tools()
    report.best_adapter = best_of(report.adapters)

    for sniffer in report.sniffers:
        if "ubertooth" in sniffer.description.lower():
            sniffer.tool_available = report.tools.get("ubertooth-btle", False)
        elif "nrf52840" in sniffer.description.lower():
            sniffer.tool_available = report.tools.get("sniff_receiver.py", False)
    return report


def print_report(report: HardwareReport):
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console()

    t = Table(title="HCI Adapters", box=box.ROUNDED, border_style="cyan")
    t.add_column("Name", style="bold white", width=8)
    t.add_column("Address", style="magenta", width=18)
    t.add_column("Bus", style="dim", width=8)
    t.add_column("State", width=8)
    t.add_column("Score", style="cyan", width=6)
    if report.adapters:
        for a in sorted(report.adapters, key=lambda x: -x.score):
            state = "[green]UP[/]" if a.is_up else "[red]DOWN[/]"
            t.add_row(a.name, a.address or "?", a.bus, state, str(a.score))
        console.print(t)
    else:
        logger.error("No HCI adapters found")
        logger.info("  Install bluez:      sudo apt install bluez bluez-tools")
        logger.info("  Bring one up:       sudo hciconfig hci0 up")
        logger.info("  In a VM, pass the USB dongle through to the guest")

    t = Table(title="Sniffer Hardware", box=box.ROUNDED, border_style="magenta")
    t.add_column("USB ID", style="dim", width=12)
    t.add_column("Device", style="bold white", width=38)
    t.add_column("Port", style="cyan", width=16)
    t.add_column("Driver tool", width=14)
    if report.sniffers:
        for sniffer in report.sniffers:
            ok = "[green]ready[/]" if sniffer.tool_available else "[yellow]missing[/]"
            t.add_row(sniffer.usb_id, sniffer.description,
                      sniffer.port or "—", ok)
        console.print(t)
    else:
        logger.info("No dedicated sniffer hardware detected")
        logger.info("  Channel-level sniffing and connection following need one of:")
        logger.info("    nRF52840 dongle + Sniffle firmware  (~20 EUR, best value)")
        logger.info("    Ubertooth One                       (~120 EUR)")

    # A board can be plugged in and still be useless to us: no serial port
    # (wrong firmware, or DFU mode), or a port we cannot write to.
    for sniffer in report.sniffers:
        if not sniffer.port:
            logger.warning(
                f"{sniffer.description} is on USB but exposes no serial port — "
                "wrong firmware, or the board is in DFU/bootloader mode"
            )
    for dev in report.serial_devices:
        if dev.usb_id in SNIFFER_USB_IDS and not dev.writable:
            logger.warning(f"{dev.port} is not writable by this user")
            logger.info("  sudo usermod -aG dialout $USER   (then log out and back in)")

    t = Table(title="Tools", box=box.SIMPLE, border_style="cyan")
    t.add_column("Tool", style="bold white", width=20)
    t.add_column("Status", width=10)
    t.add_column("Purpose", style="dim", width=50)
    for tool, purpose in SNIFFER_TOOLS.items():
        ok = "[green]found[/]" if report.tools.get(tool) else "[dim]absent[/]"
        t.add_row(tool, ok, purpose)
    console.print(t)

    logger.success(f"Best adapter for this session: {report.best_adapter}")
    if len([a for a in report.adapters if a.is_up]) >= 2:
        logger.info("Two or more adapters are up — 'meshbreaker sniff --parallel' can use them")
