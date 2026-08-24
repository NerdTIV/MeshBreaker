"""
BLE channel map + connection hopping.

Two things people mix up:

  - BLE uses **40 channels**, not 80. Each channel is 2 MHz wide, and
    40 x 2 MHz = 80 MHz of spectrum (2400-2483.5 GHz). The "80" is the
    bandwidth in MHz, not a channel count.

  - 3 of those 40 are advertising channels (37, 38, 39), placed on purpose
    between the Wi-Fi 1/6/11 channels so they collide less. The other 37
    (0-36) carry connection data.

Once two devices connect, they hop across the data channels. If you want to
follow a connection with a sniffer you need to know the hop sequence, and
that sequence is fully derived from the CONNECT_IND packet sent when the
connection is set up. Miss that packet, you cannot follow the connection.

Two hop algorithms exist:

  Channel Selection Algorithm #1 (all BLE versions)
      next = (previous + hopIncrement) mod 37
      hopIncrement is in the CONNECT_IND, values 5..16.

  Channel Selection Algorithm #2 (Bluetooth 5.0+)
      A hash of the connection event counter and a channel identifier
      derived from the Access Address. Not sequential, but still fully
      deterministic once you have the Access Address.

Everything here is pure computation — no radio needed. Feed it a captured
CONNECT_IND and it tells you which channel the connection will be on at any
future event.

Spec reference: Bluetooth Core v5.4, Vol 6, Part B, section 4.5.8.
"""

import struct
from dataclasses import dataclass, field

from src.utils import logger

# Total BLE channels, and the 3 reserved for advertising.
NUM_CHANNELS = 40
NUM_DATA_CHANNELS = 37
ADV_CHANNELS = (37, 38, 39)

# hopIncrement is a 5-bit field but the spec restricts it to this range.
HOP_INCREMENT_MIN = 5
HOP_INCREMENT_MAX = 16


def channel_to_freq(channel: int) -> int:
    """BLE channel index -> centre frequency in MHz.

    The mapping is not sequential because the 3 advertising channels are
    slotted in between the data channels to dodge Wi-Fi.
    """
    if channel == 37:
        return 2402
    if channel == 38:
        return 2426
    if channel == 39:
        return 2480
    if 0 <= channel <= 10:
        return 2404 + 2 * channel
    if 11 <= channel <= 36:
        return 2428 + 2 * (channel - 11)
    raise ValueError(f"Invalid BLE channel: {channel}")


def freq_to_channel(freq_mhz: int) -> int | None:
    """Centre frequency in MHz -> BLE channel index, or None if not a BLE channel."""
    for ch in range(NUM_CHANNELS):
        if channel_to_freq(ch) == freq_mhz:
            return ch
    return None


# The three non-overlapping Wi-Fi channels are the ones actually deployed, so
# those are the ones worth warning about. Each is 22 MHz wide.
WIFI_CHANNELS = {1: 2412, 6: 2437, 11: 2462}


def wifi_overlap(channel: int) -> str | None:
    """Which commonly-deployed Wi-Fi channel this BLE channel sits under.

    Useful when a capture is missing packets: a target advertising on a
    channel buried under a busy access point loses frames.

    Only Wi-Fi 1, 6 and 11 are checked. The 2.4 GHz band nominally has 13
    channels spaced 5 MHz apart, but they are 22 MHz wide so they overlap
    heavily and real deployments stick to those three. Reporting a match
    against all 13 would flag every BLE channel and tell you nothing.
    """
    freq = channel_to_freq(channel)
    hits = [f"WiFi-{ch}" for ch, centre in WIFI_CHANNELS.items()
            if centre - 11 <= freq <= centre + 11]
    return ", ".join(hits) if hits else None


@dataclass
class ConnectionParams:
    """Everything needed to follow a connection, all of it from CONNECT_IND."""

    access_address: int = 0
    crc_init: int = 0
    win_size: int = 0
    win_offset: int = 0
    interval: int = 0          # in units of 1.25 ms
    latency: int = 0
    timeout: int = 0           # in units of 10 ms
    channel_map: int = 0       # 37-bit bitmask, bit N set = channel N in use
    hop_increment: int = 0
    sca: int = 0               # sleep clock accuracy index
    init_addr: str = ""
    adv_addr: str = ""

    @property
    def interval_ms(self) -> float:
        return self.interval * 1.25

    @property
    def timeout_ms(self) -> float:
        return self.timeout * 10.0

    @property
    def used_channels(self) -> list[int]:
        """Channels actually in use — the peers disable noisy ones."""
        return [ch for ch in range(NUM_DATA_CHANNELS) if self.channel_map & (1 << ch)]

    @property
    def channel_identifier(self) -> int:
        """Derived from the Access Address, used by hop algorithm #2."""
        return ((self.access_address >> 16) ^ (self.access_address & 0xFFFF)) & 0xFFFF


def parse_connect_ind(payload: bytes) -> ConnectionParams:
    """Parse a CONNECT_IND (also called CONNECT_REQ) PDU payload.

    Layout, 34 bytes total, all little-endian:

        InitA     6 bytes   initiator address
        AdvA      6 bytes   advertiser address
        LLData   22 bytes:
            AA           4    Access Address
            CRCInit      3
            WinSize      1
            WinOffset    2
            Interval     2
            Latency      2
            Timeout      2
            ChM          5    37-bit channel map
            Hop/SCA      1    low 5 bits = hopIncrement, high 3 bits = SCA

    Pass the payload *without* the 2-byte advertising header.
    """
    if len(payload) < 34:
        raise ValueError(f"CONNECT_IND payload too short: {len(payload)} bytes, need 34")

    init_addr = ":".join(f"{b:02X}" for b in reversed(payload[0:6]))
    adv_addr = ":".join(f"{b:02X}" for b in reversed(payload[6:12]))

    ll = payload[12:34]
    access_address = struct.unpack("<I", ll[0:4])[0]
    crc_init = int.from_bytes(ll[4:7], "little")
    win_size = ll[7]
    win_offset = struct.unpack("<H", ll[8:10])[0]
    interval = struct.unpack("<H", ll[10:12])[0]
    latency = struct.unpack("<H", ll[12:14])[0]
    timeout = struct.unpack("<H", ll[14:16])[0]
    channel_map = int.from_bytes(ll[16:21], "little")
    hop_sca = ll[21]

    return ConnectionParams(
        access_address=access_address,
        crc_init=crc_init,
        win_size=win_size,
        win_offset=win_offset,
        interval=interval,
        latency=latency,
        timeout=timeout,
        channel_map=channel_map,
        hop_increment=hop_sca & 0x1F,
        sca=(hop_sca >> 5) & 0x07,
        init_addr=init_addr,
        adv_addr=adv_addr,
    )


# Channel Selection Algorithm #1

def hop_algo1(params: ConnectionParams, events: int = 20,
              start_unmapped: int = 0) -> list[int]:
    """Predict the next `events` channels using algorithm #1.

    The unmapped channel walks in fixed steps of hopIncrement. If it lands on
    a channel that was disabled in the channel map, it gets remapped into the
    list of used channels instead.
    """
    used = params.used_channels
    if not used:
        logger.warning("Channel map is empty — cannot compute hop sequence")
        return []

    sequence: list[int] = []
    unmapped = start_unmapped
    for _ in range(events):
        unmapped = (unmapped + params.hop_increment) % NUM_DATA_CHANNELS
        if unmapped in used:
            sequence.append(unmapped)
        else:
            # Remap: index into the used-channel list.
            sequence.append(used[unmapped % len(used)])
    return sequence


# Channel Selection Algorithm #2 (Bluetooth 5.0+)

def _bit_reverse_8(value: int) -> int:
    return int(f"{value & 0xFF:08b}"[::-1], 2)


def _permute(value: int) -> int:
    """Reverse the bits inside each of the two bytes of a 16-bit value."""
    return (_bit_reverse_8(value >> 8) << 8) | _bit_reverse_8(value & 0xFF)


def _mam(a: int, b: int) -> int:
    """Multiply, add, modulo — the spec's mixing step."""
    return (a * 17 + b) & 0xFFFF


def _prn(counter: int, channel_id: int) -> int:
    """Pseudo-random number for one connection event (spec 4.5.8.3.3)."""
    value = (counter ^ channel_id) & 0xFFFF
    for _ in range(3):
        value = _permute(value)
        value = _mam(value, channel_id)
    return value ^ channel_id


def hop_algo2(params: ConnectionParams, events: int = 20,
              start_counter: int = 0) -> list[int]:
    """Predict the next `events` channels using algorithm #2.

    Unlike algorithm #1 there is no running state: each event's channel is
    computed straight from the event counter, so you can jump to any point
    in the future without replaying the sequence.
    """
    used = params.used_channels
    if not used:
        logger.warning("Channel map is empty — cannot compute hop sequence")
        return []

    channel_id = params.channel_identifier
    sequence: list[int] = []
    for i in range(events):
        prn = _prn((start_counter + i) & 0xFFFF, channel_id)
        candidate = prn % NUM_DATA_CHANNELS
        if candidate in used:
            sequence.append(candidate)
        else:
            # Remap by scaling the PRN across the used-channel list.
            index = (len(used) * prn) >> 16
            sequence.append(used[index])
    return sequence


def predict_hops(params: ConnectionParams, events: int = 20,
                 algorithm: int = 1) -> list[int]:
    """Front door for both algorithms."""
    if algorithm == 2:
        return hop_algo2(params, events)
    return hop_algo1(params, events)


def print_channel_table():
    """Reference table of all 40 channels with Wi-Fi collisions marked."""
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console()
    t = Table(title="BLE Channel Map — 40 channels x 2 MHz = 80 MHz",
              box=box.ROUNDED, border_style="cyan")
    t.add_column("Ch", style="bold white", width=4)
    t.add_column("Freq", style="cyan", width=9)
    t.add_column("Type", style="yellow", width=12)
    t.add_column("WiFi overlap", style="dim", width=14)

    for ch in list(ADV_CHANNELS) + [c for c in range(NUM_DATA_CHANNELS)]:
        kind = "ADVERTISING" if ch in ADV_CHANNELS else "data"
        overlap = wifi_overlap(ch) or "—"
        style = "bold magenta" if ch in ADV_CHANNELS else ""
        t.add_row(f"[{style}]{ch}[/]" if style else str(ch),
                  f"{channel_to_freq(ch)} MHz", kind, overlap)
    console.print(t)


def print_connection_params(params: ConnectionParams, hops: list[int] | None = None):
    """Show a parsed CONNECT_IND and, if given, the predicted hop sequence."""
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console()
    used = params.used_channels

    t = Table(title="Connection Parameters (from CONNECT_IND)",
              box=box.ROUNDED, border_style="magenta")
    t.add_column("Field", style="bold white", width=18)
    t.add_column("Value", style="cyan")
    t.add_row("Initiator", params.init_addr)
    t.add_row("Advertiser", params.adv_addr)
    t.add_row("Access Address", f"0x{params.access_address:08X}")
    t.add_row("CRCInit", f"0x{params.crc_init:06X}")
    t.add_row("Hop increment", str(params.hop_increment))
    t.add_row("Channel ID (algo 2)", f"0x{params.channel_identifier:04X}")
    t.add_row("Interval", f"{params.interval_ms:.2f} ms")
    t.add_row("Latency", str(params.latency))
    t.add_row("Timeout", f"{params.timeout_ms:.0f} ms")
    t.add_row("Channels in use", f"{len(used)} / {NUM_DATA_CHANNELS}")
    console.print(t)

    if params.hop_increment < HOP_INCREMENT_MIN or params.hop_increment > HOP_INCREMENT_MAX:
        logger.warning(
            f"hopIncrement {params.hop_increment} is outside the spec range "
            f"{HOP_INCREMENT_MIN}-{HOP_INCREMENT_MAX} — packet may be malformed"
        )

    if len(used) < NUM_DATA_CHANNELS:
        disabled = [c for c in range(NUM_DATA_CHANNELS) if c not in used]
        logger.info(f"Disabled channels: {disabled}")

    if hops:
        logger.info("Predicted channel sequence:")
        logger.data("  " + " → ".join(str(h) for h in hops))
