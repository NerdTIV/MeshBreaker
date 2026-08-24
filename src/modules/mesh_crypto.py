"""
Bluetooth Mesh network layer cryptography.

Everything a mesh node sends is encrypted and obfuscated at the network layer.
If you want to inject a message that a node will actually process — rather than
one it drops before parsing — you have to build it properly. That means:

    NetKey  --k2()-->  NID + EncryptionKey + PrivacyKey
    payload --AES-CCM(EncryptionKey, NetworkNonce)-->  ciphertext + NetMIC
    header  --XOR PECB(PrivacyKey)-->                  obfuscated header

There is no way around holding the NetKey. That is not a gap in this code, it
is how mesh works: **the network is the trust boundary, not the node.** Anyone
inside the network is trusted by every other node in it, which is exactly why a
salvaged or resold node matters.

So use this against a network you own or have been given the keys for.

Spec references, Mesh Profile 1.0.1:
    3.8.2.3  s1  (salt generation)
    3.8.2.6  k2  (network key material derivation)
    3.8.5.1  network nonce
    3.8.7.2  network layer encryption
    3.8.7.3  header obfuscation
    6.3.1    proxy PDU format and SAR
"""

import struct

from src.utils import logger

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import CMAC
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

ZERO16 = b"\x00" * 16

PROXY_NETWORK_PDU = 0x00
PROXY_MESH_BEACON = 0x01
PROXY_CONFIGURATION = 0x02
PROXY_PROVISIONING = 0x03

SAR_COMPLETE = 0b00
SAR_FIRST = 0b01
SAR_CONTINUATION = 0b10
SAR_LAST = 0b11


def _require_crypto():
    if not CRYPTO_OK:
        raise RuntimeError("pycryptodome not installed — run: pip install pycryptodome")


def aes_cmac(key: bytes, message: bytes) -> bytes:
    """AES-CMAC, the primitive every mesh key derivation is built on."""
    _require_crypto()
    mac = CMAC.new(key, ciphermod=AES)
    mac.update(message)
    return mac.digest()


def aes_ecb(key: bytes, plaintext: bytes) -> bytes:
    """Single-block AES-ECB — the spec calls this e()."""
    _require_crypto()
    if len(plaintext) != 16:
        raise ValueError(f"e() takes exactly 16 bytes, got {len(plaintext)}")
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


def s1(message: bytes) -> bytes:
    """Salt generation: CMAC over the message with an all-zero key."""
    return aes_cmac(ZERO16, message)


def k2(net_key: bytes, p: bytes = b"\x00") -> tuple[int, bytes, bytes]:
    """Derive the network key material from a NetKey.

    Returns (NID, EncryptionKey, PrivacyKey).

    P is 0x00 for the master security material, which is what unicast and
    group traffic uses. Friendship credentials use a different P.
    """
    salt = s1(b"smk2")
    t = aes_cmac(salt, net_key)

    t1 = aes_cmac(t, p + b"\x01")
    t2 = aes_cmac(t, t1 + p + b"\x02")
    t3 = aes_cmac(t, t2 + p + b"\x03")

    material = t1 + t2 + t3
    result = material[-33:]
    nid = result[0] & 0x7F
    return nid, result[1:17], result[17:33]


def k3(net_key: bytes) -> bytes:
    """Derive the 8-byte network ID advertised in Secure Network Beacons."""
    salt = s1(b"smk3")
    t = aes_cmac(salt, net_key)
    return aes_cmac(t, b"id64" + b"\x01")[-8:]


def k4(app_key: bytes) -> int:
    """Derive the 6-bit AID for an AppKey."""
    salt = s1(b"smk4")
    t = aes_cmac(salt, app_key)
    return aes_cmac(t, b"id6" + b"\x01")[-1] & 0x3F


def network_nonce(ctl: int, ttl: int, seq: int, src: int, iv_index: int) -> bytes:
    """Build the 13-byte network nonce (spec 3.8.5.1).

    Nonce type 0x00, then the same header fields that go in the PDU, then the
    IV index. Reusing a (SEQ, SRC, IV index) triple with the same key breaks
    the encryption, which is why nodes keep a replay list.
    """
    return (b"\x00"
            + bytes([((ctl & 1) << 7) | (ttl & 0x7F)])
            + seq.to_bytes(3, "big")
            + struct.pack(">H", src)
            + b"\x00\x00"
            + struct.pack(">I", iv_index))


def obfuscate_header(privacy_key: bytes, iv_index: int, header: bytes,
                     encrypted: bytes) -> bytes:
    """Obfuscate the 6-byte network header (spec 3.8.7.3).

    `header` is CTL|TTL, SEQ (3 bytes) and SRC (2 bytes). `encrypted` is the
    EncDST || EncTransportPDU || NetMIC blob, whose first 7 bytes seed the
    obfuscation so an observer cannot correlate headers across packets.
    """
    if len(header) != 6:
        raise ValueError(f"header must be 6 bytes, got {len(header)}")

    privacy_random = encrypted[:7]
    if len(privacy_random) < 7:
        raise ValueError("encrypted payload must be at least 7 bytes")

    privacy_plaintext = b"\x00" * 5 + struct.pack(">I", iv_index) + privacy_random
    pecb = aes_ecb(privacy_key, privacy_plaintext)
    return bytes(h ^ p for h, p in zip(header, pecb[:6]))


deobfuscate_header = obfuscate_header


def build_network_pdu(net_key: bytes, iv_index: int, transport_pdu: bytes,
                      src: int, dst: int, ctl: int = 1, ttl: int = 127,
                      seq: int = 1) -> bytes:
    """Build a complete, encrypted, obfuscated Network PDU.

    Set ctl=1 for network control messages (heartbeats, and the Directed
    Forwarding path discovery messages). Control messages carry a 64-bit
    NetMIC; access messages carry 32-bit. Getting that wrong makes the node
    reject the packet with no diagnostic, so it is worth stating plainly.

    Layout of the result:
        1 byte    IVI (1 bit) | NID (7 bits)
        6 bytes   obfuscated CTL|TTL, SEQ, SRC
        n bytes   EncDST || EncTransportPDU || NetMIC
    """
    _require_crypto()
    if len(net_key) != 16:
        raise ValueError(f"NetKey must be 16 bytes, got {len(net_key)}")
    if seq > 0xFFFFFF:
        raise ValueError("SEQ is a 24-bit field")

    nid, encryption_key, privacy_key = k2(net_key)

    mic_len = 8 if ctl else 4

    nonce = network_nonce(ctl, ttl, seq, src, iv_index)
    plaintext = struct.pack(">H", dst) + transport_pdu

    cipher = AES.new(encryption_key, AES.MODE_CCM, nonce=nonce, mac_len=mic_len)
    ciphertext, mic = cipher.encrypt_and_digest(plaintext)
    encrypted = ciphertext + mic

    header = (bytes([((ctl & 1) << 7) | (ttl & 0x7F)])
              + seq.to_bytes(3, "big")
              + struct.pack(">H", src))
    obfuscated = obfuscate_header(privacy_key, iv_index, header, encrypted)

    ivi = iv_index & 1
    return bytes([(ivi << 7) | nid]) + obfuscated + encrypted


def parse_network_pdu(net_key: bytes, iv_index: int, pdu: bytes) -> dict | None:
    """Decrypt a Network PDU captured from a network you hold the key for.

    Returns None when the NID does not match or the MIC fails, which is the
    normal outcome for traffic belonging to a different network.
    """
    _require_crypto()
    if len(pdu) < 14:
        return None

    nid, encryption_key, privacy_key = k2(net_key)
    if (pdu[0] & 0x7F) != nid:
        return None

    obfuscated = pdu[1:7]
    encrypted = pdu[7:]
    header = deobfuscate_header(privacy_key, iv_index, obfuscated, encrypted)

    ctl = (header[0] >> 7) & 1
    ttl = header[0] & 0x7F
    seq = int.from_bytes(header[1:4], "big")
    src = struct.unpack(">H", header[4:6])[0]

    mic_len = 8 if ctl else 4
    if len(encrypted) <= mic_len + 2:
        return None

    ciphertext, mic = encrypted[:-mic_len], encrypted[-mic_len:]
    nonce = network_nonce(ctl, ttl, seq, src, iv_index)

    try:
        cipher = AES.new(encryption_key, AES.MODE_CCM, nonce=nonce, mac_len=mic_len)
        plaintext = cipher.decrypt_and_verify(ciphertext, mic)
    except ValueError:
        return None

    return {
        "ivi": (pdu[0] >> 7) & 1,
        "nid": nid,
        "ctl": ctl,
        "ttl": ttl,
        "seq": seq,
        "src": src,
        "dst": struct.unpack(">H", plaintext[0:2])[0],
        "transport_pdu": plaintext[2:],
    }


DEFAULT_ATT_MTU = 23


def proxy_payload_size(att_mtu: int = DEFAULT_ATT_MTU) -> int:
    """How many payload bytes fit in one Proxy PDU at a given ATT MTU.

    Two deductions, and getting either wrong silently over-fragments:

        -3   a GATT write spends 3 octets on the ATT opcode and handle, so a
             proxy PDU has to fit in ATT_MTU - 3 (Mesh Profile 6.3.1)
        -1   the Proxy protocol's own header byte, 2 bits SAR + 6 bits type

    At the 23-byte default that leaves 19 bytes per write.
    """
    return max(1, att_mtu - 4)


def wrap_proxy_pdu(payload: bytes, message_type: int = PROXY_NETWORK_PDU,
                   att_mtu: int = DEFAULT_ATT_MTU) -> list[bytes]:
    """Wrap a payload into one or more Proxy PDUs for writing over GATT.

    `att_mtu` is the *negotiated* ATT MTU of the connection — read it from
    `client.mtu_size` rather than assuming the 23-byte default, or you will
    segment messages that would have fitted in a single write.

    Returns the list of writes to send in order.
    """
    usable = proxy_payload_size(att_mtu)

    if len(payload) <= usable:
        return [bytes([(SAR_COMPLETE << 6) | message_type]) + payload]

    chunks = [payload[i:i + usable] for i in range(0, len(payload), usable)]
    out = []
    for index, chunk in enumerate(chunks):
        if index == 0:
            sar = SAR_FIRST
        elif index == len(chunks) - 1:
            sar = SAR_LAST
        else:
            sar = SAR_CONTINUATION
        out.append(bytes([(sar << 6) | message_type]) + chunk)
    return out


def build_control_transport_pdu(opcode: int, parameters: bytes = b"") -> bytes:
    """Build an unsegmented network control transport PDU.

    First byte is SEG (1 bit, 0 here) then a 7-bit opcode. Directed Forwarding
    path discovery uses opcodes 0x01 to 0x07.
    """
    if not 0 <= opcode <= 0x7F:
        raise ValueError("control opcode is 7 bits")
    return bytes([opcode & 0x7F]) + parameters


def parse_key(value: str, name: str = "key", length: int = 16) -> bytes:
    """Parse a hex key from the command line, with a useful error message."""
    cleaned = value.strip().replace(" ", "").replace(":", "").replace("0x", "")
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError(f"{name} is not valid hex: {value}")
    if len(raw) != length:
        raise ValueError(f"{name} must be {length} bytes ({length * 2} hex chars), "
                         f"got {len(raw)}")
    return raw


def print_key_material(net_key: bytes):
    """Show what a NetKey derives to — handy for confirming you have the right one."""
    from rich.table import Table
    from rich import box
    from rich.console import Console

    nid, encryption_key, privacy_key = k2(net_key)
    console = Console()

    t = Table(title="Network Key Material", box=box.ROUNDED, border_style="magenta")
    t.add_column("Field", style="bold white", width=16)
    t.add_column("Value", style="cyan")
    t.add_row("NetKey", net_key.hex())
    t.add_row("NID", f"0x{nid:02X}")
    t.add_row("EncryptionKey", encryption_key.hex())
    t.add_row("PrivacyKey", privacy_key.hex())
    t.add_row("Network ID", k3(net_key).hex())
    console.print(t)
    logger.info("Compare the NID against captured traffic to confirm the key matches")
