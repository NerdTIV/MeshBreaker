# Changelog

## [Unreleased]

### Added
- `privacy` command and `src/modules/privacy_audit.py` — audits address
  rotation and linkability. BLE privacy rests on a random address that
  changes every fifteen minutes or so, which only helps if the advertisement
  content changes with it: anything identical on both sides of a rotation
  ties the old address to the new one and the device stays trackable. The
  module classifies each address (public, static random, resolvable private,
  non-resolvable) and reports every payload broadcast under more than one
  address, naming the field that carried the link. Findings are graded:
  evidence shorter than 8 bytes, spread over more than four addresses, or of
  low byte entropy is marked weak, because a value every device of a model
  sends is not a fingerprint. Flags and TX power are never used as evidence —
  every device sends the same ones. A capture shorter than the spec rotation
  period says so, since finding no rotation in 25 seconds means the capture
  was short, not that the device stands still.
- `hci-capture` now records the address type reported by the controller,
  which the parser already decoded and then dropped. Without it, public and
  non-resolvable addresses cannot be told apart.
- `continuity` command and `src/modules/apple_continuity.py` — decodes Apple
  Continuity messages out of manufacturer data under company ID 0x004C.
  Handoff, Find My, AirDrop, Nearby Info, Proximity Pairing and the rest ride
  in a run of type-length-value messages that Apple does not document and
  that are mostly neither authenticated nor encrypted, so anything in radio
  range can read them. iBeacon is decoded in full; Handoff, Nearby Info,
  Find My and Proximity Pairing expose the fields the public research
  supports; anything else is named and handed back raw rather than guessed
  at. The report says which messages carry state about the device or its
  owner. Tested against payloads captured off the air, including a real
  iBeacon and the zero padding that used to parse as an endless run of empty
  messages.
- `recon --fuzzable MAC[,MAC...]` connects to the devices you name and reports
  what a fuzzer could write to: connectable or not, negotiated MTU, service
  count and every writable characteristic. A scan cannot answer this —
  nothing in an advertisement says whether a device accepts connections, and
  characteristics only exist once service discovery has run. It never picks
  targets on its own; `scanned` sweeps everything the scan found and says out
  loud that it only belongs in a lab you own.
- `docs/LAB_TARGET.md` — turning a phone into a BLE peripheral so there is
  something legitimate to practise on, with the traps that cost an hour
  otherwise: iOS rotates its address every few minutes, both platforms stop
  advertising when the app is backgrounded, and the advertised name is often
  not the one you asked for.
- CI now runs the test suite. The workflow linted, built the Docker image and
  checked that `--help` loads, but never ran a single test — on Python 3.11,
  3.12 and 3.13. It installs only what the tests import (`bleak`, `click`,
  `rich`, `pycryptodome`) rather than `requirements.txt`, which also pulls
  `bluepy` — unused anywhere in the code and a source build that would make
  the job fail for nothing.
- `hci-capture` command and `src/modules/hci_capture.py` — captures complete
  advertising payloads through the Linux HCI monitor socket (the interface
  `btmon` uses) and parses the AD structures itself, recovering the mesh AD
  types 0x29/0x2A/0x2B that BlueZ never exposes to bleak. Linux and root, but
  no sniffer hardware, and its output feeds `provisioning`, `df` and
  `parse-capture` directly. Python's `bind()` cannot reach the monitor channel
  — CPython hardcodes `HCI_CHANNEL_RAW` for `BTPROTO_HCI` — so the module
  builds the `sockaddr_hci` and calls `bind(2)` through libc. The packet
  decode path is split into `read_loop()` so it can be exercised over a
  socketpair with real monitor-format packets, leaving only the privileged
  bind untested — `btmon` itself fails identically without privileges, which
  independently confirms the sockaddr layout.
- `MeshServiceDataAnalyzer` in `provisioning.py` — recovers mesh state from
  service data, which BlueZ *does* expose, so a standard adapter is no longer
  blind. Decodes the Mesh Provisioning service (0x1827) into unprovisioned
  nodes with their Device UUID and OOB information bitmap, and the Mesh Proxy
  service (0x1828) into Network ID or Node Identity advertising. Flags
  unprovisioned nodes advertising no OOB (they can only be provisioned with
  No OOB, so nothing authenticates the provisioner) and nodes advertising
  Node Identity (individually trackable). With `provisioning --netkey`, it
  matches observed Network IDs against `k3(NetKey)` to tell you which nodes
  in range belong to your network.
- `capture` now records service data, which it previously discarded.
- `setup` missed an nRF52840 plugged in as a serial device: USB ID `2fe3:0004`
  was not in the table, and serial ports were never enumerated at all, so a
  connected dongle was reported as "no sniffer hardware detected". The report
  now lists the port to point a tool at, warns when a board is on USB but
  exposes no port (wrong firmware, or DFU mode) or when the port is not
  writable, and reports boards on a known vendor ID even when the product ID
  is one we have not seen — flashing firmware changes the product ID, so that
  table will always lag reality.
- `capture_io.profile_capture()` and `warn_if_mesh_blind()` — a capture that
  structurally cannot contain mesh traffic now says so, instead of reporting
  a clean-looking "nothing found". Wired into `provisioning`, `df` and
  `mesh_frame_parser`.
- `src/modules/mesh_crypto.py` — Bluetooth Mesh network layer cryptography:
  `s1`, `k2`, `k3`, `k4`, network nonce construction, AES-CCM encryption with
  the correct MIC length per message type, header obfuscation, and Proxy PDU
  SAR segmentation. Verified byte-exact against the sample vectors published
  in Mesh Profile 1.0.1, including sample message #1; the test suite asserts
  those vectors and a failure there should be treated as blocking.
- `df_path_inject` plugin — builds an encrypted network control message
  carrying a Directed Forwarding path discovery opcode and writes it to a
  proxy node over GATT. Requires the NetKey, which is the point rather than a
  limitation: Directed Forwarding trusts the network, not the node. Supports
  a dry-run mode that builds and prints without transmitting, and raw
  parameter passthrough for exact spec bytes. GATT Proxy bearer only — the
  ADV bearer needs WHAD or Mirage and is not wired up yet.
- `exploit --netkey`, `--iv-index` and repeatable `--opt KEY=VALUE` for
  passing configuration to plugins.
- `exploit --list-plugins` to show what is loaded.
- `PluginBase` now accepts an optional `config` dict, with `option()` and
  `require()` helpers. Optional, so plugins written before this keep working.
- `auto` command — runs the whole assessment chain in one go, carrying session
  state between phases. Passive by default; fuzzing only runs with `--active`.
- `provisioning` command — audits BLE Mesh provisioning. Decodes PB-ADV
  sessions from a capture (the early provisioning PDUs are unencrypted, so the
  negotiated authentication method is readable passively) and probes targets
  for an exposed PB-GATT service. Flags No OOB authentication, missing Static
  OOB support, and undersized OOB values.
- `df` command — audits Mesh Protocol 1.1 Directed Forwarding exposure from
  firmware symbols, Composition Data, or a capture. Based on the analysis
  published at SSTIC 2025 by Tali, Cayre, Nicomette and Auriol (LAAS-CNRS).
- `channels` command — BLE channel reference (40 channels x 2 MHz), plus hop
  sequence prediction from a captured CONNECT_IND using either channel
  selection algorithm.
- `sniff` command — parallel capture across several HCI adapters, or drives
  Sniffle / Ubertooth for real channel-level sniffing.
- `setup` command — inventories HCI adapters, sniffer hardware and installed
  tools, and picks a sensible default adapter.
- `src/modules/channel_map.py` — channel/frequency mapping, CONNECT_IND
  parsing, and both hop algorithms (legacy and Bluetooth 5.0+).
- 9 new CVE database entries covering SIG Mesh provisioning
  (CVE-2020-26555 through CVE-2020-26560), Zephyr mesh provisioning
  (CVE-2020-10061, CVE-2021-3430) and the Directed Forwarding research finding.
- `sig_mesh_11` protocol signature for Mesh Protocol 1.1 stacks.
- Provisioning, Directed Forwarding and connection-following sections in the
  generated reports.
- 88 new tests (93 total) covering the mesh crypto spec vectors, channel math,
  both hop algorithms, provisioning PDU decoding, mesh service data, HCI
  monitor and AD structure parsing, Directed Forwarding detection, path
  injection, MTU negotiation, adapter scoring, phase gating, CVE db
  integrity, corrupt capture handling and BLE error explanation.

### Fixed
- A capture whose scan could not start ran to completion recording nothing.
  The monitor socket is passive — it shows what the adapter already receives
  — so with no scan in progress it captures silence. The failure was only a
  warning, so `hci-capture -d 2700` spent forty-five minutes listening to an
  adapter nobody had put into scanning mode. It now stops within seconds and
  says why, unless `--no-scan` says you are driving the scan yourself.
- The GATT fuzzer kept writing into a dead connection. A target that tears
  the link down on the first unauthorised write — which is what iOS does —
  left every later payload failing with BlueZ's "Service Discovery has not
  been performed yet", a string the crash heuristic did not recognise. Those
  payloads were still counted, so the summary claimed hundreds of writes that
  never left the machine. The fuzzer now checks `client.is_connected`, stops
  on link loss, reports how many payloads were skipped, and reconnects with a
  growing backoff to finish the remaining characteristics. A link loss is
  reported as a finding in its own right: the target tore down the connection
  instead of rejecting the write.
- Errors carrying no message printed as nothing: bleak raises
  `TimeoutError('')` on a failed connection, so `enumerate` reported
  "GATT enumeration failed: " and left you guessing. `logger.describe()`
  falls back to the exception type, and the nine BLE and subprocess error
  paths use it.
- A GATT timeout suggested checking the target was advertising, which is
  wrong half the time. A link that comes up and then stalls in service
  discovery times out identically — that is what a device with no usable ATT
  server looks like. Both cases are now named, with `btmon` to tell them
  apart.
- Every report said `Devices found: 0`. `recon` filled `session.devices`, but
  the session saver never wrote the field, so the next command reloaded an
  empty list. Devices now survive the round trip.
- A failed GATT enumeration left a bare `## GATT Enumeration` heading with
  nothing under it. The section is emitted only when there is something to
  report, and says so explicitly when no writable characteristic was found.
- `hci-capture` returned an empty capture on any Bluetooth 5 controller.
  BlueZ switches to extended scanning by itself when the controller supports
  it, and reports then arrive as LE Extended Advertising Report (subevent
  0x0D) instead of the legacy 0x02. Only 0x02 was decoded, so everything else
  was dropped without a word — the user saw "No advertising reports captured"
  and read it as "nothing is advertising". On an Intel AX200 the same 25
  seconds went from 0 to 2464 AD structures.
- `provisioning --capture` invented provisioning sessions out of unrelated
  adverts. Frames that were not PB-ADV still reached the parser, and
  `parse_pb_adv()` succeeds on any buffer of 6 bytes or more because it reads
  the first four as a Link ID — so an Apple beacon was reported as a
  provisioning session with link ID 0xFF4C0002. In an audit tool a false
  "provisioning traffic observed" is worse than silence. Frames are now
  filtered on the authoritative `ad_type` field, falling back to the payload
  only for captures that carry no type.
- MAC addresses were mangled on screen: Rich renders `:cd:` as a CD emoji, so
  `64:01:60:CD:9A:1C` printed as `64:01:60(disc)9A:1C` and the address shown
  was not the address on the air. Every Console is now built with
  `emoji=False`, and a test enforces it.
- `recon` crashed with `AttributeError: 'int' object has no attribute 'replace'`
  as soon as a scan actually found a device. The `enumerate` CLI command is a
  module-level `def enumerate(...)`, which shadows the builtin for the whole
  file, and `_print_devices()` calls the builtin. With no adapter the device
  list is always empty and the loop never runs, so the bug stayed invisible
  until the first real scan. The command keeps its CLI name through
  `@cli.command("enumerate")`; the function is now `enumerate_cmd`. A test
  checks no command shadows a builtin.
- `df_path_inject` segmented proxy PDUs against a hardcoded 20-byte assumption
  made before connecting, so it fragmented messages the link could have
  carried in one write. Segmentation now happens after connecting, against the
  negotiated `client.mtu_size`. `wrap_proxy_pdu()` takes an `att_mtu` and
  derives the usable size itself (`ATT_MTU - 4`: 3 octets for the ATT write,
  1 for the proxy header), which is harder to get subtly wrong than passing a
  pre-computed budget. Backends that report no MTU fall back to the 23-byte
  minimum rather than segmenting against a garbage value.
- `recon` and `capture` crashed with a raw Python traceback when the Bluetooth
  service was not running — a very common state in Docker, in a VM, or on a
  fresh install. The underlying `BleakDBusError: Unit dbus-org.bluez.service
  not found.` did not match the existing string checks, so it propagated. All
  BLE entry points now route through `adapter_manager.explain_ble_error()` and
  print what to actually do (`sudo systemctl start bluetooth`, `hciconfig`,
  group membership), while unrecognised errors still re-raise so real bugs are
  not swallowed.
- Capture files are untrusted input and every parser assumed they were well
  formed. A truncated, hand-edited or foreign JSON file produced a traceback
  from `json.loads`, and a frame with odd-length or non-hex `raw` crashed
  `bytes.fromhex`. Affected `parse-capture`, `provisioning` and `df`. Added
  `src/utils/capture_io.py` as the single defensive loader: it reports what is
  wrong with the file, and skips and counts bad frames rather than losing the
  whole capture over one corrupt advert.
- `df --capture FILE` was silently ignored whenever the session held a
  firmware path from an earlier command, because the firmware branch was
  checked first. Explicit flags now take precedence over session state.
- Removed dead imports across `meshbreaker.py`, `enumerator.py`,
  `mesh_frame_parser.py` and the new modules.
- `report --format md|html|json` crashed with `AttributeError: 'ReportGenerator'
  object has no attribute 'generate'`. Only `--format all` worked, and since
  that is the default the bug went unnoticed. `ReportGenerator.generate()` now
  exists and writes a single format.
- `FirmwareInfo.credentials` was annotated `list[dict]` but built with
  `default_factory=dict`, so it defaulted to `{}` instead of `[]`.
- `scan_hardware()` enumerated HCI adapters twice, printing the "no adapters"
  warning twice on machines without BlueZ.
- `wifi_overlap()` reported the first of all 13 Wi-Fi channels, which matched
  nearly every BLE channel and told you nothing. It now checks only the
  non-overlapping channels 1, 6 and 11 that are actually deployed.
- `fuzz` examples in the README and QUICK_START used `--type`, an option that
  does not exist — every documented example failed with
  `Error: No such option '--type'`. Docs now use `-m` / `--methods`, and
  `--type` is accepted as an alias so older scripts keep working.
- `fuzz --psm` is now wired up. `L2CAPFuzzer.run()` already accepted a PSM list
  and the README documented the flag, but the CLI never passed one through.
- CVE-2021-28139 and CVE-2019-16336 were each listed twice in `cve_db.json`, so
  they were reported twice in every match table. Merged into single entries
  with the union of their tags and detection hints, and corrected the
  `oom_write` tag to `oob_write`. A test now guards against duplicate CVE IDs.

## [2.0.0] - 2025-01-01

### Changed
- Replaced direct Python install with Docker-based workflow
- Added `install.sh` — auto-installs Docker and registers `meshbreaker` system command
- Rewrote CLI with Click (subcommands instead of interactive menu)

### Added
- `firmware` command — static analysis of BLE/IoT firmware binaries
- `fuzz` command — GATT, L2CAP, SDP, and mesh protocol fuzzing
- `recon` command — BLE scan + automatic protocol fingerprinting
- `enumerate` command — GATT service enumeration + SDP browse
- `capture` / `parse-capture` — passive BLE capture and mesh topology decode
- `cve-check` — match known CVEs against detected stack versions
- `report` — generate Markdown, HTML, or JSON reports
- Plugin system — drop Python files into `src/plugins/` to extend the tool
- Docker Compose dev profile for live code reloading

### Removed
- Interactive menu
- `run.sh` / `tools/INSTALL.sh`

## [1.0.0] - 2024-01-18

### Added
- Initial release — BLE Radio Fuzzing, Firmware Analysis, Hardware Exploitation modules
