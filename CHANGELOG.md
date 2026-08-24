# Changelog

## [Unreleased]

### Added
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
