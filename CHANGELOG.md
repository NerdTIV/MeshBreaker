# Changelog

## [Unreleased]

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
