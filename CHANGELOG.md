# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-18

### Added
- Initial release of the BLE security suite.
- BLE Radio Fuzzing module for over-the-air attacks (sniffer, enumerator, fuzzer).
- Hardware Exploitation module for peripheral fuzzing (UART, SPI, I2C, etc).
- Firmware Analysis module for extracting cryptographic keys and credentials.
- Basic project documentation and structure.

### Features
- **BLE Radio Fuzzing**: Target the BLE protocol stack via RF, including advertising, GATT, L2CAP, and Link Layer manipulation.
- **Hardware Fuzzing**: Test common hardware peripherals for vulnerabilities like buffer overflows or invalid state handling.
- **Firmware Analysis**: Statically scan firmware binaries for high-entropy regions, cryptographic constants, and known key formats.

## [Unreleased]

- Future development ideas will be tracked in the project's issues.