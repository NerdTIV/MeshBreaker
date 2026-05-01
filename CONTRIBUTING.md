# Contributing

Contributions are welcome. This project is intended for authorized security testing and research only.

## Reporting Bugs

Check existing issues before opening a new one. Include:
- Clear description of the problem
- Steps to reproduce
- Relevant error output, OS, and Python version

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'feat: add some feature'`)
4. Push to your fork and open a Pull Request

Keep changes focused. One feature or fix per PR.

## Development Setup

```bash
git clone https://github.com/yourusername/MeshBreaker.git
cd MeshBreaker
bash install.sh
```

`install.sh` installs Docker if needed, builds the image, and adds the `meshbreaker` command to your PATH.

For live code editing without rebuilding the image:

```bash
docker compose --profile dev up
```

This mounts `src/` directly into the container so changes take effect immediately.

## Code Style

- PEP 8, max line length 100
- No unnecessary comments — names should be self-explanatory
- Keep it simple and readable
