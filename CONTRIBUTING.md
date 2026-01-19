# Contributing

Contributions are welcome. This project is intended for authorized security testing and research; please use it responsibly.

## Reporting Bugs

Before submitting a bug, please check the existing issues to avoid duplicates.

Your bug report should include:
- A clear description of the issue.
- Steps to reproduce it.
- Relevant logs, error messages, and environment details (OS, Python version, etc.).

## Pull Requests

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/my-new-feature`).
3.  Commit your changes (`git commit -m 'feat: Add some feature'`).
4.  Push to the branch (`git push origin feature/my-new-feature`).
5.  Open a Pull Request.

Please keep your changes focused, test them, and follow the existing code style.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/MeshBreaker.git
cd MeshBreaker

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest
```

## Code Style

-   Use PEP 8 for Python code.
-   Keep lines under 100 characters.
-   Use clear and descriptive variable names.
-   Write simple, readable commit messages (e.g., `feat: Add new hardware fuzzing module`).
