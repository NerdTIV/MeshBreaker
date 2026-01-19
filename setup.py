#!/usr/bin/env python3

from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="meshbreaker-ble-suite",
    version="1.0.0",
    author="MeshBreaker Contributors",
    author_email="",
    description="BLE and hardware security testing toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/user/meshbreaker-ble-suite",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest",
            "pytest-cov",
            "black",
            "flake8",
            "mypy",
        ],
    },
    entry_points={
        "console_scripts": [
            "ble-sniffer=script.radio_fuzzing.ble_packet_sniffer:main",
            "ble-enum=script.radio_fuzzing.ble_service_enumerator:main",
            "ble-fuzz=script.radio_fuzzing.ble_radio_fuzzer:main",
            "hw-fuzz=script.hardware_exploitation.hardware_fuzzer:main",
            "crypto-extract=script.firmware_analysis.crypto_key_extractor:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/user/MeshBreaker/issues",
        "Source": "https://github.com/user/MeshBreaker",
    },
    keywords="ble bluetooth fuzzing security hardware firmware",
    include_package_data=True,
    zip_safe=False,
)
