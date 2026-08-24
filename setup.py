# File: setup.py
"""
Setup script for Cyber-EW Fusion Cell
"""
from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

# Get the long description from the README file
long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="cyber-ew-fusion-cell",
    version="1.0.0",
    description="Cyber Situational Awareness & Threat Intelligence Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourorg/cyber-ew-fusion-cell",
    author="Cyber-EW Development Team",
    author_email="dev@cyber-ew.example.com",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: Commercial",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
    ],
    keywords="cybersecurity, threat intelligence, situational awareness, ew, fusion",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9, <4",
    install_requires=[
        "scapy>=2.5.0",
        "pyshark>=0.4.3",
        "pandas>=1.5.0",
        "numpy>=1.24.0",
        "stix2>=3.0.0",
        "taxii2-client>=2.3.0",
        "fastapi>=0.95.0",
        "streamlit>=1.22.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "black",
            "pylint",
            "pytest",
            "pytest-asyncio",
        ],
        "geo": [
            "geoip2",
        ],
        "viz": [
            "plotly",
            "matplotlib",
        ],
    },
    entry_points={
        "console_scripts": [
            "cyber-ew=main:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/yourorg/cyber-ew-fusion-cell/issues",
        "Source": "https://github.com/yourorg/cyber-ew-fusion-cell",
    },
)