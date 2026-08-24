import sys
print(f"Python version: {sys.version}")
print("=" * 50)

packages = [
    ("numpy", "numpy"),
    ("pandas", "pandas"),
    ("scapy", "scapy"),
    ("pyshark", "pyshark"),
    ("stix2", "stix2"),
    ("fastapi", "fastapi"),
    ("yara", "yara"),
    ("pydantic", "pydantic")
]

print("Testing package imports:")
for name, import_name in packages:
    try:
        __import__(import_name)
        print(f"✓ {name}")
    except ImportError as e:
        print(f"✗ {name}: {e}")

print("=" * 50)
print("Installation test complete!")