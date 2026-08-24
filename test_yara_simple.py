import sys
try:
    # Try importing yara
    import yara
    print(f"✓ YARA imported successfully")
    print(f"  Version: {yara.__version__ if hasattr(yara, '__version__') else 'unknown'}")
    print(f"  Path: {yara.__file__}")
    
    # Try a simple rule
    rule_source = 'rule test { strings: $a = "test" condition: $a }'
    rule = yara.compile(source=rule_source)
    print("✓ YARA rule compilation works")
    
except Exception as e:
    print(f"✗ YARA error: {e}")
    
    # Check if there's a DLL issue
    import platform
    if platform.system() == 'Windows':
        print("\nWindows YARA fix:")
        print("1. Download yara.dll from: https://github.com/VirusTotal/yara/releases")
        print("2. Place it in C:\\Windows\\System32 or your Python directory")
        print("3. Or try: pip install yara-python-win32")