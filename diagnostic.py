import os
import sys

def check_project():
    print("Cyber-EW Fusion Cell Diagnostic")
    print("=" * 60)
    
    current = os.getcwd()
    print(f"Directory: {current}")
    
    # Check directories
    dirs = ['core', 'config', 'utils', 'tests', 'data']
    for d in dirs:
        path = os.path.join(current, d)
        if os.path.exists(path):
            files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
            print(f"[DIR] {d}/: {len(files)} files")
        else:
            print(f"[DIR] {d}/: MISSING")
    
    # Check critical files
    print("\nCritical files:")
    files = [
        'core/models/event_models.py',
        'core/engines/correlation_engine.py', 
        'core/engines/behavior_engine.py',
        'utils/time_utils.py',
        'config/settings.py'
    ]
    
    for f in files:
        if os.path.exists(f):
            size = os.path.getsize(f)
            print(f"  ✓ {f} ({size} bytes)")
        else:
            print(f"  ✗ {f}")
    
    # Count total .py files
    py_files = []
    for root, dirs, files in os.walk(current):
        if 'venv' in root:
            continue
        for file in files:
            if file.endswith('.py'):
                py_files.append(os.path.join(root, file))
    
    print(f"\nTotal Python files (excluding venv): {len(py_files)}")
    if py_files:
        print("First 10 Python files:")
        for f in py_files[:10]:
            print(f"  - {os.path.relpath(f, current)}")
    
    print("=" * 60)

if __name__ == "__main__":
    check_project()