#!/usr/bin/env python3
"""Quick test of all components"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("Quick System Test")
print("=" * 60)

# Test 1: Check what's in core directory
print("\n1. Checking core directory...")
try:
    import core
    print(f"   Core package found: {core.__file__}")
    print("   Contents:", [x for x in dir(core) if not x.startswith('_')])
except Exception as e:
    print(f"   Error: {e}")

# Test 2: Check pipeline module
print("\n2. Checking pipeline module...")
try:
    import core.pipeline as pipeline_module
    print(f"   Pipeline module found: {pipeline_module.__file__}")
    
    # List all classes in pipeline
    import inspect
    classes = [name for name, obj in inspect.getmembers(pipeline_module) 
               if inspect.isclass(obj) and obj.__module__ == 'core.pipeline']
    print(f"   Classes in pipeline: {classes}")
    
    # Try to find a pipeline class
    for class_name in classes:
        if 'pipeline' in class_name.lower() or 'Pipeline' in class_name:
            print(f"   Found pipeline class: {class_name}")
            PipelineClass = getattr(pipeline_module, class_name)
            break
    else:
        print("   No pipeline class found, checking for functions...")
        functions = [name for name, obj in inspect.getmembers(pipeline_module) 
                    if inspect.isfunction(obj)]
        print(f"   Functions: {functions[:5]}...")
        
except Exception as e:
    print(f"   Error: {e}")

# Test 3: Check threat intel engine
print("\n3. Checking threat intel engine...")
try:
    # Try different import paths
    try:
        from threat_intel_engine import ThreatIntelEngine
        print("   ✓ Imported from threat_intel_engine")
    except ImportError:
        try:
            from core.threat_intel_engine import ThreatIntelEngine
            print("   ✓ Imported from core.threat_intel_engine")
        except ImportError:
            # Try to find it
            import importlib.util
            spec = importlib.util.find_spec("threat_intel_engine")
            if spec:
                print(f"   Found module at: {spec.origin}")
                # Dynamically import
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                ThreatIntelEngine = module.ThreatIntelEngine
                print("   ✓ Dynamically imported")
            else:
                print("   ✗ Could not find threat_intel_engine module")
                
    # Test the engine
    engine = ThreatIntelEngine()
    print(f"   ✓ Engine created: {len(engine.feeds)} feeds loaded")
    
except Exception as e:
    print(f"   Error: {e}")

# Test 4: Check dependencies
print("\n4. Checking dependencies...")
deps = {
    'yara': ('yara', 'import yara'),
    'sklearn': ('scikit-learn', 'import sklearn'),
    'pandas': ('pandas', 'import pandas'),
    'numpy': ('numpy', 'import numpy'),
}

for name, (package, import_stmt) in deps.items():
    try:
        exec(import_stmt)
        version = eval(f"{name}.__version__") if hasattr(eval(name), '__version__') else 'unknown'
        print(f"   ✅ {package}: version {version}")
    except Exception as e:
        print(f"   ❌ {package}: {e}")

print("\n" + "=" * 60)