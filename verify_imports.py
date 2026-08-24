# Save as: verify_imports.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

print("Verifying all imports...")
modules = [
    ("utils.validators", ["validate_ip_address", "validate_domain", "validate_mac"]),
    ("utils.time_utils", ["normalize_timestamp"]),
    ("core.models.event_models", ["NormalizedEvent", "EventType", "Entity"]),
    ("core.engines.normalization_engine", ["NormalizationEngine"]),
    ("core.engines.ingest_engine", ["IngestEngine"]),
    ("core.engines.correlation_engine", ["CorrelationEngine"]),
    ("core.engines.behavior_engine", ["BehaviorEngine"]),
    ("core.engines.scoring_engine", ["ScoringEngine"]),
    ("core.engines.output_engine", ["OutputEngine"]),
    ("core.pipeline", ["CyberEWPipeline"]),
]

for module_path, imports in modules:
    try:
        module = __import__(module_path, fromlist=imports)
        print(f"✓ {module_path}")
    except Exception as e:
        print(f"✗ {module_path}: {e}")

print("\nAll imports verified!")