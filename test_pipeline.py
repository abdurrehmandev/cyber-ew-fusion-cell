# Create test_pipeline.py
import sys
sys.path.insert(0, '.')
from core.pipeline import Pipeline
from datetime import datetime, timezone

pipeline = Pipeline()

# Test with malicious IP
test_event = {
    'source_ip': '192.168.1.100',
    'destination_ip': '8.8.8.8',
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'event_type': 'network_connection',
    'severity': 'high',
    'details': {
        'bytes_sent': 5000,
        'bytes_received': 100,
        'protocol': 'TCP',
        'port': 443
    }
}

result = pipeline.process_event(test_event)
print(f"Alerts: {len(result.get('alerts', []))}")
for alert in result.get('alerts', []):
    print(f"  - {alert.get('title')}")