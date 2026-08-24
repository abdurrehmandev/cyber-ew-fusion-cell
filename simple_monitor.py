#!/usr/bin/env python3
import sys
import os
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("Cyber-EW Fusion Cell - Simple Monitor")
print("=" * 60)

try:
    from core.pipeline import CyberEWPipeline
    
    # Create pipeline with fixed engines
    pipeline = CyberEWPipeline()
    
    try:
        from core.engines.fixed_ml_engine import FixedMLEngine
        from core.engines.fixed_signature_engine import FixedSignatureEngine
        pipeline.ml_anomaly_engine = FixedMLEngine()
        pipeline.signature_engine = FixedSignatureEngine()
        print("Fixed engines loaded")
    except ImportError:
        print("Using original engines")
    
    # Start pipeline
    pipeline.start()
    print("Pipeline started (Press Ctrl+C to stop)")
    
    # Monitor loop
    event_count = 0
    alert_count = 0
    
    try:
        while True:
            stats = pipeline.get_statistics()
            current_events = stats.get("events_processed", 0)
            current_alerts = stats.get("total_alerts", 0)
            
            if current_events > event_count or current_alerts > alert_count:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Events: {current_events}, Alerts: {current_alerts}")
                event_count = current_events
                alert_count = current_alerts
            
            # Show recent alerts
            if current_alerts > 0:
                alerts = pipeline.get_recent_alerts(limit=2)
                for alert in alerts:
                    title = alert.get("title", "Alert")
                    if title != "Unknown Alert":
                        print(f"  ! {title}")
            
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\nStopping...")
    
    finally:
        pipeline.stop()
        print("Pipeline stopped")
        
        # Final stats
        stats = pipeline.get_statistics()
        print(f"\nFinal stats:")
        print(f"  Total events: {stats.get('events_processed', 0)}")
        print(f"  Total alerts: {stats.get('total_alerts', 0)}")
        
except Exception as e:
    print(f"Error: {e}")

print("\n" + "=" * 60)
print("Monitor stopped")
print("=" * 60)