#!/usr/bin/env python3
"""
Simple main script for Cyber-EW Fusion Cell
"""
import sys
import os
import argparse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    parser = argparse.ArgumentParser(description='Cyber-EW Fusion Cell')
    parser.add_argument('--mode', choices=['run', 'test', 'config'], 
                       default='run', help='Operation mode')
    parser.add_argument('--monitor', action='store_true', 
                       help='Enable real-time monitoring')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Cyber-EW Fusion Cell")
    print("=" * 60)
    
    if args.mode == 'run':
        from core.pipeline import CyberEWPipeline
        
        print(f"\nStarting Cyber-EW Fusion Cell...")
        print(f"Mode: {'Monitor' if args.monitor else 'Single Run'}")
        
        # Initialize pipeline
        pipeline = CyberEWPipeline()
        
        if args.monitor:
            print("\nStarting real-time monitoring...")
            print("Press Ctrl+C to stop\n")
            
            try:
                # Start the pipeline
                pipeline.start()
                
                # Interactive mode
                print("Commands: stats, alerts, stop, exit")
                
                while pipeline.running:
                    cmd = input("\n> ").strip().lower()
                    
                    if cmd == 'stats':
                        stats = pipeline.get_statistics()
                        print(f"\nStatistics:")
                        print(f"  Events Processed: {stats.get('events_processed', 0)}")
                        print(f"  Total Alerts: {stats.get('total_alerts', 0)}")
                        print(f"  Threat Intel IOCs: {stats.get('threat_intel_iocs', 0)}")
                        
                    elif cmd == 'alerts':
                        alerts = pipeline.get_recent_alerts(limit=10)
                        if alerts:
                            print(f"\nRecent Alerts ({len(alerts)}):")
                            for i, alert in enumerate(alerts, 1):
                                print(f"  {i}. {alert.get('title', 'Unknown')}")
                        else:
                            print("No recent alerts")
                            
                    elif cmd == 'stop':
                        pipeline.stop()
                        print("Monitoring stopped")
                        
                    elif cmd == 'exit':
                        pipeline.stop()
                        print("Exiting...")
                        break
                        
                    else:
                        print("Unknown command")
                        
            except KeyboardInterrupt:
                print("\n\nStopping pipeline...")
                pipeline.stop()
                
        else:
            # Single run mode
            print("\nRunning single analysis cycle...")
            pipeline.start()
            import time
            time.sleep(2)  # Process for 2 seconds
            pipeline.stop()
            
            stats = pipeline.get_statistics()
            print(f"\nAnalysis complete:")
            print(f"  Events Processed: {stats.get('events_processed', 0)}")
            print(f"  Alerts Generated: {stats.get('total_alerts', 0)}")
    
    elif args.mode == 'test':
        print("\nRunning system tests...")
        os.system("python final_system_test.py")
        
    elif args.mode == 'config':
        print("\nConfiguration mode")
        print("\nConfiguration files:")
        print("  - IOCs: data/threat_intel/local_iocs.json")
        print("  - Rules: data/signatures/")
        print("  - Config: core/config.py")
        
    print("\n" + "=" * 60)
    print("Cyber-EW Fusion Cell - Operation Complete")
    print("=" * 60)

if __name__ == "__main__":
    main()