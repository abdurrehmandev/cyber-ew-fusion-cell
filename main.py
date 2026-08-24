#!/usr/bin/env python3
"""
Cyber-EW Fusion Cell - Main Entry Point
Defensive Cyber Intelligence Fusion Engine
"""
import sys
import os
import logging
import argparse
from datetime import datetime
import json

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.pipeline import CyberEWPipeline
from utils.time_utils import datetime_now_utc

SERVICE_COMMANDS = {"install-service", "remove-service", "start-service", "stop-service"}

def setup_logging(verbose: bool = False, log_file: str = None, log_level: str = "INFO"):
    """Setup logging configuration"""
    # Convert string log level to logging constant
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    
    log_level_num = level_map.get(log_level.upper(), logging.INFO)
    if verbose:
        log_level_num = logging.DEBUG
    
    # Create logs directory if it doesn't exist
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Default log file
    if log_file is None:
        log_file = os.path.join(
            log_dir, 
            f"cyber_ew_{datetime_now_utc().strftime('%Y%m%d_%H%M%S')}.log"
        )
    
    # Configure logging
    logging.basicConfig(
        level=log_level_num,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set specific loggers
    logging.getLogger("core").setLevel(log_level_num)
    logging.getLogger("utils").setLevel(log_level_num)
    
    return log_file

def print_banner():
    """Print Cyber-EW Fusion Cell banner"""
    banner = """
    +--------------------------------------------------------------+
    |                    CYBER-EW FUSION CELL                      |
    |           Defensive Cyber Intelligence Platform              |
    +--------------------------------------------------------------+
    """
    print(banner)

def monitor_callback(data):
    """Callback for real-time monitoring"""
    event = data["event"]
    threat_score = data["threat_score"]
    
    # Safe attribute access
    event_type = getattr(event, 'event_type', 'UNKNOWN')
    if hasattr(event_type, 'value'):
        event_type = event_type.value
    
    threat_level = getattr(threat_score, 'level', 'UNKNOWN')
    if hasattr(threat_level, 'value'):
        threat_level = threat_level.value
    
    source_ip = getattr(event, 'source_ip', 'Unknown')
    
    # Simple console output for monitoring
    print(
        f"[{data['timestamp'].strftime('%H:%M:%S')}] "
        f"Event: {event_type} | "
        f"Threat: {threat_level.upper()} | "
        f"Source: {source_ip}"
    )

def run_pipeline(args):
    """Run the main pipeline"""
    # Setup logging
    log_file = setup_logging(args.verbose, args.log_file, args.log_level)
    
    # Print banner
    print_banner()
    print(f"[*] Project: Cyber-EW Fusion Cell")
    print(f"[*] Type: Defensive Cyber Intelligence Platform")
    print(f"[*] Deployment: On-prem / Air-gapped Environments")
    print(f"[*] Status: OPERATIONAL")
    print(f"[*] Version: 1.0")
    print(f"\n[*] Log file: {log_file}")
    print(f"[*] Mode: {args.mode.upper()}")
    print(f"[*] Log level: {args.log_level}")
    print(f"[*] Verbose: {args.verbose}")
    print(f"[*] Test mode: {args.test}")
    print(f"[*] Monitor mode: {args.monitor}")
    print("-" * 60)
    
    try:
        # Create pipeline. The default settings remain the source of truth; the
        # optional CLI values are carried for components that read overrides.
        pipeline_config = {}
        if args.config:
            pipeline_config["config_path"] = args.config
        if args.data_dir:
            pipeline_config["data_dir"] = args.data_dir

        pipeline = CyberEWPipeline(pipeline_config or None)
        
        # Set monitor callback
        if args.monitor:
            pipeline.monitor_callback = monitor_callback
        
        # Handle different modes
        if args.mode == "test" or args.test:
            print("[*] Running pipeline test...")
            results = pipeline.test_pipeline()
            
            print("\n[+] Test Results:")
            print(f"  Events processed: {results['events_processed']}")
            print(f"  Alerts generated: {results['alerts_generated']}")
            print(f"  Threat scores calculated: {len(results['threat_scores'])}")
            print(f"  Behavior patterns detected: {len(results['behavior_patterns'])}")
            print(f"  Correlation clusters created: {len(results['correlation_clusters'])}")
            
            if args.verbose and results['threat_scores']:
                print("\n[+] Sample Threat Scores:")
                for score in results['threat_scores'][:3]:  # Show first 3
                    print(f"  - Level: {score['level'].upper()}, Score: {score['score']:.2f}, "
                          f"Confidence: {score['confidence']:.2f}")
            
            # Save test results
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"\n[+] Test results saved to: {args.output}")
            
            return 0
            
        elif args.mode == "console":
            print("\n[+] Starting interactive console...")
            print("Type 'help' for commands, 'exit' to quit")
            
            # Simple console loop
            while True:
                try:
                    cmd = input("\ncyber-ew> ").strip()
                    
                    if cmd.lower() in ['exit', 'quit']:
                        print("[+] Exiting console mode")
                        break
                    elif cmd.lower() == 'help':
                        print("Available commands:")
                        print("  help     - Show this help")
                        print("  exit     - Exit console")
                        print("  test     - Run quick test")
                        print("  stats    - Show pipeline statistics")
                        print("  engines  - Show loaded engines")
                        print("  start    - Start the pipeline")
                        print("  stop     - Stop the pipeline")
                    elif cmd.lower() == 'test':
                        print("[*] Running test...")
                        results = pipeline.test_pipeline()
                        print(f"[+] Test completed: {results['events_processed']} events processed")
                    elif cmd.lower() == 'stats':
                        stats = pipeline.get_stats()
                        print(f"[*] Pipeline Statistics:")
                        print(f"  Events processed: {stats.get('events_processed', 0)}")
                        print(f"  Alerts generated: {stats.get('alerts_generated', 0)}")
                        print(f"  Uptime: {stats.get('uptime', 0):.1f} seconds")
                    elif cmd.lower() == 'engines':
                        print("[*] Loaded Engines:")
                        print("  - Ingest Engine")
                        print("  - Normalization Engine")
                        print("  - Correlation Engine")
                        print("  - Behavior Engine")
                        print("  - Scoring Engine")
                        print("  - Output Engine")
                    elif cmd.lower() == 'start':
                        print("[*] Starting pipeline...")
                        pipeline.start()
                    elif cmd.lower() == 'stop':
                        print("[*] Stopping pipeline...")
                        pipeline.stop()
                    elif cmd:
                        print(f"Unknown command: {cmd}")
                        
                except KeyboardInterrupt:
                    print("\n[+] Exiting console mode")
                    break
                except Exception as e:
                    print(f"[!] Error: {e}")
            
            return 0
            
        elif args.mode == "stats":
            print("\n" + "="*60)
            print("CYBER-EW FUSION CELL - STATISTICS")
            print("="*60)
            
            stats = pipeline.get_stats()
            print(f"\n{'Metric':<30} {'Value':>10}")
            print("-" * 40)
            print(f"{'Events Processed':<30} {stats.get('events_processed', 0):>10}")
            print(f"{'Alerts Generated':<30} {stats.get('alerts_generated', 0):>10}")
            print(f"{'Pipeline Uptime (s)':<30} {stats.get('uptime', 0):>10.1f}")
            print(f"{'Processing Rate (events/s)':<30} {stats.get('processing_rate', 0):>10.2f}")
            
            # Queue status
            q_status = stats.get('queue_status', {})
            print(f"\n{'Queue Status':<30}")
            print(f"{'  Raw Events':<28} {q_status.get('raw_events', 0):>10}")
            print(f"{'  Normalized Events':<28} {q_status.get('normalized_events', 0):>10}")
            print(f"{'  Analyzed Events':<28} {q_status.get('analyzed_events', 0):>10}")
            
            print("\nSystem Status: OPERATIONAL")
            return 0
            
        elif args.mode == "run":
            # Start the pipeline
            print("[*] Starting Cyber-EW Fusion Cell pipeline...")
            pipeline.start()
            
            # Keep main thread alive
            try:
                print("[*] Pipeline is running. Press Ctrl+C to stop.")
                print("[*] Monitoring console output...")
                
                # Show status periodically
                import time
                while True:
                    time.sleep(30)  # Update status every 30 seconds
                    
                    # Get pipeline stats
                    stats = pipeline.get_stats()
                    
                    print(f"\n[*] Pipeline Status (Uptime: {stats.get('uptime', 0):.0f}s)")
                    print(f"    Events processed: {stats.get('events_processed', 0)}")
                    print(f"    Alerts generated: {stats.get('alerts_generated', 0)}")
                    print(f"    Processing rate: {stats.get('processing_rate', 0):.1f} events/sec")
                    
                    # Show queue status if available
                    if 'queue_status' in stats:
                        q = stats['queue_status']
                        print(f"    Queue status: R:{q.get('raw_events', 0)} | "
                              f"N:{q.get('normalized_events', 0)} | "
                              f"A:{q.get('analyzed_events', 0)}")
                    
                    # Show recent alerts
                    recent_alerts = pipeline.get_recent_alerts(limit=3)
                    if recent_alerts:
                        print(f"    Recent alerts: {len(recent_alerts)}")
                        for alert in recent_alerts:
                            summary = alert.get('summary', 'No summary')
                            print(f"      - {summary[:80]}{'...' if len(summary) > 80 else ''}")
            
            except KeyboardInterrupt:
                print("\n[*] Shutdown signal received...")
            
            finally:
                # Stop the pipeline
                pipeline.stop()
                print("[*] Pipeline stopped.")
            
            return 0
        else:
            print(f"[!] Unknown mode: {args.mode}")
            return 1
    
    except Exception as e:
        print(f"\n[!] Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

def main():
    """Main entry point"""
    if len(sys.argv) > 1 and sys.argv[1] in SERVICE_COMMANDS:
        try:
            from windows_service import handle_service_command
            return handle_service_command(sys.argv[1:])
        except Exception as exc:
            print(f"[!] Windows service command failed: {exc}", file=sys.stderr)
            return 1

    parser = argparse.ArgumentParser(
        description="Cyber-EW Fusion Cell - Defensive Cyber Intelligence Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Run the pipeline in normal mode
  %(prog)s --test            # Run pipeline test
  %(prog)s install-service    # Install as a Windows Service
  %(prog)s remove-service     # Remove the Windows Service
  %(prog)s --test --verbose  # Run test with verbose output
  %(prog)s --monitor         # Run with real-time monitoring
  %(prog)s --mode console    # Start in console mode
  %(prog)s --mode stats      # Show statistics
  %(prog)s --mode test       # Run in test mode
        
For more information, see the project documentation.
        """
    )
    
    # Operation mode
    parser.add_argument(
        "--mode", 
        choices=["run", "test", "stats", "console"],
        default="run",
        help="Operation mode"
    )
    
    # Flags (for backward compatibility)
    parser.add_argument(
        "--test", 
        action="store_true",
        help="Run pipeline test (overrides --mode)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--monitor", "-m",
        action="store_true",
        help="Enable real-time monitoring output"
    )
    
    # File options
    parser.add_argument(
        "--log-file",
        help="Specify custom log file path"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set logging level"
    )
    
    parser.add_argument(
        "--output", "-o",
        help="Output file for test results (JSON format)"
    )
    
    parser.add_argument(
        "--config",
        help="Path to custom configuration file"
    )
    
    parser.add_argument(
        "--data-dir",
        help="Override data directory path"
    )
    
    args = parser.parse_args()
    
    # If --test flag is used, override mode
    if args.test:
        args.mode = "test"
    
    # Run the pipeline
    return run_pipeline(args)

if __name__ == "__main__":
    sys.exit(main())
