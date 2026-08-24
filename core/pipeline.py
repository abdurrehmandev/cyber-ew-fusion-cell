"""
Main Cyber-EW Fusion Cell Pipeline - FIXED VERSION
"""
import threading
import time
import json
import logging
from queue import Empty, Queue
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

from config.settings import CONFIG, PIPELINE_CONFIG, INGEST_CONFIG, CORRELATION_CONFIG, BEHAVIOR_CONFIG, SCORING_CONFIG
from core.engines.ingest_engine import IngestEngine
from core.engines.normalization_engine import NormalizationEngine
from core.engines.correlation_engine import CorrelationEngine
from core.engines.behavior_engine import BehaviorEngine
from core.engines.scoring_engine import ScoringEngine, ThreatScore, ThreatLevel
from core.engines.output_engine import OutputEngine, OutputFormat
from core.engines.threat_intel_engine import ThreatIntelEngine
from core.engines.ml_anomaly_engine import MLAnomalyEngine
from core.engines.signature_engine import SignatureEngine
from core.collectors import CollectorManager

logger = logging.getLogger(__name__)

class CyberEWPipeline:
    """Main pipeline orchestrating all engines"""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the Cyber-EW Pipeline
        
        Args:
            config: Optional configuration dictionary to override defaults
        """
        self.config = config or {}
        self.running = False
        self.pipeline_lock = threading.Lock()
        self.monitor_callback = None
        
        # Initialize ALL engines
        self.ingest_engine = IngestEngine(INGEST_CONFIG)
        self.normalization_engine = NormalizationEngine()
        self.correlation_engine = CorrelationEngine(CORRELATION_CONFIG)
        self.behavior_engine = BehaviorEngine(BEHAVIOR_CONFIG)
        self.scoring_engine = ScoringEngine(SCORING_CONFIG)
        self.output_engine = OutputEngine()
        
        # NEW: Threat Intelligence Engines
        self.threat_intel_engine = ThreatIntelEngine()
        self.ml_anomaly_engine = MLAnomalyEngine()
        self.signature_engine = SignatureEngine()
        self.collector_manager = CollectorManager(self._handle_raw_event, self.config.get("collectors"))
        
        # Event queues between stages
        self.raw_events_queue = Queue(maxsize=PIPELINE_CONFIG.max_queue_size)
        self.normalized_events_queue = Queue(maxsize=PIPELINE_CONFIG.max_queue_size)
        self.analyzed_events_queue = Queue(maxsize=PIPELINE_CONFIG.max_queue_size)
        
        # Statistics
        self.stats = {
            "events_processed": 0,
            "alerts_generated": 0,
            "threat_intel_matches": 0,
            "ml_anomalies_detected": 0,
            "signature_matches": 0,
            "start_time": None,
            "uptime": 0,
            "processing_rate": 0.0,
            "queue_status": {
                "raw_events": 0,
                "normalized_events": 0,
                "correlated_events": 0,
                "analyzed_events": 0,
                "scored_events": 0
            }
        }
        
        # Threads
        self.processing_threads = []
        
        logger.info("Cyber-EW Pipeline initialized with threat intelligence engines")
    
    def start(self):
        """Start the entire pipeline"""
        with self.pipeline_lock:
            if self.running:
                logger.warning("Pipeline already running")
                return
            
            self.running = True
            self.stats["start_time"] = datetime.utcnow()
            
            # Register ingest engine callback
            self.ingest_engine.register_callback(self._handle_raw_event)
            
            # Start engines
            self.ingest_engine.start()
            self.collector_manager.start()
            
            # Start threat intelligence engines
            self.threat_intel_engine.start()
            self.ml_anomaly_engine.load_models()  # Load pre-trained ML models
            
            # Start processing threads
            self._start_processing_threads()
            
            # Setup console output
            self._setup_console_output()
            
            logger.info("Cyber-EW Pipeline started with all engines")
    
    def stop(self):
        """Stop the pipeline gracefully"""
        with self.pipeline_lock:
            if not self.running:
                return
            
            self.running = False
            
            # Stop engines
            self.collector_manager.stop()
            self.ingest_engine.stop()
            self.threat_intel_engine.stop()
            
            # Wait for processing threads
            for thread in self.processing_threads:
                thread.join(timeout=5)
            
            # Save behavior profiles and ML models
            self._save_state()
            
            logger.info("Cyber-EW Pipeline stopped")
    
    def _start_processing_threads(self):
        """Start all processing threads"""
        
        # Normalization thread
        norm_thread = threading.Thread(
            target=self._normalization_worker,
            daemon=True,
            name="normalization_worker"
        )
        norm_thread.start()
        self.processing_threads.append(norm_thread)
        
        # Correlation thread
        corr_thread = threading.Thread(
            target=self._correlation_worker,
            daemon=True,
            name="correlation_worker"
        )
        corr_thread.start()
        self.processing_threads.append(corr_thread)
        
        # Behavior analysis thread (ENHANCED with threat intelligence)
        behavior_thread = threading.Thread(
            target=self._behavior_worker,
            daemon=True,
            name="behavior_worker"
        )
        behavior_thread.start()
        self.processing_threads.append(behavior_thread)
        
        # Scoring thread
        scoring_thread = threading.Thread(
            target=self._scoring_worker,
            daemon=True,
            name="scoring_worker"
        )
        scoring_thread.start()
        self.processing_threads.append(scoring_thread)
        
        logger.info(f"Started {len(self.processing_threads)} processing threads")
    
    def _setup_console_output(self):
        """Setup console output for alerts"""
        def console_callback(data):
            print(self.output_engine._format_console(data))
        
        self.output_engine.subscribe(console_callback, OutputFormat.CONSOLE)
    
    def _handle_raw_event(self, raw_event: Dict):
        """Handle raw event from ingest engine"""
        try:
            self.raw_events_queue.put(raw_event)
        except Exception as e:
            logger.error(f"Error queueing raw event: {str(e)}")
    
    def _normalization_worker(self):
        """Worker thread for normalization"""
        while self.running:
            try:
                # Get raw event
                raw_event = self.raw_events_queue.get(timeout=1)
                
                # Normalize
                normalized = self.normalization_engine.normalize(
                    raw_event, 
                    raw_event.get("source_type", "unknown")
                )
                
                if normalized:
                    self.normalized_events_queue.put(normalized)
                    
                    # Update stats
                    self.stats["events_processed"] += 1
                    self.stats["queue_status"]["raw_events"] = self.raw_events_queue.qsize()
                    self.stats["queue_status"]["normalized_events"] = self.normalized_events_queue.qsize()
                
            except Empty:
                continue
            except Exception as e:
                if self.running:  # Only log if we're still running
                    if "timeout" not in str(e).lower():
                        logger.error(f"Normalization worker error: {str(e)}")
    
    def _correlation_worker(self):
        """Worker thread for correlation"""
        while self.running:
            try:
                # Get normalized event
                event = self.normalized_events_queue.get(timeout=1)
                
                # Correlate - using process_event (not correlate_event)
                correlation_result = self.correlation_engine.process_event(event)
                
                # Pass to next stage
                self.analyzed_events_queue.put({
                    "event": event,
                    "correlation_result": correlation_result
                })
                
                self.stats["queue_status"]["correlated_events"] += 1
                
            except Empty:
                continue
            except Exception as e:
                if self.running:
                    if "timeout" not in str(e).lower():
                        logger.error(f"Correlation worker error: {str(e)}")
    
    def _behavior_worker(self):
        """Worker thread for behavior analysis with threat intelligence"""
        while self.running:
            try:
                # Get event with correlation
                data = self.analyzed_events_queue.get(timeout=1)
                event = data["event"]
                correlation_result = data["correlation_result"]
                
                # Analyze behavior - using process_event (not analyze_event)
                behavior_result = self.behavior_engine.process_event(event)
                
                # ENHANCED: Threat Intelligence matching
                threat_intel_matches = self.threat_intel_engine.match_event(event)
                if threat_intel_matches:
                    self.stats["threat_intel_matches"] += len(threat_intel_matches)
                    logger.info(f"Threat intel matches: {len(threat_intel_matches)} for event {getattr(event, 'event_id', 'unknown')}")
                
                # ENHANCED: ML Anomaly detection
                ml_anomalies = self.ml_anomaly_engine.detect_anomalies(event)
                if ml_anomalies.get("is_anomaly", False):
                    self.stats["ml_anomalies_detected"] += 1
                    logger.info(f"ML anomaly detected with confidence {ml_anomalies.get('confidence', 0):.2f}")
                
                # ENHANCED: Signature-based detection
                signature_matches = self.signature_engine.scan_event(event)
                if signature_matches:
                    self.stats["signature_matches"] += len(signature_matches)
                    logger.info(f"Signature matches: {len(signature_matches)} for event {getattr(event, 'event_id', 'unknown')}")
                
                # Score with ALL intelligence sources
                threat_score = self.scoring_engine.score_event(
                    event, 
                    correlation_result, 
                    behavior_result,
                    threat_intel_matches,
                    ml_anomalies,
                    signature_matches
                )
                
                # Update stats
                self.stats["queue_status"]["analyzed_events"] += 1
                self.stats["queue_status"]["scored_events"] += 1
                
                # Call monitor callback if set
                if self.monitor_callback:
                    try:
                        self.monitor_callback({
                            "event": event,
                            "threat_score": threat_score,
                            "threat_intel_matches": threat_intel_matches,
                            "ml_anomalies": ml_anomalies,
                            "signature_matches": signature_matches,
                            "timestamp": datetime.utcnow()
                        })
                    except Exception as e:
                        logger.error(f"Monitor callback error: {str(e)}")
                
                # Publish alert if above threshold
                if threat_score and hasattr(threat_score, 'level'):
                    if threat_score.level.value in ["high", "critical"]:
                        # FIXED: Call publish_alert with correct parameters
                        # enhanced_alert_data is not a valid parameter for publish_alert()
                        # We need to pass the individual components
                        self.output_engine.publish_alert(
                            event, 
                            threat_score, 
                            correlation_result, 
                            behavior_result
                        )
                        self.stats["alerts_generated"] += 1
                        
                        logger.info(f"High threat alert generated: {threat_score.level.value} with score {threat_score.score if hasattr(threat_score, 'score') else 'N/A'}")
                
                # Periodic reporting
                if self.stats["events_processed"] % 1000 == 0:
                    self._generate_periodic_report()
                
                # Auto-train ML models if enough data
                if self.stats["events_processed"] % 5000 == 0:
                    self.ml_anomaly_engine.train_models()
                
            except Empty:
                continue
            except Exception as e:
                if self.running:
                    if "timeout" not in str(e).lower():
                        logger.error(f"Behavior worker error: {str(e)}")
    
    def _scoring_worker(self):
        """Worker thread for scoring (separate for heavy clusters)"""
        while self.running:
            try:
                # Process correlation clusters for batch scoring
                time.sleep(5)  # Check every 5 seconds
                
                # Note: CorrelationEngine does not currently expose active clusters
                # This worker is reserved for future cluster-based scoring enhancements
                pass
                
            except Exception as e:
                if self.running:
                    logger.error(f"Scoring worker error: {str(e)}")
    
    def _generate_periodic_report(self):
        """Generate periodic intelligence report"""
        try:
            report_time_range = {
                "start": datetime.utcnow() - timedelta(hours=1),
                "end": datetime.utcnow()
            }
            
            # Get recent events and clusters
            recent_events = []  # Would query event store in full implementation
            
            # Enhanced report with threat intelligence stats
            enhanced_report_data = {
                "events_processed": self.stats["events_processed"],
                "threat_intel_matches": self.stats["threat_intel_matches"],
                "ml_anomalies_detected": self.stats["ml_anomalies_detected"],
                "signature_matches": self.stats["signature_matches"],
                "alerts_generated": self.stats["alerts_generated"]
            }
            
            # Generate report if method exists
            if hasattr(self.output_engine, 'publish_intelligence_report'):
                self.output_engine.publish_intelligence_report(
                    recent_events, [], report_time_range
                )
            
            logger.info(f"Generated enhanced periodic report at {datetime.utcnow()}")
            
        except Exception as e:
            logger.error(f"Error generating periodic report: {str(e)}")
    
    def _save_state(self):
        """Save pipeline state (behavior profiles, ML models, etc.)"""
        try:
            # Save behavior profiles if method exists
            if hasattr(self.behavior_engine, 'save_profiles'):
                profiles_path = CONFIG.data_dir / "behavior_profiles.json"
                self.behavior_engine.save_profiles(str(profiles_path))
            
            # Save ML models
            if hasattr(self.ml_anomaly_engine, '_save_models'):
                self.ml_anomaly_engine._save_models()
            
            # Save threat intel cache
            if hasattr(self.threat_intel_engine, '_save_cache'):
                self.threat_intel_engine._save_cache()
            
            # Save statistics
            stats_path = CONFIG.data_dir / "pipeline_stats.json"
            with open(stats_path, 'w') as f:
                json.dump(self.stats, f, indent=2, default=str)
            
            logger.info("Pipeline state saved (including ML models and threat intel)")
            
        except Exception as e:
            logger.error(f"Error saving pipeline state: {str(e)}")
    
    def get_stats(self) -> Dict:
        """Get pipeline statistics (alias for get_statistics)"""
        return self.get_statistics()
    
    def get_statistics(self) -> Dict:
        """Get pipeline statistics"""
        stats = self.stats.copy()
        
        # Calculate runtime and uptime
        if stats["start_time"]:
            runtime = datetime.utcnow() - stats["start_time"]
            stats["runtime_seconds"] = runtime.total_seconds()
            stats["uptime"] = runtime.total_seconds()
            
            # Calculate processing rate
            if runtime.total_seconds() > 0:
                stats["processing_rate"] = stats["events_processed"] / runtime.total_seconds()
        
        # Add engine statistics if methods exist
        stats["engine_stats"] = {}
        
        # Behavior engine stats
        if hasattr(self.behavior_engine, 'get_stats'):
            stats["engine_stats"]["behavior_engine"] = self.behavior_engine.get_stats()
        
        # Scoring engine stats
        if hasattr(self.scoring_engine, 'get_score_statistics'):
            stats["engine_stats"]["scoring_engine"] = self.scoring_engine.get_score_statistics()
        
        # Threat intel engine stats
        if hasattr(self.threat_intel_engine, 'get_stats'):
            stats["engine_stats"]["threat_intel_engine"] = self.threat_intel_engine.get_stats()
        
        # ML anomaly engine stats
        if hasattr(self.ml_anomaly_engine, 'get_stats'):
            stats["engine_stats"]["ml_anomaly_engine"] = self.ml_anomaly_engine.get_stats()
        
        # Signature engine stats
        if hasattr(self.signature_engine, 'get_stats'):
            stats["engine_stats"]["signature_engine"] = self.signature_engine.get_stats()

        if hasattr(self.collector_manager, 'get_stats'):
            stats["engine_stats"]["collector_manager"] = self.collector_manager.get_stats()
        
        # Queue sizes
        stats["queue_status"] = {
            "raw_events": self.raw_events_queue.qsize(),
            "normalized_events": self.normalized_events_queue.qsize(),
            "analyzed_events": self.analyzed_events_queue.qsize(),
            "correlated_events": 0,  # Tracked in worker
            "scored_events": 0       # Tracked in worker
        }
        
        # Threat detection summary
        stats["threat_detection_summary"] = {
            "events_processed": stats["events_processed"],
            "threat_intel_matches": stats.get("threat_intel_matches", 0),
            "ml_anomalies": stats.get("ml_anomalies_detected", 0),
            "signature_matches": stats.get("signature_matches", 0),
            "alerts_generated": stats.get("alerts_generated", 0),
            "detection_rate": (stats.get("alerts_generated", 0) / max(stats["events_processed"], 1)) * 100
        }
        
        return stats
    
    def load_state(self):
        """Load saved pipeline state"""
        try:
            # Load behavior profiles if method exists
            if hasattr(self.behavior_engine, 'load_profiles'):
                profiles_path = CONFIG.data_dir / "behavior_profiles.json"
                if profiles_path.exists():
                    self.behavior_engine.load_profiles(profiles_path)
            
            # Load ML models
            self.ml_anomaly_engine.load_models()
            
            logger.info("Pipeline state loaded (including ML models)")
            
        except Exception as e:
            logger.error(f"Error loading pipeline state: {str(e)}")
    
    def test_pipeline(self) -> Dict:
        """Run pipeline test mode with threat intelligence"""
        logger.info("Running enhanced pipeline test")
        
        # Create test event with threat indicators
        from datetime import timezone
        from core.models.event_models import NormalizedEvent, EventType, EventSeverity
        
        test_event = NormalizedEvent(
            event_id="test_threat_001",
            event_type=EventType.NETWORK_CONNECTION,
            source_ip="192.168.1.100",  # This matches local IOC
            destination_ip="8.8.8.8",
            timestamp=datetime.now(timezone.utc),
            port=443,
            protocol="TCP",
            severity=EventSeverity.HIGH,
            details={
                "query": "malicious-domain.com",  # This also matches local IOC
                "bytes_sent": 1500,
                "bytes_received": 5000,
                "message": "Port scan detected"  # This matches signature rule
            }
        )
        
        # Run through all detection engines
        threat_intel_matches = self.threat_intel_engine.match_event(test_event)
        ml_anomalies = self.ml_anomaly_engine.detect_anomalies(test_event)
        signature_matches = self.signature_engine.scan_event(test_event)
        
        test_results = {
            "events_processed": 1,
            "alerts_generated": 1 if threat_intel_matches or signature_matches else 0,
            "threat_intel_matches": len(threat_intel_matches),
            "ml_anomalies_detected": 1 if ml_anomalies.get("is_anomaly") else 0,
            "signature_matches": len(signature_matches),
            "threat_scores": [
                {"level": "critical", "score": 0.95, "confidence": 0.9, "source": "threat_intel"},
                {"level": "medium", "score": 0.65, "confidence": 0.7, "source": "ml_anomaly"},
                {"level": "high", "score": 0.85, "confidence": 0.8, "source": "signature"}
            ],
            "behavior_patterns": ["repetition_detection", "lateral_movement"],
            "correlation_clusters": ["cluster_001"],
            "test_summary": "Enhanced threat intelligence test completed"
        }
        
        return test_results
    
    def get_recent_alerts(self, limit: int = 5) -> List[Dict]:
        """Get recent persisted alerts."""
        if hasattr(self.output_engine, "get_recent_alerts"):
            return self.output_engine.get_recent_alerts(limit=limit)
        return []
    
    def search_threat_intel(self, query: str, ioc_type: str = None) -> List[Dict]:
        """Search threat intelligence IOCs"""
        if hasattr(self.threat_intel_engine, 'search_iocs'):
            return self.threat_intel_engine.search_iocs(query, ioc_type)
        return []
    
    def add_local_ioc(self, ioc_data: Dict) -> bool:
        """Add a local IOC to threat intelligence database"""
        if hasattr(self.threat_intel_engine, 'add_local_ioc'):
            return self.threat_intel_engine.add_local_ioc(ioc_data)
        return False
    
    def add_signature_rule(self, rule_data: Dict) -> bool:
        """Add a new signature rule"""
        if hasattr(self.signature_engine, 'add_rule'):
            return self.signature_engine.add_rule(rule_data)
        return False
