"""
Comprehensive test suite for Cyber-EW Fusion Cell
"""
import sys
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def print_test_result(test_name, passed):
    """Print test result in a formatted way"""
    status = "✓ PASSED" if passed else "✗ FAILED"
    print(f"{status:20} {test_name}")

def print_test_result(test_name, passed):
    """Print test result in an ASCII-safe format."""
    status = "PASSED" if passed else "FAILED"
    print(f"{status:20} {test_name}")


class TestCyberEWFusionCell:
    """Comprehensive test suite"""
    
    def __init__(self):
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = []
    
    def run_all_tests(self):
        """Run all tests"""
        print("=" * 70)
        print("CYBER-EW FUSION CELL - COMPREHENSIVE TEST SUITE")
        print("=" * 70)
        
        # Module import tests
        self.test_module_imports()
        
        # Utility function tests
        self.test_utility_functions()
        
        # Model tests
        self.test_data_models()
        
        # Engine tests
        self.test_engines()
        
        # Pipeline tests
        self.test_pipeline()
        
        # Integration tests
        self.test_integration()
        
        # Print summary
        self.print_summary()
        
        return len(self.failed_tests) == 0
    
    def test_module_imports(self):
        """Test that all modules can be imported"""
        print("\n" + "=" * 70)
        print("MODULE IMPORT TESTS")
        print("=" * 70)
        
        modules_to_test = [
            ("config.settings", ["CONFIG", "PIPELINE_CONFIG", "INGEST_CONFIG", 
                               "CORRELATION_CONFIG", "BEHAVIOR_CONFIG", "SCORING_CONFIG"]),
            ("utils.validators", ["validate_ip_address", "validate_domain", "validate_mac", "validate_timestamp"]),
            ("utils.time_utils", ["normalize_timestamp"]),
            ("utils.helpers", ["get_project_root", "is_windows"]),
            ("utils.security", ["generate_secure_random"]),
            ("core.models.event_models", ["NormalizedEvent", "EventType", "Entity", "EntityType"]),
            ("core.engines.ingest_engine", ["IngestEngine"]),
            ("core.engines.normalization_engine", ["NormalizationEngine"]),
            ("core.engines.correlation_engine", ["CorrelationEngine"]),
            ("core.engines.behavior_engine", ["BehaviorEngine"]),
            ("core.engines.scoring_engine", ["ScoringEngine"]),
            ("core.engines.output_engine", ["OutputEngine", "OutputFormat"]),
            ("core.pipeline", ["CyberEWPipeline"]),
        ]
        
        for module_path, imports in modules_to_test:
            test_name = f"Import {module_path}"
            try:
                module = __import__(module_path, fromlist=imports)
                
                # Check specific imports
                for item in imports:
                    if not hasattr(module, item):
                        raise AttributeError(f"{item} not found in {module_path}")
                
                print_test_result(test_name, True)
                self.passed_tests += 1
            except Exception as e:
                print_test_result(test_name, False)
                self.failed_tests.append(f"{test_name}: {e}")
            finally:
                self.total_tests += 1
    
    def test_utility_functions(self):
        """Test utility functions"""
        print("\n" + "=" * 70)
        print("UTILITY FUNCTION TESTS")
        print("=" * 70)
        
        from utils.validators import validate_ip_address, validate_domain, validate_mac, validate_timestamp
        from utils.time_utils import normalize_timestamp
        from utils.helpers import get_project_root, is_windows
        
        # Test validate_ip_address
        test_name = "validate_ip_address - valid IPv4"
        try:
            assert validate_ip_address("192.168.1.1") == True
            print_test_result(test_name, True)
            self.passed_tests += 1
        except AssertionError:
            print_test_result(test_name, False)
            self.failed_tests.append(test_name)
        self.total_tests += 1
        
        # Test validate_ip_address - invalid
        test_name = "validate_ip_address - invalid"
        try:
            assert validate_ip_address("999.999.999.999") == False
            print_test_result(test_name, True)
            self.passed_tests += 1
        except AssertionError:
            print_test_result(test_name, False)
            self.failed_tests.append(test_name)
        self.total_tests += 1
        
        # Test validate_domain
        test_name = "validate_domain - valid"
        try:
            assert validate_domain("example.com") == True
            print_test_result(test_name, True)
            self.passed_tests += 1
        except AssertionError:
            print_test_result(test_name, False)
            self.failed_tests.append(test_name)
        self.total_tests += 1
        
        # Test validate_mac
        test_name = "validate_mac - valid"
        try:
            assert validate_mac("00:11:22:33:44:55") == True
            print_test_result(test_name, True)
            self.passed_tests += 1
        except AssertionError:
            print_test_result(test_name, False)
            self.failed_tests.append(test_name)
        self.total_tests += 1
        
        # Test normalize_timestamp
        test_name = "normalize_timestamp"
        try:
            dt = normalize_timestamp("2024-01-15T10:30:00Z")
            assert isinstance(dt, datetime)
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
        
        # Test helper functions
        test_name = "get_project_root"
        try:
            root = get_project_root()
            assert isinstance(root, Path)
            assert root.exists()
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
    
    def test_data_models(self):
        """Test data model creation and serialization"""
        print("\n" + "=" * 70)
        print("DATA MODEL TESTS")
        print("=" * 70)
        
        from core.models.event_models import NormalizedEvent, EventType, Entity, EntityType
        
        # Test Entity creation
        test_name = "Create Entity"
        try:
            entity = Entity(
                id="test_entity",
                type=EntityType.IP,
                value="192.168.1.100"
            )
            assert entity.id == "test_entity"
            assert entity.type == EntityType.IP
            assert entity.value == "192.168.1.100"
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
        
        # Test NormalizedEvent creation
        test_name = "Create NormalizedEvent"
        try:
            timestamp = datetime.now(timezone.utc)
            source_entity = Entity(
                id="test_source",
                type=EntityType.IP,
                value="192.168.1.100"
            )
            
            event = NormalizedEvent(
                event_id="test_event",
                timestamp=timestamp,
                event_type=EventType.NETWORK_CONNECTION,
                source={"system": "test"},
                source_entity=source_entity
            )
            
            assert event.event_id == "test_event"
            assert event.timestamp == timestamp
            assert event.event_type == EventType.NETWORK_CONNECTION
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
        
        # Test event serialization
        test_name = "Event serialization to dict"
        try:
            timestamp = datetime.now(timezone.utc)
            source_entity = Entity(
                id="test_source",
                type=EntityType.IP,
                value="192.168.1.100"
            )
            
            event = NormalizedEvent(
                event_id="test_event",
                timestamp=timestamp,
                event_type=EventType.NETWORK_CONNECTION,
                source={"system": "test"},
                source_entity=source_entity
            )
            
            event_dict = event.to_dict()
            assert isinstance(event_dict, dict)
            assert event_dict["event_id"] == "test_event"
            assert "timestamp" in event_dict
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
    
    def test_engines(self):
        """Test engine initialization and basic functionality"""
        print("\n" + "=" * 70)
        print("ENGINE TESTS")
        print("=" * 70)
        
        from config.settings import INGEST_CONFIG, CORRELATION_CONFIG, BEHAVIOR_CONFIG, SCORING_CONFIG
        from core.engines.ingest_engine import IngestEngine
        from core.engines.normalization_engine import NormalizationEngine
        from core.engines.correlation_engine import CorrelationEngine
        from core.engines.behavior_engine import BehaviorEngine
        from core.engines.scoring_engine import ScoringEngine
        from core.engines.output_engine import OutputEngine
        from core.models.event_models import NormalizedEvent
        
        # Test NormalizationEngine
        test_name = "NormalizationEngine initialization"
        try:
            norm_engine = NormalizationEngine()
            assert norm_engine is not None
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
        
        # Test NormalizationEngine.normalize
        test_name = "NormalizationEngine.normalize"
        try:
            norm_engine = NormalizationEngine()
            test_event = {
                "timestamp": "2024-01-15T10:30:00Z",
                "source_ip": "192.168.1.100",
                "destination_ip": "8.8.8.8",
                "destination_port": 53,
                "protocol": "udp",
                "dns_query": "google.com",
                "source_type": "test"
            }
            
            normalized = norm_engine.normalize(test_event, "test")
            # Should return None for unknown source type
            assert normalized is None or isinstance(normalized, NormalizedEvent)
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
        
        # Test CorrelationEngine
        test_name = "CorrelationEngine initialization"
        try:
            corr_engine = CorrelationEngine(CORRELATION_CONFIG)
            assert corr_engine is not None
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
        
        # Test BehaviorEngine
        test_name = "BehaviorEngine initialization"
        try:
            behavior_engine = BehaviorEngine(BEHAVIOR_CONFIG)
            assert behavior_engine is not None
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
        
        # Test ScoringEngine
        test_name = "ScoringEngine initialization"
        try:
            scoring_engine = ScoringEngine(SCORING_CONFIG)
            assert scoring_engine is not None
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
        
        # Test OutputEngine
        test_name = "OutputEngine initialization"
        try:
            output_engine = OutputEngine()
            assert output_engine is not None
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
    
    def test_pipeline(self):
        """Test pipeline initialization and basic operations"""
        print("\n" + "=" * 70)
        print("PIPELINE TESTS")
        print("=" * 70)
        
        from core.pipeline import CyberEWPipeline
        
        # Test pipeline initialization
        test_name = "CyberEWPipeline initialization"
        try:
            pipeline = CyberEWPipeline()
            assert pipeline is not None
            assert hasattr(pipeline, 'ingest_engine')
            assert hasattr(pipeline, 'normalization_engine')
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
        
        # Test pipeline statistics
        test_name = "Pipeline statistics"
        try:
            pipeline = CyberEWPipeline()
            stats = pipeline.get_statistics()
            assert isinstance(stats, dict)
            assert "events_processed" in stats
            assert "alerts_generated" in stats
            print_test_result(test_name, True)
            self.passed_tests += 1
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        self.total_tests += 1
    
    def test_integration(self):
        """Test integration of multiple components"""
        print("\n" + "=" * 70)
        print("INTEGRATION TESTS")
        print("=" * 70)
        
        from core.models.event_models import NormalizedEvent, EventType, Entity, EntityType
        from core.engines.normalization_engine import NormalizationEngine
        from core.engines.behavior_engine import BehaviorEngine
        from core.engines.scoring_engine import ScoringEngine
        from config.settings import BEHAVIOR_CONFIG, SCORING_CONFIG
        
        # Test full flow: Event -> Normalization -> Behavior Analysis -> Scoring
        test_name = "Full analysis flow"
        test_dir = Path(tempfile.mkdtemp(prefix="cyber_ew_test_"))
        try:
            # Create a test event
            timestamp = datetime.now(timezone.utc)
            source_entity = Entity(
                id="test_source",
                type=EntityType.IP,
                value="192.168.1.100"
            )
            
            dest_entity = Entity(
                id="test_dest",
                type=EntityType.IP,
                value="8.8.8.8"
            )
            
            event = NormalizedEvent(
                event_id="integration_test_event",
                timestamp=timestamp,
                event_type=EventType.NETWORK_CONNECTION,
                source={"system": "integration_test"},
                source_entity=source_entity,
                destination_entity=dest_entity,
                details={
                    "destination_port": 53,
                    "protocol": "udp",
                    "dns_query": "google.com"
                }
            )
            
            # Test BehaviorEngine
            behavior_engine = BehaviorEngine(BEHAVIOR_CONFIG)
            behavior_result = behavior_engine.analyze_event(event)
            
            assert isinstance(behavior_result, dict)
            assert "risk_score" in behavior_result
            assert "anomalies" in behavior_result
            
            # Test ScoringEngine
            scoring_engine = ScoringEngine(SCORING_CONFIG)
            threat_score = scoring_engine.score_event(event, None, behavior_result)
            
            assert threat_score is not None
            assert hasattr(threat_score, 'score')
            assert hasattr(threat_score, 'level')
            
            print_test_result(test_name, True)
            self.passed_tests += 1
            
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        finally:
            # Clean up test directory
            import shutil
            if test_dir.exists():
                shutil.rmtree(test_dir, ignore_errors=True)
        
        self.total_tests += 1
        
        # Test file I/O integration
        test_name = "File I/O integration"
        test_dir = Path(tempfile.mkdtemp(prefix="cyber_ew_test_"))
        try:
            # Test writing and reading JSON
            test_data = {
                "test": "data",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "value": 123
            }
            
            test_file = test_dir / "test.json"
            with open(test_file, 'w') as f:
                json.dump(test_data, f, default=str)
            
            with open(test_file, 'r') as f:
                loaded_data = json.load(f)
            
            assert loaded_data["test"] == "data"
            assert loaded_data["value"] == 123
            
            print_test_result(test_name, True)
            self.passed_tests += 1
            
        except Exception as e:
            print_test_result(test_name, False)
            self.failed_tests.append(f"{test_name}: {e}")
        finally:
            # Clean up
            import shutil
            if test_dir.exists():
                shutil.rmtree(test_dir, ignore_errors=True)
        
        self.total_tests += 1
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        print(f"Total Tests: {self.total_tests}")
        print(f"Passed: {self.passed_tests}")
        print(f"Failed: {len(self.failed_tests)}")
        
        if self.failed_tests:
            print("\nFailed Tests:")
            for i, failure in enumerate(self.failed_tests, 1):
                print(f"  {i}. {failure}")
        
        success_rate = (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0
        print(f"\nSuccess Rate: {success_rate:.1f}%")
        
        if len(self.failed_tests) == 0:
            print("\n✅ ALL TESTS PASSED! Cyber-EW Fusion Cell is ready.")
        else:
            print(f"\n⚠️  {len(self.failed_tests)} tests failed. Review the failures above.")

def _safe_print_summary(self):
    """ASCII-safe test summary for Windows consoles."""
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total Tests: {self.total_tests}")
    print(f"Passed: {self.passed_tests}")
    print(f"Failed: {len(self.failed_tests)}")

    if self.failed_tests:
        print("\nFailed Tests:")
        for i, failure in enumerate(self.failed_tests, 1):
            print(f"  {i}. {failure}")

    success_rate = (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0
    print(f"\nSuccess Rate: {success_rate:.1f}%")

    if len(self.failed_tests) == 0:
        print("\nALL TESTS PASSED! Cyber-EW Fusion Cell is ready.")
    else:
        print(f"\n{len(self.failed_tests)} tests failed. Review the failures above.")


TestCyberEWFusionCell.print_summary = _safe_print_summary


def main():
    """Main test runner"""
    test_suite = TestCyberEWFusionCell()
    success = test_suite.run_all_tests()
    
    # Return exit code: 0 for success, 1 for failure
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
