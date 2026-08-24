"""
Machine Learning Anomaly Detection Engine
"""
import math
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    import joblib
    ML_AVAILABLE = True
except Exception as exc:
    np = None
    pd = None
    IsolationForest = None
    StandardScaler = None
    DBSCAN = None
    joblib = None
    ML_AVAILABLE = False
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
from pathlib import Path
import threading

from config.settings import CONFIG

logger = logging.getLogger(__name__)

class MLAnomalyEngine:
    """Machine Learning based anomaly detection"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.models = {}
        self.scalers = {}
        self.feature_history = []
        self.max_history = self.config.get("max_history", 10000)
        self.is_training = False
        self.models_trained = False
        self.training_lock = threading.Lock()
        self._model_readiness_warning_logged = False
        
        # Statistics
        self.stats = {
            "events_processed": 0,
            "anomalies_detected": 0,
            "last_training": None,
            "model_accuracy": 0.0
        }
        
        # Initialize models
        self._init_models()
        
        logger.info("ML Anomaly Engine initialized")
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict:
        """Load ML configuration"""
        default_config = {
            "models": {
                "isolation_forest": {
                    "enabled": True,
                    "contamination": 0.1,
                    "n_estimators": 100,
                    "random_state": 42
                },
                "dbscan": {
                    "enabled": False,
                    "eps": 0.5,
                    "min_samples": 5
                }
            },
            "training_interval": 3600,  # 1 hour
            "retraining_threshold": 1000,
            "feature_weights": {
                "source_ip_frequency": 1.0,
                "destination_port_variety": 1.0,
                "protocol_entropy": 1.0,
                "bytes_transferred": 0.5,
                "time_of_day": 0.3,
                "day_of_week": 0.2
            },
            "anomaly_threshold": 0.7
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.error(f"Error loading ML config: {str(e)}")
        
        return default_config
    
    def _init_models(self):
        """Initialize ML models"""
        if not ML_AVAILABLE:
            logger.warning("ML dependencies unavailable. Using heuristic anomaly detection only.")
            return

        if self.config["models"]["isolation_forest"]["enabled"]:
            model_config = self.config["models"]["isolation_forest"]
            self.models["isolation_forest"] = IsolationForest(
                contamination=model_config["contamination"],
                n_estimators=model_config["n_estimators"],
                random_state=model_config["random_state"]
            )
        
        if self.config["models"]["dbscan"]["enabled"]:
            model_config = self.config["models"]["dbscan"]
            self.models["dbscan"] = DBSCAN(
                eps=model_config["eps"],
                min_samples=model_config["min_samples"]
            )
        
        # Initialize scaler
        self.scalers["standard"] = StandardScaler()
        
        logger.info(f"Initialized {len(self.models)} ML models")
    
    def extract_features(self, event: Any) -> Dict[str, float]:
        """Extract features from event for ML analysis"""
        features = {}
        
        try:
            # Get event data
            if hasattr(event, '__dict__'):
                event_dict = event.__dict__
            elif isinstance(event, dict):
                event_dict = event
            else:
                return features
            
            # 1. Source IP frequency (normalized)
            source_ip = str(event_dict.get('source_ip', 'unknown'))
            features['source_ip_hash'] = float(hash(source_ip) % 1000) / 1000.0
            
            # 2. Destination port variety
            port = event_dict.get('port') or event_dict.get('destination_port')
            if port:
                features['destination_port'] = float(port) / 65535.0
            else:
                features['destination_port'] = 0.0
            
            # 3. Protocol entropy
            protocol = str(event_dict.get('protocol', 'unknown')).lower()
            protocol_map = {'tcp': 0.3, 'udp': 0.6, 'icmp': 0.9, 'unknown': 0.0}
            features['protocol'] = protocol_map.get(protocol, 0.0)
            
            # 4. Bytes transferred (normalized)
            bytes_sent = event_dict.get('bytes_sent', 0) or 0
            bytes_received = event_dict.get('bytes_received', 0) or 0
            total_bytes = bytes_sent + bytes_received
            features['bytes_transferred'] = min(total_bytes / 1000000.0, 1.0)  # Cap at 1MB
            
            # 5. Time of day (cyclical encoding)
            timestamp = event_dict.get('timestamp')
            if isinstance(timestamp, datetime):
                hour = timestamp.hour
                minute = timestamp.minute
                # Convert to radians for cyclical encoding
                time_rad = 2 * math.pi * (hour * 60 + minute) / (24 * 60)
                features['time_sin'] = math.sin(time_rad)
                features['time_cos'] = math.cos(time_rad)
            else:
                features['time_sin'] = 0.0
                features['time_cos'] = 0.0
            
            # 6. Day of week
            if isinstance(timestamp, datetime):
                features['day_of_week'] = timestamp.weekday() / 6.0  # 0=Monday, 6=Sunday
            else:
                features['day_of_week'] = 0.0
            
            # 7. Event type encoding
            event_type = str(event_dict.get('event_type', 'unknown')).lower()
            type_map = {
                'authentication': 0.1,
                'network_connection': 0.2,
                'dns_query': 0.3,
                'http_request': 0.4,
                'file_access': 0.5,
                'process_execution': 0.6,
                'system_log': 0.7,
                'threat_intel': 0.8,
                'unknown': 0.9
            }
            features['event_type'] = type_map.get(event_type, 0.9)
            
            # 8. Severity encoding
            severity = str(event_dict.get('severity', 'info')).lower()
            severity_map = {
                'critical': 0.9,
                'high': 0.7,
                'medium': 0.5,
                'low': 0.3,
                'info': 0.1
            }
            features['severity'] = severity_map.get(severity, 0.1)
            
            # Apply feature weights
            weights = self.config.get("feature_weights", {})
            for feature_name in features:
                weight = weights.get(feature_name, 1.0)
                features[feature_name] *= weight
            
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
            features = {}
        
        return features
    
    def detect_anomalies(self, event: Any) -> Dict:
        """
        Detect anomalies in event using ML models
        
        Returns:
            Dict with anomaly scores and detection results
        """
        self.stats["events_processed"] += 1
        
        # Extract features
        features = self.extract_features(event)
        
        if not features:
            return {
                "is_anomaly": False,
                "confidence": 0.0,
                "scores": {},
                "reason": "No features extracted"
            }
        
        if not ML_AVAILABLE:
            # Heuristic-only mode must never advertise trained models (contract:
            # models_trained implies fitted sklearn models are in use).
            self.models_trained = False
            self.feature_history.append(list(features.values()))
            if len(self.feature_history) > self.max_history:
                self.feature_history.pop(0)
            return self._heuristic_anomaly_detection(features, event)

        # Convert features to numpy array
        feature_values = np.array(list(features.values())).reshape(1, -1)
        
        # Scale features
        if hasattr(self.scalers["standard"], 'n_features_in_'):
            feature_values_scaled = self.scalers["standard"].transform(feature_values)
        else:
            feature_values_scaled = feature_values
        
        # Store in history
        self.feature_history.append(feature_values_scaled.flatten())
        if len(self.feature_history) > self.max_history:
            self.feature_history.pop(0)
        
        # Auto-train if enough data
        if len(self.feature_history) >= self.config.get("retraining_threshold", 1000) \
           and not self.models_trained:
            self.train_models()
        
        if self.models_trained and not self._models_ready():
            self.models_trained = False
            if not self._model_readiness_warning_logged:
                logger.warning("ML model files are present but not fitted; using heuristic anomaly detection until retraining completes")
                self._model_readiness_warning_logged = True

        # Predict anomalies
        anomaly_results = {"is_anomaly": False, "confidence": 0.0, "scores": {}}
        
        if self.models_trained:
            for model_name, model in self.models.items():
                try:
                    if model_name == "isolation_forest":
                        # Isolation Forest returns -1 for anomalies, 1 for normal
                        prediction = model.predict(feature_values_scaled)
                        score = model.score_samples(feature_values_scaled)
                        
                        # Convert to anomaly score (0=normal, 1=anomaly)
                        anomaly_score = 1.0 if prediction[0] == -1 else 0.0
                        confidence = abs(score[0])  # Higher abs score = more confident
                        
                        anomaly_results["scores"][model_name] = {
                            "score": float(anomaly_score),
                            "confidence": float(confidence),
                            "prediction": int(prediction[0])
                        }
                        
                        # Update overall anomaly detection
                        if anomaly_score > self.config.get("anomaly_threshold", 0.7):
                            anomaly_results["is_anomaly"] = True
                            anomaly_results["confidence"] = max(
                                anomaly_results["confidence"],
                                confidence
                            )
                            self.stats["anomalies_detected"] += 1
                    
                    elif model_name == "dbscan":
                        # DBSCAN clustering for anomaly detection
                        prediction = model.fit_predict(feature_values_scaled)
                        
                        # -1 indicates outlier in DBSCAN
                        anomaly_score = 1.0 if prediction[0] == -1 else 0.0
                        
                        anomaly_results["scores"][model_name] = {
                            "score": float(anomaly_score),
                            "prediction": int(prediction[0]),
                            "cluster_size": len([p for p in prediction if p == prediction[0]])
                        }
                        
                        if anomaly_score > 0.5:
                            anomaly_results["is_anomaly"] = True
                            anomaly_results["confidence"] = 0.8
                
                except Exception as e:
                    logger.debug(f"Error in model {model_name}: {str(e)}")
        
        # Add feature-based heuristics if ML models not trained
        if not self.models_trained:
            anomaly_results = self._heuristic_anomaly_detection(features, event)
        
        return anomaly_results
    
    def _heuristic_anomaly_detection(self, features: Dict, event: Any) -> Dict:
        """Fallback heuristic anomaly detection when ML models not available"""
        anomaly_score = 0.0
        reasons = []
        
        # Check for unusual ports
        if 0.8 < features.get('destination_port', 0.0) < 0.9:  # High ports
            anomaly_score += 0.3
            reasons.append("Unusual port usage")
        
        # Check for unusual protocols
        if features.get('protocol', 0.0) > 0.8:  # Rare protocols
            anomaly_score += 0.2
            reasons.append("Rare protocol")
        
        # Check for large data transfers
        if features.get('bytes_transferred', 0.0) > 0.8:  # Large transfer
            anomaly_score += 0.4
            reasons.append("Large data transfer")
        
        # Check for unusual time (e.g., 2-5 AM)
        time_sin = features.get('time_sin', 0.0)
        time_cos = features.get('time_cos', 0.0)
        if time_sin < -0.5:  # Roughly 2-5 AM
            anomaly_score += 0.3
            reasons.append("Unusual time of day")
        
        # Check severity
        if features.get('severity', 0.0) > 0.7:  # High/Critical severity
            anomaly_score += 0.5
            reasons.append("High severity event")
        
        is_anomaly = anomaly_score > self.config.get("anomaly_threshold", 0.7)
        
        if is_anomaly:
            self.stats["anomalies_detected"] += 1
        
        return {
            "is_anomaly": is_anomaly,
            "confidence": min(anomaly_score, 1.0),
            "scores": {"heuristic": {"score": anomaly_score}},
            "reasons": reasons,
            "feature_values": features
        }
    
    def train_models(self):
        """Train ML models on collected features"""
        if not ML_AVAILABLE:
            logger.warning("Skipping ML training because ML dependencies are unavailable")
            return

        with self.training_lock:
            if self.is_training or len(self.feature_history) < 100:
                return
            
            self.is_training = True
            
            try:
                logger.info(f"Training ML models on {len(self.feature_history)} samples")
                
                # Convert history to numpy array
                X = np.array(self.feature_history)
                
                # Scale features
                self.scalers["standard"].fit(X)
                X_scaled = self.scalers["standard"].transform(X)
                
                # Train each model
                for model_name, model in self.models.items():
                    if model_name == "isolation_forest":
                        model.fit(X_scaled)
                        logger.info(f"Trained Isolation Forest on {len(X)} samples")
                    
                    elif model_name == "dbscan":
                        # DBSCAN doesn't need training, just fitting
                        model.fit(X_scaled)
                        n_clusters = len(set(model.labels_)) - (1 if -1 in model.labels_ else 0)
                        logger.info(f"DBSCAN found {n_clusters} clusters with {sum(model.labels_ == -1)} outliers")
                
                self.models_trained = True
                self.stats["last_training"] = datetime.utcnow()
                self.stats["model_accuracy"] = 0.85  # Placeholder, would calculate from test data
                
                # Save models
                self._save_models()
                
                logger.info("ML models trained and saved")
                
            except Exception as e:
                logger.error(f"Error training ML models: {str(e)}")
            
            finally:
                self.is_training = False
    
    def _save_models(self):
        """Save trained models to disk"""
        if not ML_AVAILABLE:
            return

        try:
            models_dir = CONFIG.data_dir / "ml_models"
            models_dir.mkdir(parents=True, exist_ok=True)
            
            for model_name, model in self.models.items():
                model_path = models_dir / f"{model_name}.joblib"
                joblib.dump(model, model_path)
            
            scaler_path = models_dir / "scaler.joblib"
            joblib.dump(self.scalers["standard"], scaler_path)
            
            logger.info(f"Saved models to {models_dir}")
            
        except Exception as e:
            logger.error(f"Error saving models: {str(e)}")

    def _model_is_fitted(self, model_name: str, model: Any) -> bool:
        """Best-effort fitted-state check for supported sklearn models."""
        if model_name == "isolation_forest":
            return all(hasattr(model, attr) for attr in ("estimators_", "offset_", "n_features_in_"))
        if model_name == "dbscan":
            return hasattr(model, "labels_")
        return True

    def _models_ready(self) -> bool:
        if not self.models:
            return False
        if not all(self._model_is_fitted(name, model) for name, model in self.models.items()):
            return False
        return hasattr(self.scalers.get("standard"), "n_features_in_")
    
    def load_models(self):
        """Load trained models from disk"""
        if not ML_AVAILABLE:
            self.models_trained = False
            logger.warning("Skipping model load because ML dependencies are unavailable")
            return

        try:
            models_dir = CONFIG.data_dir / "ml_models"
            
            loaded_models = 0
            for model_name in list(self.models.keys()):
                model_path = models_dir / f"{model_name}.joblib"
                if model_path.exists():
                    self.models[model_name] = joblib.load(model_path)
                    loaded_models += 1
            
            scaler_path = models_dir / "scaler.joblib"
            if scaler_path.exists():
                self.scalers["standard"] = joblib.load(scaler_path)
            
            self.models_trained = loaded_models > 0 and self._models_ready()
            if self.models_trained:
                logger.info("Loaded trained ML models")
            else:
                logger.warning("No fitted ML models loaded; using heuristic anomaly detection until enough data is collected")
            
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            self.models_trained = False
    
    def get_stats(self) -> Dict:
        """Get engine statistics"""
        stats = self.stats.copy()
        stats["feature_history_size"] = len(self.feature_history)
        stats["models_trained"] = self.models_trained
        stats["active_models"] = list(self.models.keys())
        stats["ml_available"] = ML_AVAILABLE
        return stats
    
    def export_training_data(self, filepath: Optional[str] = None):
        """Export feature history for analysis"""
        if not filepath:
            filepath = str(CONFIG.data_dir / "ml_models" / f"training_data_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv")
        
        try:
            sample_count = len(self.feature_history)
            if ML_AVAILABLE:
                df = pd.DataFrame(self.feature_history)
                df.to_csv(filepath, index=False)
            else:
                import csv
                with open(filepath, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerows(self.feature_history)
            logger.info(f"Exported {sample_count} samples to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error exporting training data: {str(e)}")
            return None
