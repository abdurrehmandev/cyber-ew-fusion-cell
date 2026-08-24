"""
Scoring Engine for Cyber-EW Fusion Cell
Calculates threat scores based on multiple intelligence sources
"""
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from utils.time_utils import datetime_now_utc, ensure_utc

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatScore:
    """Threat score with level and confidence"""
    score: float  # 0.0 to 1.0
    level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    sources: Optional[List[str]] = None
    details: Optional[Dict] = None
    
    def __post_init__(self):
        if self.sources is None:
            self.sources = []
        if self.details is None:
            self.details = {}

class ScoringEngine:
    """
    Enhanced Scoring Engine
    Aggregates scores from multiple detection sources:
    1. Threat Intelligence feeds
    2. Machine Learning anomaly detection
    3. Signature-based detection
    4. Behavior analysis
    5. Correlation clustering
    """
    
    def __init__(self, config: Any = None):
        self.config = config
        self.score_history = []
        self.max_history = 10000
        
        # Default weights if not provided in config
        self.weights = {
            "threat_intelligence": 0.25,  # Highest weight - known bad indicators
            "signature_detection": 0.20,   # High weight - known attack patterns
            "ml_anomaly": 0.20,           # High weight - statistical anomalies
            "event_severity": 0.15,        # Medium weight - event intrinsic severity
            "behavior_analysis": 0.10,     # Medium weight - behavioral patterns
            "correlation": 0.05,           # Low weight - event clustering
            "recency": 0.05               # Low weight - recent events
        }
        
        # Override with config if provided
        if config and hasattr(config, 'weights'):
            self.weights.update(config.weights)
        
        # Threat level thresholds
        self.thresholds = {
            ThreatLevel.CRITICAL: 0.85,
            ThreatLevel.HIGH: 0.70,
            ThreatLevel.MEDIUM: 0.50,
            ThreatLevel.LOW: 0.30,
            ThreatLevel.INFO: 0.00
        }
        
        # Statistics
        self.stats = {
            "scores_calculated": 0,
            "high_risk_scores": 0,
            "average_score": 0.0,
            "score_distribution": {level.value: 0 for level in ThreatLevel}
        }
        
        logger.info(f"Scoring Engine initialized with weights: {self.weights}")
    
    def score_event(self, event: Any, 
                   correlation_result: Optional[Any] = None,
                   behavior_result: Optional[Any] = None,
                   threat_intel_matches: Optional[List[Dict]] = None,
                   ml_anomalies: Optional[Dict] = None,
                   signature_matches: Optional[List[Dict]] = None) -> ThreatScore:
        """
        Calculate comprehensive threat score for an event
        
        Args:
            event: NormalizedEvent or dict
            correlation_result: Correlation engine results
            behavior_result: Behavior analysis results
            threat_intel_matches: Threat intelligence matches
            ml_anomalies: ML anomaly detection results
            signature_matches: Signature-based detection matches
            
        Returns:
            ThreatScore object with overall assessment
        """
        # Initialize component scores
        component_scores = {}
        sources = []
        details = {}
        
        # 1. Threat Intelligence Score (HIGHEST PRIORITY)
        ti_score = self._calculate_threat_intel_score(threat_intel_matches)
        if ti_score > 0:
            component_scores["threat_intelligence"] = ti_score
            sources.append("threat_intel")
            details["threat_intel_matches"] = len(threat_intel_matches or [])
            details["threat_intel_score"] = ti_score
        
        # 2. Signature-Based Detection Score
        sig_score = self._calculate_signature_score(signature_matches)
        if sig_score > 0:
            component_scores["signature_detection"] = sig_score
            sources.append("signature")
            details["signature_matches"] = len(signature_matches or [])
            details["signature_score"] = sig_score
        
        # 3. ML Anomaly Detection Score
        ml_score = self._calculate_ml_anomaly_score(ml_anomalies)
        if ml_score > 0:
            component_scores["ml_anomaly"] = ml_score
            sources.append("ml_anomaly")
            details["ml_anomaly"] = ml_anomalies
            details["ml_score"] = ml_score
        
        # 4. Event Severity Score
        severity_score = self._calculate_event_severity(event)
        component_scores["event_severity"] = severity_score
        details["event_severity"] = severity_score
        
        # 5. Behavior Analysis Score
        behavior_score = self._calculate_behavior_score(behavior_result)
        if behavior_score > 0:
            component_scores["behavior_analysis"] = behavior_score
            sources.append("behavior")
            details["behavior_score"] = behavior_score
        
        # 6. Correlation Score
        correlation_score = self._calculate_correlation_score(correlation_result)
        if correlation_score > 0:
            component_scores["correlation"] = correlation_score
            sources.append("correlation")
            details["correlation_score"] = correlation_score
        
        # 7. Recency Score (penalize old events)
        recency_score = self._calculate_recency_score(event)
        component_scores["recency"] = recency_score
        
        # Calculate weighted sum
        weighted_sum = 0.0
        total_weight = 0.0
        
        for component, score in component_scores.items():
            weight = self.weights.get(component, 0.0)
            weighted_sum += score * weight
            total_weight += weight
        
        # Normalize to 0-1 range
        if total_weight > 0:
            final_score = weighted_sum / total_weight
        else:
            final_score = 0.0
        
        # Apply boosting for multiple detection sources
        source_multiplier = 1.0 + (0.1 * len(sources))  # 10% boost per source
        final_score = min(1.0, final_score * source_multiplier)
        
        # Determine threat level
        threat_level = self._determine_threat_level(final_score)
        
        # Calculate confidence based on sources and consistency
        confidence = self._calculate_confidence(component_scores, sources)
        
        # Update statistics
        self._update_stats(final_score, threat_level)
        
        # Create threat score object
        threat_score = ThreatScore(
            score=final_score,
            level=threat_level,
            confidence=confidence,
            sources=sources,
            details=details
        )
        
        # Store in history
        self._store_score(threat_score)
        
        logger.debug(f"Calculated threat score: {final_score:.3f} ({threat_level.value}) "
                    f"from {len(sources)} sources")
        
        return threat_score
    
    def _calculate_threat_intel_score(self, matches: Optional[List[Dict]]) -> float:
        """Calculate score from threat intelligence matches"""
        if not matches:
            return 0.0
        
        score = 0.0
        for match in matches:
            # Base score from match
            match_score = match.get("match_score", 0.5)
            
            # Boost based on IOC confidence
            ioc_confidence = match.get("ioc", {}).get("confidence", 0.5)
            
            # Boost for high severity threat types
            threat_type = match.get("ioc", {}).get("threat_type", "").lower()
            if any(ht in threat_type for ht in ["c2", "botnet", "ransomware", "apt"]):
                match_score += 0.2
            
            score = max(score, match_score)
        
        return min(1.0, score)
    
    
    def _calculate_signature_score(self, matches: Optional[List[Dict]]) -> float:
        """Calculate score from signature matches"""
        if not matches:
            return 0.0
        
        score = 0.0
        for match in matches:
            # Map severity to score
            severity_map = {
                "critical": 1.0,
                "high": 0.8,
                "medium": 0.6,
                "low": 0.4
            }
            
            match_score = severity_map.get(match.get("severity", "medium"), 0.5)
            
            # Boost for multiple conditions matched
            match_details = match.get("match_details", [])
            if len(match_details) > 1:
                match_score += 0.1
            
            score = max(score, match_score)
        
        return min(1.0, score)
    
    def _calculate_ml_anomaly_score(self, anomalies: Optional[Dict]) -> float:
        """Calculate score from ML anomaly detection"""
        if not anomalies or not anomalies.get("is_anomaly", False):
            return 0.0
        
        # Base score from confidence
        confidence = anomalies.get("confidence", 0.5)
        
        # Check for high anomaly scores
        scores = anomalies.get("scores", {})
        max_anomaly_score = 0.0
        
        for model_score in scores.values():
            if isinstance(model_score, dict):
                anomaly_score = model_score.get("score", 0.0)
                max_anomaly_score = max(max_anomaly_score, anomaly_score)
        
        # Use the higher of confidence or anomaly score
        return max(confidence, max_anomaly_score)
    
    def _calculate_event_severity(self, event: Any) -> float:
        """Calculate score from event severity"""
        if hasattr(event, 'severity'):
            severity = event.severity
            if hasattr(severity, 'value'):
                severity = severity.value
            
            severity_map = {
                "critical": 0.9,
                "high": 0.7,
                "medium": 0.5,
                "low": 0.3,
                "info": 0.1
            }
            
            return severity_map.get(str(severity).lower(), 0.1)
        
        return 0.1
    
    def _calculate_behavior_score(self, behavior_result: Optional[Any]) -> float:
        """Calculate score from behavior analysis"""
        if not behavior_result:
            return 0.0
        
        if isinstance(behavior_result, list):
            confidences = [
                float(getattr(pattern, "confidence", 0.0))
                for pattern in behavior_result
            ]
            severities = [
                getattr(getattr(pattern, "severity", None), "value", str(getattr(pattern, "severity", ""))).lower()
                for pattern in behavior_result
            ]
            if confidences:
                score = max(confidences)
                if "critical" in severities:
                    score = max(score, 0.9)
                elif "high" in severities:
                    score = max(score, 0.75)
                return min(1.0, score)
            pattern_count = len(behavior_result)
        elif hasattr(behavior_result, '__len__'):
            pattern_count = len(behavior_result)
        else:
            pattern_count = 1 if behavior_result else 0
        
        # Score increases with more patterns
        return min(0.6, pattern_count * 0.2)
    
    def _calculate_correlation_score(self, correlation_result: Optional[Any]) -> float:
        """Calculate score from correlation"""
        if not correlation_result:
            return 0.0
        
        # Check for correlation clusters
        if isinstance(correlation_result, list):
            cluster_count = len(correlation_result)
        elif hasattr(correlation_result, '__len__'):
            cluster_count = len(correlation_result)
        else:
            cluster_count = 1 if correlation_result else 0
        
        # Larger clusters get higher scores
        return min(0.4, cluster_count * 0.1)
    
    def _calculate_recency_score(self, event: Any) -> float:
        """Calculate recency penalty for old events"""
        try:
            if hasattr(event, 'timestamp'):
                timestamp = event.timestamp
            elif isinstance(event, dict) and 'timestamp' in event:
                timestamp = event['timestamp']
            else:
                return 1.0  # No timestamp, assume recent
            
            # Convert to datetime if needed
            if isinstance(timestamp, str):
                from dateutil.parser import isoparse
                timestamp = isoparse(timestamp)
            
            # Calculate hours since event. Pipeline timestamps are tz-aware UTC,
            # so use tz-aware "now" and coerce the event ts to UTC. (Previously
            # datetime.utcnow() was naive, raising TypeError on aware timestamps
            # and silently forcing every event to a recency of 1.0.)
            hours_ago = (datetime_now_utc() - ensure_utc(timestamp)).total_seconds() / 3600
            
            # Penalize older events
            if hours_ago < 1:  # Less than 1 hour
                return 1.0
            elif hours_ago < 24:  # Less than 1 day
                return 0.8
            elif hours_ago < 168:  # Less than 1 week
                return 0.5
            else:  # Older than 1 week
                return 0.2
                
        except Exception:
            return 1.0  # Default to recent if error
    
    def _determine_threat_level(self, score: float) -> ThreatLevel:
        """Determine threat level based on score"""
        if score >= self.thresholds[ThreatLevel.CRITICAL]:
            return ThreatLevel.CRITICAL
        elif score >= self.thresholds[ThreatLevel.HIGH]:
            return ThreatLevel.HIGH
        elif score >= self.thresholds[ThreatLevel.MEDIUM]:
            return ThreatLevel.MEDIUM
        elif score >= self.thresholds[ThreatLevel.LOW]:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO
    
    def _calculate_confidence(self, component_scores: Dict, sources: List[str]) -> float:
        """Calculate confidence based on consistency and sources"""
        if not component_scores:
            return 0.1
        
        # Base confidence from number of sources
        source_confidence = min(0.5, len(sources) * 0.1)
        
        # Consistency confidence - how many sources agree on high score
        high_score_count = sum(1 for score in component_scores.values() if score > 0.6)
        consistency_confidence = min(0.3, high_score_count * 0.1)
        
        # Maximum score confidence
        max_score = max(component_scores.values()) if component_scores else 0.0
        score_confidence = max_score * 0.2
        
        return min(1.0, source_confidence + consistency_confidence + score_confidence)
    
    def _update_stats(self, score: float, level: ThreatLevel):
        """Update scoring statistics"""
        self.stats["scores_calculated"] += 1
        
        if level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            self.stats["high_risk_scores"] += 1
        
        # Update running average
        prev_avg = self.stats["average_score"]
        n = self.stats["scores_calculated"]
        self.stats["average_score"] = ((prev_avg * (n - 1)) + score) / n
        
        # Update distribution
        self.stats["score_distribution"][level.value] = \
            self.stats["score_distribution"].get(level.value, 0) + 1
    
    def _store_score(self, threat_score: ThreatScore):
        """Store score in history"""
        self.score_history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "score": threat_score.score,
            "level": threat_score.level.value,
            "sources": threat_score.sources,
            "confidence": threat_score.confidence
        })
        
        # Trim history if too large
        if len(self.score_history) > self.max_history:
            self.score_history.pop(0)
    
    def score_cluster(self, cluster: Any) -> Optional[ThreatScore]:
        """
        Calculate threat score for a correlation cluster
        
        Args:
            cluster: Correlation cluster object
            
        Returns:
            ThreatScore for the cluster
        """
        try:
            if not hasattr(cluster, 'events') or not cluster.events:
                return None
            
            # Calculate average score of events in cluster
            event_scores = []
            for event in cluster.events:
                # This would normally use score_event, but we need a simplified version
                # for clustering. For now, use a heuristic.
                
                # Check if event has threat score attribute
                if hasattr(event, 'threat_score'):
                    event_scores.append(event.threat_score.score)
                else:
                    # Estimate score based on event attributes
                    severity_score = self._calculate_event_severity(event)
                    event_scores.append(severity_score)
            
            if not event_scores:
                return None
            
            avg_score = sum(event_scores) / len(event_scores)
            
            # Boost for large clusters
            size_boost = min(0.3, len(cluster.events) * 0.02)
            cluster_score = min(1.0, avg_score + size_boost)
            
            # Determine level
            threat_level = self._determine_threat_level(cluster_score)
            
            # Confidence based on cluster size and consistency
            confidence = min(0.9, 0.3 + (len(cluster.events) * 0.05))
            
            return ThreatScore(
                score=cluster_score,
                level=threat_level,
                confidence=confidence,
                sources=["correlation_cluster"],
                details={
                    "cluster_size": len(cluster.events),
                    "event_score_average": avg_score,
                    "cluster_id": getattr(cluster, 'cluster_id', 'unknown')
                }
            )
            
        except Exception as e:
            logger.error(f"Error scoring cluster: {str(e)}")
            return None
    
    def get_score_statistics(self) -> Dict:
        """Get scoring engine statistics"""
        stats = self.stats.copy()
        
        # Add recent scores summary
        if self.score_history:
            recent_scores = self.score_history[-10:]  # Last 10 scores
            stats["recent_scores"] = [
                {"score": s["score"], "level": s["level"]} 
                for s in recent_scores
            ]
            stats["current_trend"] = self._calculate_trend()
        else:
            stats["recent_scores"] = []
            stats["current_trend"] = "insufficient_data"
        
        return stats
    
    def _calculate_trend(self) -> str:
        """Calculate score trend"""
        if len(self.score_history) < 10:
            return "insufficient_data"
        
        # Get last 10 scores
        recent = self.score_history[-10:]
        scores = [s["score"] for s in recent]
        
        # Simple linear trend calculation
        n = len(scores)
        x = list(range(n))
        y = scores
        
        # Calculate slope
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(x[i] * y[i] for i in range(n))
        sum_x2 = sum(x_i * x_i for x_i in x)
        
        numerator = n * sum_xy - sum_x * sum_y
        denominator = n * sum_x2 - sum_x * sum_x
        
        if denominator == 0:
            return "stable"
        
        slope = numerator / denominator
        
        if slope > 0.01:
            return "increasing"
        elif slope < -0.01:
            return "decreasing"
        else:
            return "stable"
    
    def get_recent_scores(self, limit: int = 20) -> List[Dict]:
        """Get recent threat scores"""
        return self.score_history[-limit:] if self.score_history else []
    
    def get_high_risk_events(self, threshold: float = 0.7) -> List[Dict]:
        """Get high risk events from history"""
        high_risk = []
        
        for score_data in self.score_history[-100:]:  # Check last 100
            if score_data["score"] >= threshold:
                high_risk.append(score_data)
        
        return high_risk
    
    def reset_statistics(self):
        """Reset scoring statistics"""
        self.stats = {
            "scores_calculated": 0,
            "high_risk_scores": 0,
            "average_score": 0.0,
            "score_distribution": {level.value: 0 for level in ThreatLevel}
        }
        logger.info("Scoring statistics reset")
