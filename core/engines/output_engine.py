"""
Output Engine: Formats and delivers intelligence to various consumers - FIXED VERSION
"""
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable
import logging
from enum import Enum

from core.models.event_models import NormalizedEvent, EventCluster, Entity, EventType, EventSeverity
from core.engines.scoring_engine import ThreatScore, ThreatLevel
from storage.alert_store import AlertStore

logger = logging.getLogger(__name__)

class OutputFormat(Enum):
    """Supported output formats"""
    JSON = "json"
    CONSOLE = "console"
    SYSLOG = "syslog"
    CSV = "csv"
    STIX = "stix"
    CEF = "cef"

class AlertPriority(Enum):
    """Alert priority levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class OutputEngine:
    """Formats and delivers intelligence to various consumers"""
    
    def __init__(self, config: Any = None):
        self.config = config or {}
        self.subscribers = []
        self.alert_history = []
        self.max_alerts_history = 10000
        self.alert_store = AlertStore(self.config.get("alert_store_path") if isinstance(self.config, dict) else None)
        
        # Output formatters
        self.formatters = {
            OutputFormat.JSON: self._format_json,
            OutputFormat.CONSOLE: self._format_console,
            OutputFormat.CSV: self._format_csv,
            OutputFormat.CEF: self._format_cef,
            OutputFormat.STIX: self._format_stix
        }
        
        # Statistics
        self.stats = {
            "alerts_published": 0,
            "reports_published": 0,
            "subscribers": 0,
            "errors": 0
        }
        
        logger.info("Output Engine initialized")
    
    def subscribe(self, callback: Callable, format: OutputFormat = OutputFormat.JSON):
        """Subscribe to receive output"""
        self.subscribers.append((callback, format))
        self.stats["subscribers"] = len(self.subscribers)
        logger.info(f"New subscriber added. Total subscribers: {self.stats['subscribers']}")
    
    def publish_alert(self, event: NormalizedEvent, 
                     threat_score: ThreatScore,
                     correlation_result: Optional[List[EventCluster]] = None,
                     behavior_result: Optional[List[Any]] = None):
        """Publish a new alert"""
        
        try:
            # Create alert object
            alert = self._create_alert(event, threat_score, correlation_result, behavior_result)

            if not self.alert_store.append(alert):
                logger.debug(f"Skipped duplicate alert: {alert['alert_id']}")
                return
            
            # Store in history
            self.alert_history.append(alert)
            if len(self.alert_history) > self.max_alerts_history:
                self.alert_history = self.alert_history[-self.max_alerts_history:]
            
            # Publish to all subscribers
            for callback, format in self.subscribers:
                try:
                    formatted_alert = self.formatters[format](alert)
                    callback(formatted_alert)
                except Exception as e:
                    logger.error(f"Error publishing alert to subscriber: {str(e)}")
                    self.stats["errors"] += 1
            
            self.stats["alerts_published"] += 1
            logger.info(f"Published alert: {alert['alert_id']} - {alert['threat_level']}")
            
        except Exception as e:
            logger.error(f"Error publishing alert: {str(e)}")
            self.stats["errors"] += 1
    
    # ADD THIS COMPATIBILITY METHOD - This is the fix!
    def publish_alert_simple(self, alert_data: Dict, threat_score: float):
        """Simplified publish_alert for compatibility with existing code
        
        This method is needed because somewhere in your code (likely in 
        behavior_engine.py), publish_alert is being called with only 
        alert_data and threat_score parameters.
        
        Args:
            alert_data: Dictionary containing alert information
            threat_score: Numeric threat score (0-100)
        """
        try:
            # Convert simple threat_score to ThreatScore object
            from core.engines.scoring_engine import ThreatScore, ThreatLevel
            
            # Map numeric score to ThreatLevel
            if threat_score >= 80:
                level = ThreatLevel.CRITICAL
            elif threat_score >= 60:
                level = ThreatLevel.HIGH
            elif threat_score >= 40:
                level = ThreatLevel.MEDIUM
            elif threat_score >= 20:
                level = ThreatLevel.LOW
            else:
                level = ThreatLevel.INFO
                
            threat_score_obj = ThreatScore(
                score=threat_score,
                level=level,
                confidence=threat_score / 100.0
            )
            
            # Convert alert_data to NormalizedEvent if needed
            # This is a simplified conversion
            from core.models.event_models import NormalizedEvent, EventType, EventSeverity
            import uuid
            
            # Check if alert_data is already a NormalizedEvent
            if isinstance(alert_data, NormalizedEvent):
                event = alert_data
            else:
                # Create a simple NormalizedEvent from dictionary
                event = NormalizedEvent(
                    event_id=str(uuid.uuid4())[:8],
                    event_type=EventType.NETWORK_CONNECTION,
                    timestamp=datetime.now(timezone.utc),
                    source_ip=alert_data.get('src_ip', 'unknown'),
                    destination_ip=alert_data.get('dst_ip', 'unknown'),
                    severity=EventSeverity.MEDIUM,
                    details={
                        **alert_data,
                        'src_port': alert_data.get('src_port', 0),
                        'dst_port': alert_data.get('dst_port', 0),
                        'protocol': alert_data.get('protocol', 'unknown')
                    }
                )
            
            # Call the main publish_alert method
            self.publish_alert(event, threat_score_obj)
            
        except Exception as e:
            logger.error(f"Error in publish_alert_simple: {str(e)}")
            # Fallback: just log the alert
            logger.info(f"Simple Alert: Score={threat_score}, Data={alert_data}")
    
    def publish_intelligence_report(self, events: List[NormalizedEvent],
                                  clusters: List[EventCluster],
                                  time_range: Optional[Dict[str, datetime]] = None):
        """Publish an intelligence report"""
        
        try:
            if time_range is None:
                from datetime import timedelta
                time_range = {
                    "start": datetime.now(timezone.utc) - timedelta(hours=24),
                    "end": datetime.now(timezone.utc)
                }
            
            report = self._create_intelligence_report(events, clusters, time_range)
            
            # Publish to all subscribers
            for callback, format in self.subscribers:
                try:
                    formatted_report = self.formatters[format](report)
                    callback(formatted_report)
                except Exception as e:
                    logger.error(f"Error publishing report to subscriber: {str(e)}")
                    self.stats["errors"] += 1
            
            self.stats["reports_published"] += 1
            logger.info(f"Published intelligence report covering {len(events)} events")
            
        except Exception as e:
            logger.error(f"Error publishing intelligence report: {str(e)}")
            self.stats["errors"] += 1
    
    def _create_alert(self, event: NormalizedEvent,
                     threat_score: ThreatScore,
                     correlation_result: Optional[List[EventCluster]],
                     behavior_result: Optional[List[Any]]) -> Dict:
        """Create structured alert object"""
        
        alert_id = f"alert_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{event.event_id[:8]}"
        
        alert = {
            "alert_id": alert_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event.to_dict(),
            "threat_score": {
                "score": threat_score.score,
                "level": threat_score.level.value,
                "confidence": threat_score.confidence,
                "sources": threat_score.sources,
                "details": threat_score.details
            },
            "threat_level": threat_score.level.value,
            "priority": self._calculate_priority(threat_score).value,
            "summary": self._generate_alert_summary(event, threat_score),
            "recommended_actions": self._generate_recommendations(event, threat_score),
            "metadata": {
                "correlation_present": bool(correlation_result),
                "behavior_analysis_present": bool(behavior_result),
                "source_system": "cyber_ew_fusion_cell",
                "dedupe_key": f"{event.hash_id}:{threat_score.level.value}"
            }
        }
        
        # Add correlation data if available
        if correlation_result:
            alert["correlation"] = {
                "cluster_count": len(correlation_result),
                "clusters": [
                    {
                        "cluster_id": c.cluster_id,
                        "correlation_type": c.correlation_type,
                        "confidence": c.confidence,
                        "event_count": len(c.event_ids),
                        "entities": c.entities
                    }
                    for c in correlation_result[:5]  # Limit to 5 clusters
                ]
            }
        
        # Add behavior analysis if available
        if behavior_result:
            # Assuming behavior_result is a list of BehaviorPattern objects
            alert["behavior_analysis"] = {
                "pattern_count": len(behavior_result),
                "patterns": [
                    {
                        "pattern_type": self._extract_pattern_type(p),
                        "confidence": getattr(p, 'confidence', 0.0),
                        "description": getattr(p, 'description', 'No description')
                    }
                    for p in behavior_result[:3]  # Limit to 3 patterns
                ]
            }
        
        return alert
    
    def _create_intelligence_report(self, events: List[NormalizedEvent],
                                  clusters: List[EventCluster],
                                  time_range: Dict[str, datetime]) -> Dict:
        """Create structured intelligence report"""
        
        report_id = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        
        # Calculate statistics
        unique_source_ips = set()
        unique_destination_ips = set()
        
        for event in events:
            if event.source_ip:
                unique_source_ips.add(event.source_ip)
            if event.destination_ip:
                unique_destination_ips.add(event.destination_ip)
        
        report = {
            "report_id": report_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_range": {
                "start": time_range["start"].isoformat(),
                "end": time_range["end"].isoformat()
            },
            "executive_summary": self._generate_executive_summary(events, clusters),
            "statistics": {
                "total_events": len(events),
                "high_severity_events": len([e for e in events if e.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL]]),
                "correlation_clusters": len(clusters),
                "unique_source_ips": len(unique_source_ips),
                "unique_destination_ips": len(unique_destination_ips)
            },
            "key_findings": self._extract_key_findings(events, clusters),
            "threat_actors": self._identify_threat_actors(events),
            "timeline": self._build_timeline(events, clusters),
            "recommendations": self._generate_report_recommendations(events, clusters),
            "appendix": {
                "event_samples": [e.to_dict() for e in events[:5]],  # First 5 events
                "cluster_details": [
                    {
                        "cluster_id": c.cluster_id,
                        "type": c.correlation_type,
                        "event_count": len(c.event_ids),
                        "confidence": c.confidence
                    }
                    for c in clusters[:3]  # First 3 clusters
                ]
            }
        }
        
        return report
    
    def _calculate_priority(self, threat_score: ThreatScore) -> AlertPriority:
        """Calculate alert priority from threat score"""
        if threat_score.level == ThreatLevel.CRITICAL:
            return AlertPriority.CRITICAL
        elif threat_score.level == ThreatLevel.HIGH:
            return AlertPriority.HIGH
        elif threat_score.level == ThreatLevel.MEDIUM:
            return AlertPriority.MEDIUM
        elif threat_score.level == ThreatLevel.LOW:
            return AlertPriority.LOW
        else:
            return AlertPriority.INFO
    
    def _generate_alert_summary(self, event: NormalizedEvent, 
                               threat_score: ThreatScore) -> str:
        """Generate human-readable alert summary"""
        
        summary_parts = []
        
        # Event type and entities
        summary_parts.append(f"Event: {event.event_type.value}")
        if event.source_ip:
            summary_parts.append(f"Source: {event.source_ip}")
        if event.destination_ip:
            summary_parts.append(f"Destination: {event.destination_ip}")
        
        # Action and outcome from details
        if event.details.get("action"):
            summary_parts.append(f"Action: {event.details.get('action')}")
        if event.details.get("status"):
            summary_parts.append(f"Status: {event.details.get('status')}")
        
        # Threat level
        summary_parts.append(f"Threat Level: {threat_score.level.value.upper()}")
        summary_parts.append(f"Confidence: {threat_score.confidence:.0%}")
        
        # Additional context
        if event.tags:
            summary_parts.append(f"Tags: {', '.join(event.tags[:3])}")
        
        return " | ".join(summary_parts)
    
    def _generate_recommendations(self, event: NormalizedEvent,
                                 threat_score: ThreatScore) -> List[str]:
        """Generate recommended actions for the alert"""
        
        recommendations = []
        
        # Base recommendations based on threat level
        if threat_score.level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            recommendations.extend([
                "Immediate investigation required",
                "Consider network isolation of affected systems",
                "Review related security controls"
            ])
        elif threat_score.level == ThreatLevel.MEDIUM:
            recommendations.extend([
                "Schedule investigation within 24 hours",
                "Monitor for related activity",
                "Update threat intelligence feeds"
            ])
        else:
            recommendations.append("Monitor for escalation")
        
        # Specific recommendations based on event type
        if event.event_type == EventType.NETWORK_CONNECTION:
            recommendations.append("Review firewall rules for source/destination")
        
        if event.is_external:
            recommendations.append("Check if external communication was authorized")
        
        if "known_malicious" in event.tags:
            recommendations.append("Update block lists with observed indicators")
        
        return recommendations
    
    def _generate_executive_summary(self, events: List[NormalizedEvent],
                                  clusters: List[EventCluster]) -> str:
        """Generate executive summary for intelligence report"""
        
        if not events:
            return "No events to report in the specified time period."
        
        # Calculate basic metrics
        high_severity_count = len([e for e in events if e.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL]])
        cluster_count = len(clusters)
        
        summary = [
            f"Analysis of {len(events)} events revealed {high_severity_count} high-severity incidents.",
            f"{cluster_count} correlation clusters were identified, indicating potential coordinated activity."
        ]
        
        # Add notable findings
        if clusters:
            largest_cluster = max(clusters, key=lambda c: len(c.event_ids))
            summary.append(
                f"Largest cluster ({len(largest_cluster.event_ids)} events) "
                f"showed pattern: {largest_cluster.correlation_type}."
            )
        
        return " ".join(summary)
    
    def _extract_key_findings(self, events: List[NormalizedEvent],
                             clusters: List[EventCluster]) -> List[Dict]:
        """Extract key findings from events and clusters"""
        
        findings = []
        
        # Top events by severity
        severe_events = sorted(
            events,
            key=lambda e: {
                EventSeverity.CRITICAL: 5,
                EventSeverity.HIGH: 4,
                EventSeverity.MEDIUM: 3,
                EventSeverity.LOW: 2,
                EventSeverity.INFO: 1
            }.get(e.severity, 0),
            reverse=True
        )[:3]  # Top 3 events
        
        for event in severe_events:
            finding = {
                "type": "high_severity_event",
                "event_id": event.event_id,
                "description": f"{event.event_type.value} with {event.severity.value} severity",
                "timestamp": event.timestamp.isoformat(),
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip
            }
            findings.append(finding)
        
        # Notable clusters
        for cluster in clusters[:2]:  # Top 2 clusters
            finding = {
                "type": "correlation_cluster",
                "cluster_id": cluster.cluster_id,
                "description": f"{cluster.correlation_type} cluster with {len(cluster.event_ids)} events",
                "confidence": cluster.confidence,
                "entities": cluster.entities
            }
            findings.append(finding)
        
        return findings
    
    def _identify_threat_actors(self, events: List[NormalizedEvent]) -> List[Dict]:
        """Identify potential threat actors from events"""
        
        actors = []
        
        # Group events by source IP
        source_events = {}
        for event in events:
            if event.source_ip:
                if event.source_ip not in source_events:
                    source_events[event.source_ip] = []
                source_events[event.source_ip].append(event)
        
        # Identify suspicious sources
        for source_ip, events_list in source_events.items():
            if len(events_list) > 10:  # High volume source
                high_severity_count = len([e for e in events_list if e.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL]])
                
                if high_severity_count > 0:
                    timestamps = [e.timestamp for e in events_list]
                    actor = {
                        "entity_id": source_ip,
                        "entity_value": source_ip,
                        "event_count": len(events_list),
                        "high_severity_events": high_severity_count,
                        "first_seen": min(timestamps).isoformat(),
                        "last_seen": max(timestamps).isoformat()
                    }
                    actors.append(actor)
        
        return actors
    
    def _build_timeline(self, events: List[NormalizedEvent],
                       clusters: List[EventCluster]) -> List[Dict]:
        """Build chronological timeline of events and clusters"""
        
        timeline = []
        
        # Add events to timeline
        for event in events[:50]:  # Limit to 50 events for timeline
            timeline_entry = {
                "timestamp": event.timestamp.isoformat(),
                "type": "event",
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "source": event.source_ip,
                "destination": event.destination_ip,
                "severity": event.severity.value
            }
            timeline.append(timeline_entry)
        
        # Add clusters to timeline (use cluster timestamp)
        for cluster in clusters[:10]:  # Limit to 10 clusters
            timeline_entry = {
                "timestamp": cluster.timestamp.isoformat(),
                "type": "cluster",
                "cluster_id": cluster.cluster_id,
                "correlation_type": cluster.correlation_type,
                "event_count": len(cluster.event_ids)
            }
            timeline.append(timeline_entry)
        
        # Sort timeline chronologically
        timeline.sort(key=lambda x: x["timestamp"])
        
        return timeline[:100]  # Limit timeline size
    
    def _generate_report_recommendations(self, events: List[NormalizedEvent],
                                        clusters: List[EventCluster]) -> List[Dict]:
        """Generate recommendations from intelligence report"""
        
        recommendations = []
        
        # Security control recommendations
        if clusters:
            recommendations.append({
                "priority": "high",
                "category": "detection",
                "recommendation": "Review and tune correlation rules based on observed cluster patterns",
                "rationale": f"{len(clusters)} correlation clusters detected, indicating pattern-based activity"
            })
        
        # Threat hunting recommendations
        high_severity_sources = set()
        for event in events:
            if event.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL] and event.source_ip:
                high_severity_sources.add(event.source_ip)
        
        if high_severity_sources:
            recommendations.append({
                "priority": "high",
                "category": "threat_hunting",
                "recommendation": "Conduct threat hunt for activities from identified high-risk sources",
                "rationale": f"{len(high_severity_sources)} sources associated with high-severity events"
            })
        
        # Infrastructure recommendations
        external_events = sum(1 for e in events if e.is_external)
        if external_events > len(events) * 0.3:  # More than 30% external
            recommendations.append({
                "priority": "medium",
                "category": "network_security",
                "recommendation": "Review outbound communication policies and egress filtering",
                "rationale": f"High volume of external communications ({external_events} events)"
            })
        
        return recommendations
    
    def _format_json(self, data: Any) -> str:
        """Format data as JSON"""
        return json.dumps(data, indent=2, default=str)
    
    def _format_console(self, data: Any) -> str:
        """Format data for console output"""
        if isinstance(data, dict):
            # Simple console-friendly format
            output = []
            
            if "alert_id" in data:  # It's an alert
                output.append(f"\n=== ALERT: {data['alert_id']} ===")
                output.append(f"Priority: {data['priority']}")
                output.append(f"Summary: {data['summary']}")
                output.append(f"Time: {data['timestamp']}")
                
                if "recommended_actions" in data:
                    output.append("Recommended Actions:")
                    for action in data["recommended_actions"]:
                        output.append(f"  - {action}")
            
            elif "report_id" in data:  # It's a report
                output.append(f"\n=== INTELLIGENCE REPORT: {data['report_id']} ===")
                output.append(f"Executive Summary: {data['executive_summary']}")
                output.append(f"Time Range: {data['time_range']['start']} to {data['time_range']['end']}")
                output.append(f"Total Events: {data['statistics']['total_events']}")
            
            return "\n".join(output)
        
        return str(data)
    
    def _format_csv(self, data: Any) -> str:
        """Format data as CSV"""
        # Simplified CSV formatter
        if isinstance(data, dict) and "alert_id" in data:
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                "alert_id", "timestamp", "priority", "threat_level",
                "confidence", "source_ip", "destination_ip", "event_type"
            ])
            
            # Write data
            writer.writerow([
                data["alert_id"],
                data["timestamp"],
                data["priority"],
                data["threat_score"]["level"],
                data["threat_score"]["confidence"],
                data["event"]["source_ip"],
                data["event"]["destination_ip"],
                data["event"]["event_type"]
            ])
            
            return output.getvalue()
        
        return str(data)
    
    def _format_cef(self, data: Any) -> str:
        """Format data as Common Event Format (CEF)"""
        if isinstance(data, dict) and "alert_id" in data:
            # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
            cef_parts = [
                "CEF:0",
                "CyberEW",
                "FusionCell",
                "1.0",
                data["alert_id"],
                data["summary"][:100],  # Truncate if needed
                self._cef_severity(data["priority"]),
                self._build_cef_extension(data)
            ]
            
            return "|".join(cef_parts)
        
        return str(data)
    
    def _cef_severity(self, priority: str) -> str:
        """Convert priority to CEF severity"""
        severity_map = {
            "critical": "10",
            "high": "8",
            "medium": "5",
            "low": "3",
            "info": "1"
        }
        return severity_map.get(priority.lower(), "3")
    
    def _build_cef_extension(self, data: Dict) -> str:
        """Build CEF extension string"""
        extension_parts = []
        
        # Add standard fields
        if "event" in data:
            event = data["event"]
            
            if event.get("timestamp"):
                extension_parts.append(f"rt={event['timestamp']}")
            
            if event.get("source_ip"):
                extension_parts.append(f"src={event['source_ip']}")
            
            if event.get("destination_ip"):
                extension_parts.append(f"dst={event['destination_ip']}")
        
        # Add threat score
        if "threat_score" in data:
            ts = data["threat_score"]
            extension_parts.append(f"deviceSeverity={ts['level']}")
            extension_parts.append(f"confidence={ts['confidence']}")
        
        return " ".join(extension_parts)
    
    def _extract_pattern_type(self, pattern: Any) -> str:
        """Safely extract pattern_type from a behavior pattern object"""
        pattern_type = getattr(pattern, 'pattern_type', 'unknown')
        
        # If it's already a string, return it
        if isinstance(pattern_type, str):
            return pattern_type
        # If it's an enum with a .value attribute, extract the value
        elif hasattr(pattern_type, 'value'):
            return pattern_type.value
        # Otherwise convert to string
        else:
            return str(pattern_type)
    
    def _format_stix(self, data: Any) -> str:
        """Format data as STIX 2.x"""
        # This would use the stix2 library to create proper STIX objects
        # Simplified implementation
        if isinstance(data, dict) and "alert_id" in data:
            stix_object = {
                "type": "indicator",
                "id": f"indicator--{data['alert_id']}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": data["summary"][:100],
                "description": f"Alert from Cyber-EW Fusion Cell: {data['alert_id']}",
                "pattern": self._build_stix_pattern(data),
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "labels": ["malicious-activity"]
            }
            
            return json.dumps(stix_object, indent=2)
        
        return str(data)
    
    def _build_stix_pattern(self, data: Dict) -> str:
        """Build STIX pattern from alert data"""
        pattern_parts = []
        
        if "event" in data:
            event = data["event"]
            
            if event.get("source_ip"):
                value = event["source_ip"]
                if ":" in value:  # IPv6
                    pattern_parts.append(f"[ipv6-addr:value = '{value}']")
                elif "." in value:  # IPv4
                    pattern_parts.append(f"[ipv4-addr:value = '{value}']")
        
        if pattern_parts:
            return " AND ".join(pattern_parts)
        
        return "[network-traffic:protocols[*] = 'tcp']"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            **self.stats,
            "current_subscribers": len(self.subscribers),
            "alert_history_size": len(self.alert_history)
        }

    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent alerts from memory and durable storage."""
        if self.alert_history:
            return self.alert_history[-limit:][::-1]
        return self.alert_store.recent(limit=limit)
    
    def clear_history(self):
        """Clear alert history"""
        self.alert_history.clear()
        logger.info("Alert history cleared")
