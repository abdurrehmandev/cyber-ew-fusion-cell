"""
Correlation Engine - FIXED VERSION
"""
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
import uuid
from collections import defaultdict

from core.models.event_models import NormalizedEvent, EventCluster
from utils.time_utils import TimeWindowIndex, ensure_utc, datetime_now_utc
from config.settings import CORRELATION_CONFIG

class CorrelationEngine:
    """
    Correlation engine that links events based on time, entities, and patterns.
    FIXED: Uses UTC timestamps consistently.
    """
    
    def __init__(self, config: Any = None):
        self.config = config or CORRELATION_CONFIG
        self.time_index = TimeWindowIndex(
            window_seconds=self.config.time_window_seconds
        )
        self.entity_index: Dict[str, Set[str]] = defaultdict(set)  # entity_value -> set(event_ids)
        self.clusters: Dict[str, EventCluster] = {}
        self.event_store: Dict[str, NormalizedEvent] = {}
        
        # Statistics
        self.stats = {
            "events_processed": 0,
            "clusters_created": 0,
            "clusters_updated": 0
        }
    
    def process_event(self, event: NormalizedEvent) -> List[EventCluster]:
        """
        Process an event and return any updated clusters.
        
        Args:
            event: Normalized event to process
            
        Returns:
            List of clusters that were created or updated
        """
        updated_clusters = []
        
        # Store event
        self.event_store[event.event_id] = event
        self.stats["events_processed"] += 1
        
        # Index event
        self._index_event(event)
        
        # Find correlated events
        correlated_event_ids = self._find_correlated_events(event)
        
        if correlated_event_ids:
            # Create or update cluster
            cluster = self._create_or_update_cluster(event, correlated_event_ids)
            if cluster:
                updated_clusters.append(cluster)
        
        # Clean up old events periodically
        if self.stats["events_processed"] % 1000 == 0:
            self._cleanup_old_events()
        
        return updated_clusters
    
    def _index_event(self, event: NormalizedEvent):
        """Index event by time and entities"""
        # Index by time (time index handles UTC conversion)
        self.time_index.add_event(event.timestamp, event.event_id)
        
        # Index by entities
        entities = self._extract_entities(event)
        for entity_type, entity_value in entities:
            if entity_value:  # Skip None/empty values
                self.entity_index[entity_value].add(event.event_id)
    
    def _extract_entities(self, event: NormalizedEvent) -> List[Tuple[str, str]]:
        """Extract entities from event for indexing"""
        entities = []
        
        if event.source_ip:
            entities.append(("source_ip", event.source_ip))
        if event.destination_ip:
            entities.append(("destination_ip", event.destination_ip))
        if event.source_host:
            entities.append(("source_host", event.source_host))
        if event.destination_host:
            entities.append(("destination_host", event.destination_host))
        if event.username:
            entities.append(("username", event.username))
        
        return entities
    
    def _find_correlated_events(self, event: NormalizedEvent) -> List[str]:
        """Find events correlated with the given event"""
        correlated_ids = set()
        
        # Find events in time window
        time_correlated = self.time_index.get_events_in_window(event.timestamp)
        correlated_ids.update(time_correlated)
        
        # Find events with same entities
        entities = self._extract_entities(event)
        for _, entity_value in entities:
            if entity_value in self.entity_index:
                correlated_ids.update(self.entity_index[entity_value])
        
        # Remove the event itself
        correlated_ids.discard(event.event_id)
        
        return list(correlated_ids)
    
    def _create_or_update_cluster(self, event: NormalizedEvent, 
                                 correlated_ids: List[str]) -> Optional[EventCluster]:
        """Create or update a cluster with correlated events"""
        # Find existing clusters containing correlated events
        existing_clusters = self._find_existing_clusters(correlated_ids)
        
        if existing_clusters:
            # Merge into the first cluster
            main_cluster = existing_clusters[0]
            
            # Add event to main cluster
            main_cluster.add_event(event.event_id)
            
            # Merge other clusters if multiple exist
            for other_cluster in existing_clusters[1:]:
                for eid in other_cluster.event_ids:
                    if eid not in main_cluster.event_ids:
                        main_cluster.add_event(eid)
                
                # Remove merged cluster
                if other_cluster.cluster_id in self.clusters:
                    del self.clusters[other_cluster.cluster_id]
            
            # Update entities
            self._update_cluster_entities(main_cluster)
            
            self.stats["clusters_updated"] += 1
            return main_cluster
        else:
            # Create new cluster
            cluster_id = f"cluster_{uuid.uuid4().hex[:8]}"
            
            # All event IDs including the new event
            all_event_ids = [event.event_id] + correlated_ids
            
            # Extract entities
            entities = self._extract_entities_for_cluster(all_event_ids)
            
            # Create cluster
            cluster = EventCluster(
                cluster_id=cluster_id,
                event_ids=all_event_ids,
                correlation_type="temporal_entity",
                confidence=self._calculate_confidence(all_event_ids),
                timestamp=datetime_now_utc(),
                entities=entities,
                summary=f"Cluster of {len(all_event_ids)} correlated events"
            )
            
            self.clusters[cluster_id] = cluster
            self.stats["clusters_created"] += 1
            return cluster
    
    def _find_existing_clusters(self, event_ids: List[str]) -> List[EventCluster]:
        """Find clusters containing any of the given event IDs"""
        clusters = []
        for cluster in self.clusters.values():
            if any(eid in cluster.event_ids for eid in event_ids):
                clusters.append(cluster)
        return clusters
    
    def _extract_entities_for_cluster(self, event_ids: List[str]) -> Dict[str, List[str]]:
        """Extract entities for a cluster of events"""
        entities = defaultdict(list)
        
        for event_id in event_ids:
            if event_id in self.event_store:
                event = self.event_store[event_id]
                event_entities = self._extract_entities(event)
                
                for entity_type, entity_value in event_entities:
                    if entity_value and entity_value not in entities[entity_type]:
                        entities[entity_type].append(entity_value)
        
        return dict(entities)
    
    def _update_cluster_entities(self, cluster: EventCluster):
        """Update entities for an existing cluster"""
        entities = self._extract_entities_for_cluster(cluster.event_ids)
        cluster.entities = entities
    
    def _calculate_confidence(self, event_ids: List[str]) -> float:
        """Calculate correlation confidence"""
        if len(event_ids) < 2:
            return 0.0
        
        # Base confidence on number of events and shared entities
        base_confidence = min(len(event_ids) / 10.0, 1.0)
        
        # Check for shared entities
        shared_entity_count = 0
        entity_counts = defaultdict(set)
        
        for event_id in event_ids:
            if event_id in self.event_store:
                event = self.event_store[event_id]
                entities = self._extract_entities(event)
                for entity_type, entity_value in entities:
                    if entity_value:
                        entity_counts[entity_type].add(entity_value)
        
        # Count entity types with shared values
        for entity_type, values in entity_counts.items():
            if len(values) < len(event_ids):  # Not all unique = some sharing
                shared_entity_count += 1
        
        entity_confidence = shared_entity_count / 5.0  # Max 5 entity types
        return min(base_confidence + entity_confidence, 1.0)
    
    def _cleanup_old_events(self):
        """Clean up events older than time window"""
        # Get events outside time window
        cutoff = datetime_now_utc() - timedelta(seconds=self.config.time_window_seconds)
        
        # Remove old events from event store
        old_event_ids = [
            eid for eid, event in self.event_store.items()
            if ensure_utc(event.timestamp) < cutoff
        ]
        
        for event_id in old_event_ids:
            if event_id in self.event_store:
                # Remove from entity index
                event = self.event_store[event_id]
                entities = self._extract_entities(event)
                for _, entity_value in entities:
                    if entity_value in self.entity_index:
                        self.entity_index[entity_value].discard(event_id)
                        if not self.entity_index[entity_value]:
                            del self.entity_index[entity_value]
                
                # Remove from event store
                del self.event_store[event_id]
    
    def get_recent_events(self, minutes: int = 5) -> List[NormalizedEvent]:
        """Get events from the last N minutes"""
        cutoff = datetime_now_utc() - timedelta(minutes=minutes)
        
        recent_events = []
        for event in self.event_store.values():
            if ensure_utc(event.timestamp) >= cutoff:
                recent_events.append(event)
        
        return recent_events
    
    def get_clusters_by_entity(self, entity_type: str, entity_value: str) -> List[EventCluster]:
        """Get clusters containing a specific entity"""
        matching_clusters = []
        
        for cluster in self.clusters.values():
            if (entity_type in cluster.entities and 
                entity_value in cluster.entities[entity_type]):
                matching_clusters.append(cluster)
        
        return matching_clusters
    
    def clear(self):
        """Clear all data from the engine"""
        self.time_index.clear()
        self.entity_index.clear()
        self.clusters.clear()
        self.event_store.clear()
        self.stats = {
            "events_processed": 0,
            "clusters_created": 0,
            "clusters_updated": 0
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            **self.stats,
            "events_stored": len(self.event_store),
            "clusters_active": len(self.clusters),
            "entities_indexed": len(self.entity_index)
        }