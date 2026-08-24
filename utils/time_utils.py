"""
Time utilities for Cyber-EW Fusion Cell - FIXED VERSION
"""
from datetime import datetime, timedelta, timezone
from typing import List, Tuple, Optional, Dict, Any
import heapq
from dataclasses import dataclass

def ensure_utc(dt: datetime) -> datetime:
    """
    Ensure a datetime object is timezone-aware in UTC.
    
    Args:
        dt: Datetime object (naive or aware)
        
    Returns:
        Timezone-aware datetime in UTC
    """
    if dt.tzinfo is None:
        # Assume naive datetime is in UTC
        return dt.replace(tzinfo=timezone.utc)
    elif dt.tzinfo != timezone.utc:
        # Convert to UTC if in another timezone
        return dt.astimezone(timezone.utc)
    return dt

def datetime_now_utc() -> datetime:
    """Get current UTC datetime with timezone"""
    return datetime.now(timezone.utc)

def parse_timestamp(timestamp_str: str, fmt: str = "%Y-%m-%d %H:%M:%S") -> datetime:
    """
    Parse timestamp string to UTC datetime.
    
    Args:
        timestamp_str: String representation of timestamp
        fmt: Format string for parsing
        
    Returns:
        UTC datetime object
    """
    dt = datetime.strptime(timestamp_str, fmt)
    return ensure_utc(dt)

# ADD THIS FUNCTION - FIX FOR normalization_engine.py
def normalize_timestamp(timestamp_input) -> datetime:
    """
    Normalize various timestamp formats to UTC datetime.
    
    Args:
        timestamp_input: Can be datetime object, string, float (Unix timestamp), or None
        
    Returns:
        UTC datetime object
    """
    if timestamp_input is None:
        return datetime_now_utc()
    
    # If it's already a datetime object
    if isinstance(timestamp_input, datetime):
        return ensure_utc(timestamp_input)
    
    # If it's a string
    if isinstance(timestamp_input, str):
        try:
            # Try ISO format first
            try:
                from dateutil.parser import isoparse
                dt = isoparse(timestamp_input)
                return ensure_utc(dt)
            except ImportError:
                # If dateutil is not available, try without it
                pass
            
            # Try common string formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
                "%d-%b-%Y %H:%M:%S",
                "%b %d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S%z"
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(timestamp_input, fmt)
                    return ensure_utc(dt)
                except ValueError:
                    continue
            
            # If all else fails, return current UTC time
            return datetime_now_utc()
        except Exception:
            return datetime_now_utc()
    
    # If it's a Unix timestamp (float or int)
    if isinstance(timestamp_input, (int, float)):
        try:
            # Check if it's in seconds or milliseconds
            if timestamp_input > 1_000_000_000_000:  # Likely milliseconds
                timestamp_input = timestamp_input / 1000.0
            dt = datetime.fromtimestamp(timestamp_input, timezone.utc)
            return dt
        except (ValueError, OSError):
            return datetime_now_utc()
    
    # Default fallback
    return datetime_now_utc()

@dataclass
class TimeRange:
    """Time range with UTC timezone handling"""
    start: datetime
    end: datetime
    
    def __post_init__(self):
        self.start = ensure_utc(self.start)
        self.end = ensure_utc(self.end)
    
    def contains(self, dt: datetime) -> bool:
        """Check if datetime is within range"""
        dt_utc = ensure_utc(dt)
        return self.start <= dt_utc <= self.end
    
    def duration(self) -> timedelta:
        """Get duration of time range"""
        return self.end - self.start

class TimeWindowIndex:
    """Index events within a sliding time window - FIXED"""
    
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        # Store (UTC_timestamp, event_id)
        self.events: List[Tuple[datetime, str]] = []
        self._cleanup_threshold = 1000
    
    def add_event(self, timestamp: datetime, event_id: str):
        """Add an event to the time index"""
        # Convert to UTC
        timestamp_utc = ensure_utc(timestamp)
        heapq.heappush(self.events, (timestamp_utc, event_id))
        
        # Clean old events if threshold reached
        if len(self.events) > self._cleanup_threshold:
            self._clean_old_events()
    
    def get_events_in_window(self, reference_time: Optional[datetime] = None) -> List[str]:
        """
        Get all event IDs within the time window ending at reference_time.
        
        Args:
            reference_time: End of time window (defaults to now)
            
        Returns:
            List of event IDs within the window
        """
        if not self.events:
            return []
        
        # Use current UTC time if no reference provided
        if reference_time is None:
            end_time = datetime_now_utc()
        else:
            end_time = ensure_utc(reference_time)
        
        # Calculate window start
        window_start = end_time - timedelta(seconds=self.window_seconds)
        
        # Filter events within window
        event_ids = []
        for ts, eid in self.events:
            if ts >= window_start:
                event_ids.append(eid)
        
        return event_ids
    
    def get_events_by_time_range(self, start: datetime, end: datetime) -> List[str]:
        """
        Get event IDs within a specific time range.
        
        Args:
            start: Start of time range
            end: End of time range
            
        Returns:
            List of event IDs in range
        """
        start_utc = ensure_utc(start)
        end_utc = ensure_utc(end)
        
        event_ids = []
        for ts, eid in self.events:
            if start_utc <= ts <= end_utc:
                event_ids.append(eid)
        
        return event_ids
    
    def _clean_old_events(self):
        """Remove events older than the time window"""
        if not self.events:
            return
        
        # Calculate cutoff time (now - window)
        cutoff = datetime_now_utc() - timedelta(seconds=self.window_seconds)
        
        # Keep only events within the window
        self.events = [
            (ts, eid) 
            for ts, eid in self.events 
            if ts >= cutoff  # Now comparing UTC to UTC
        ]
        heapq.heapify(self.events)
    
    def clear(self):
        """Clear all events from the index"""
        self.events.clear()
    
    def count(self) -> int:
        """Get number of events in index"""
        return len(self.events)
    
    def get_oldest(self) -> Optional[datetime]:
        """Get timestamp of oldest event"""
        if not self.events:
            return None
        return min(ts for ts, _ in self.events)
    
    def get_newest(self) -> Optional[datetime]:
        """Get timestamp of newest event"""
        if not self.events:
            return None
        return max(ts for ts, _ in self.events)

class TimeSeriesBuffer:
    """Buffer for time series data with timezone handling"""
    
    def __init__(self, max_points: int = 10000):
        self.max_points = max_points
        self.timestamps: List[datetime] = []
        self.values: List[float] = []
    
    def add_point(self, timestamp: datetime, value: float):
        """Add a data point"""
        timestamp_utc = ensure_utc(timestamp)
        
        self.timestamps.append(timestamp_utc)
        self.values.append(value)
        
        # Trim if too many points
        if len(self.timestamps) > self.max_points:
            self.timestamps.pop(0)
            self.values.pop(0)
    
    def get_points_in_range(self, start: datetime, end: datetime) -> List[Tuple[datetime, float]]:
        """Get points within time range"""
        start_utc = ensure_utc(start)
        end_utc = ensure_utc(end)
        
        points = []
        for ts, val in zip(self.timestamps, self.values):
            if start_utc <= ts <= end_utc:
                points.append((ts, val))
        
        return points