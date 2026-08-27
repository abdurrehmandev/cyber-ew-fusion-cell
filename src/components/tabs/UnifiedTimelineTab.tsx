import React, { useEffect, useState, useRef } from "react";
import { UnifiedTimelineEvent, TimelineDomain } from "../../types";
import {
  Play,
  Pause,
  RotateCcw,
  FastForward,
  Filter,
  Layers,
  Radio,
  Globe,
  Binary,
  Flame,
  ShieldCheck,
  Search,
  Clock,
  Zap,
  Info,
  ChevronRight,
  ShieldAlert,
  ArrowRight
} from "lucide-react";

export const UnifiedTimelineTab: React.FC = () => {
  const [events, setEvents] = useState<UnifiedTimelineEvent[]>([]);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);
  const [currentProgress, setCurrentProgress] = useState<number>(0); // 0 to 100%
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [domainFilter, setDomainFilter] = useState<TimelineDomain | "All">("All");
  const [searchTerm, setSearchTerm] = useState("");
  const intervalRef = useRef<any>(null);

  const fetchEvents = async () => {
    try {
      const res = await fetch("/api/timeline/events");
      const data = await res.json();
      setEvents(data);
      if (data.length > 0 && !selectedEventId) {
        setSelectedEventId(data[0].id);
      }
    } catch (err) {
      console.error("Failed to load timeline events", err);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, []);

  // Playback timer loop
  useEffect(() => {
    if (isPlaying) {
      intervalRef.current = setInterval(() => {
        setCurrentProgress((prev) => {
          if (prev >= 100) {
            setIsPlaying(false);
            return 100;
          }
          return Math.min(100, prev + 0.5 * playbackSpeed);
        });
      }, 200);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isPlaying, playbackSpeed]);

  const handleResetTimeline = async () => {
    try {
      const res = await fetch("/api/timeline/reset", { method: "POST" });
      const data = await res.json();
      setEvents(data);
      setCurrentProgress(0);
      setIsPlaying(false);
      if (data.length > 0) setSelectedEventId(data[0].id);
    } catch (err) {
      console.error(err);
    }
  };

  const domains: TimelineDomain[] = [
    "Cyber Host",
    "RF / SIGINT",
    "Tactical GIS",
    "Network DPI",
    "Defense SOAR"
  ];

  const getDomainColor = (d: TimelineDomain) => {
    switch (d) {
      case "Cyber Host":
        return { bg: "bg-rose-500/10", border: "border-rose-500/30", text: "text-rose-400", dot: "bg-rose-500" };
      case "RF / SIGINT":
        return { bg: "bg-amber-500/10", border: "border-amber-500/30", text: "text-amber-400", dot: "bg-amber-500" };
      case "Tactical GIS":
        return { bg: "bg-cyan-500/10", border: "border-cyan-500/30", text: "text-cyan-400", dot: "bg-cyan-500" };
      case "Network DPI":
        return { bg: "bg-indigo-500/10", border: "border-indigo-500/30", text: "text-indigo-400", dot: "bg-indigo-500" };
      case "Defense SOAR":
        return { bg: "bg-emerald-500/10", border: "border-emerald-500/30", text: "text-emerald-400", dot: "bg-emerald-500" };
    }
  };

  const filteredEvents = events.filter((ev) => {
    if (!ev) return false;
    const matchesDomain = domainFilter === "All" || ev.domain === domainFilter;
    const s = (searchTerm || "").toLowerCase();
    const matchesSearch =
      !s ||
      (ev.title || "").toLowerCase().includes(s) ||
      (ev.description || "").toLowerCase().includes(s) ||
      (ev.source_entity || "").toLowerCase().includes(s) ||
      (ev.mitre_ref && (ev.mitre_ref || "").toLowerCase().includes(s));
    return matchesDomain && matchesSearch;
  });

  const selectedEvent = events.find((e) => e.id === selectedEventId) || events[0];

  return (
    <div id="unified-timeline-tab" className="space-y-6">
      {/* Top Banner with Player Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-indigo-500/10 border border-indigo-500/30 rounded-xl text-indigo-400">
              <Clock className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-slate-100 tracking-wide">
                  Unified Cross-Domain Timeline & Temporal Scrubber
                </h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-400 border border-indigo-500/40">
                  MULTI-TRACK
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Synchronously replay, analyze, and correlate telemetry across Cyber Host, RF Spectrum, 3D GIS Bearings, and PCAP DPI flows.
              </p>
            </div>
          </div>

          {/* VCR / Scrubber Controls */}
          <div className="flex items-center gap-2">
            <button
              id="timeline-play-btn"
              onClick={() => setIsPlaying(!isPlaying)}
              className={`px-4 py-2 rounded-lg font-semibold text-xs flex items-center gap-2 shadow-lg transition-all cursor-pointer ${
                isPlaying
                  ? "bg-amber-600 hover:bg-amber-500 text-white shadow-amber-600/20"
                  : "bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-600/20"
              }`}
            >
              {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              {isPlaying ? "Pause Replay" : "Play Timeline"}
            </button>

            <div className="flex items-center bg-slate-800 rounded-lg p-0.5 border border-slate-700">
              {[0.5, 1, 2, 5].map((speed) => (
                <button
                  key={speed}
                  onClick={() => setPlaybackSpeed(speed)}
                  className={`px-2.5 py-1 text-xs font-mono rounded transition-all ${
                    playbackSpeed === speed
                      ? "bg-slate-700 text-cyan-400 font-bold shadow"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {speed}x
                </button>
              ))}
            </div>

            <button
              id="timeline-reset-btn"
              onClick={handleResetTimeline}
              className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1.5 border border-slate-700 transition-all cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset
            </button>
          </div>
        </div>

        {/* Temporal Scrubber Slider */}
        <div className="space-y-2">
          <div className="flex justify-between text-xs font-mono text-slate-400">
            <span>T-00:00:00 (Incident Genesis)</span>
            <span className="text-cyan-400 font-bold">
              Current Scrubber: {currentProgress.toFixed(1)}% Replayed
            </span>
            <span>T+03:00:00 (Final Eviction)</span>
          </div>

          <div className="relative">
            <input
              type="range"
              min="0"
              max="100"
              step="0.1"
              value={currentProgress}
              onChange={(e) => setCurrentProgress(Number(e.target.value))}
              className="w-full accent-indigo-500 cursor-pointer h-2 bg-slate-800 rounded-lg appearance-none"
            />
          </div>
        </div>
      </div>

      {/* Domain Filter Chips & Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/80 border border-slate-800 p-3 rounded-xl">
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setDomainFilter("All")}
            className={`px-3 py-1 text-xs font-medium rounded-lg border transition-all ${
              domainFilter === "All"
                ? "bg-indigo-600 border-indigo-500 text-white shadow-md shadow-indigo-600/20"
                : "bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200"
            }`}
          >
            All Tracks ({events.length})
          </button>
          {domains.map((d) => {
            const count = events.filter((e) => e.domain === d).length;
            const colors = getDomainColor(d);
            return (
              <button
                key={d}
                onClick={() => setDomainFilter(d)}
                className={`px-3 py-1 text-xs font-medium rounded-lg border transition-all flex items-center gap-1.5 ${
                  domainFilter === d
                    ? `${colors.bg} ${colors.border} ${colors.text} font-bold shadow-md`
                    : "bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200"
                }`}
              >
                <span className={`w-2 h-2 rounded-full ${colors.dot}`} />
                {d} ({count})
              </button>
            );
          })}
        </div>

        <div className="relative w-72">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search events, MITRE tags, entities..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 font-mono"
          />
        </div>
      </div>

      {/* Multi-Track Grid View */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Timeline Events Feed */}
        <div className="lg:col-span-7 space-y-3">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-400 px-1">
            Correlated Chronological Event Stream ({filteredEvents.length})
          </div>

          <div className="space-y-2.5">
            {filteredEvents.map((ev) => {
              const isSelected = ev.id === selectedEventId;
              const colors = getDomainColor(ev.domain);

              return (
                <div
                  key={ev.id}
                  id={`timeline-event-${ev.id}`}
                  onClick={() => setSelectedEventId(ev.id)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer flex flex-col gap-2 ${
                    isSelected
                      ? "bg-slate-800/90 border-indigo-500/80 shadow-lg shadow-indigo-950/30 ring-1 ring-indigo-500/40"
                      : "bg-slate-900/70 border-slate-800 hover:border-slate-700 hover:bg-slate-800/40"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${colors.bg} ${colors.border} ${colors.text} border`}>
                        {ev.domain}
                      </span>
                      <span className="font-bold text-xs text-slate-200 line-clamp-1">{ev.title}</span>
                    </div>

                    <span
                      className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold ${
                        ev.severity === "CRITICAL"
                          ? "bg-red-500/20 text-red-400 border border-red-500/30"
                          : ev.severity === "HIGH"
                          ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {ev.severity}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-2">{ev.description}</p>

                  <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-[11px] font-mono text-slate-400">
                    <span className="text-slate-500">{ev.timestamp.slice(11, 19)} UTC</span>
                    <span className="text-cyan-400 truncate max-w-[200px]">
                      {ev.source_entity} → {ev.target_entity}
                    </span>
                    {ev.mitre_ref && (
                      <span className="px-1.5 py-0.2 bg-red-950/40 border border-red-500/30 text-red-400 rounded">
                        {ev.mitre_ref}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Event Deep-Dive Inspector */}
        <div className="lg:col-span-5 space-y-4">
          {selectedEvent && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4 sticky top-6">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <span className={`w-3 h-3 rounded-full ${getDomainColor(selectedEvent.domain).dot}`} />
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                    {selectedEvent.domain} Inspector
                  </span>
                </div>
                <span className="text-[11px] font-mono text-slate-400">{selectedEvent.id}</span>
              </div>

              <div>
                <h3 className="text-sm font-bold text-slate-100">{selectedEvent.title}</h3>
                <p className="text-xs text-slate-400 mt-1">{selectedEvent.description}</p>
              </div>

              {/* Entity Flow Pair */}
              <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg font-mono text-xs space-y-2">
                <div className="flex justify-between items-center text-slate-400">
                  <span>Source Entity:</span>
                  <span className="text-cyan-300 font-semibold">{selectedEvent.source_entity}</span>
                </div>
                <div className="flex justify-between items-center text-slate-400">
                  <span>Target Entity:</span>
                  <span className="text-rose-300 font-semibold">{selectedEvent.target_entity}</span>
                </div>
                <div className="flex justify-between items-center text-slate-400">
                  <span>Timestamp:</span>
                  <span className="text-slate-300">{selectedEvent.timestamp}</span>
                </div>
              </div>

              {/* MITRE & D3FEND Correlations */}
              <div className="grid grid-cols-2 gap-2">
                {selectedEvent.mitre_ref && (
                  <div className="p-2.5 rounded-lg bg-red-950/20 border border-red-500/30">
                    <div className="text-[10px] font-mono uppercase text-red-400">MITRE ATT&CK</div>
                    <div className="text-xs font-bold text-slate-200 mt-0.5">{selectedEvent.mitre_ref}</div>
                  </div>
                )}
                {selectedEvent.d3fend_id && (
                  <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-500/30">
                    <div className="text-[10px] font-mono uppercase text-emerald-400">MITRE D3FEND</div>
                    <div className="text-xs font-bold text-slate-200 mt-0.5">{selectedEvent.d3fend_id}</div>
                  </div>
                )}
              </div>

              {/* Raw Telemetry Snippet */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">
                  Raw Event Telemetry JSON
                </div>
                <pre className="p-3 rounded-lg bg-black/90 border border-slate-800 font-mono text-[11px] text-emerald-400 overflow-x-auto max-h-48">
                  {JSON.stringify(selectedEvent.telemetry_snippet, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
