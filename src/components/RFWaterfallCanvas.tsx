import React, { useEffect, useRef, useState } from "react";
import { Play, Pause, RefreshCw, Layers, ZoomIn, ZoomOut, Zap } from "lucide-react";

interface RFWaterfallCanvasProps {
  centerFreqMHz?: number;
  bandwidthMHz?: number;
  isJammingActive?: boolean;
}

export const RFWaterfallCanvas: React.FC<RFWaterfallCanvasProps> = ({
  centerFreqMHz = 433.92,
  bandwidthMHz = 2.0,
  isJammingActive = false,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [isRunning, setIsRunning] = useState(true);
  const [colorMap, setColorMap] = useState<"inferno" | "plasma" | "tactical" | "viridis">("tactical");
  const [gainDb, setGainDb] = useState(24);
  const [fftRateMs, setFftRateMs] = useState(30);
  const animationFrameRef = useRef<number | null>(null);
  const historyRef = useRef<Uint8ClampedArray[]>([]);

  // Generate color palette LUT
  const getColormapRgb = (value: number, map: string): [number, number, number] => {
    const v = Math.min(255, Math.max(0, value)) / 255;
    if (map === "tactical") {
      // Dark slate -> bright emerald green -> hot neon cyan / white
      if (v < 0.2) return [10, Math.floor(v * 5 * 60), 20];
      if (v < 0.6) return [16, Math.floor(60 + (v - 0.2) * 2.5 * 180), 80];
      if (v < 0.85) return [Math.floor((v - 0.6) * 4 * 200), 245, 140];
      return [220, 255, Math.floor(200 + (v - 0.85) * 6.6 * 55)];
    } else if (map === "inferno") {
      // Black -> Purple -> Orange -> Yellow -> White
      if (v < 0.25) return [Math.floor(v * 4 * 80), 0, Math.floor(v * 4 * 100)];
      if (v < 0.5) return [Math.floor(80 + (v - 0.25) * 4 * 140), 20, 100];
      if (v < 0.75) return [230, Math.floor(20 + (v - 0.5) * 4 * 160), 20];
      return [255, Math.floor(180 + (v - 0.75) * 4 * 75), Math.floor((v - 0.75) * 4 * 255)];
    } else if (map === "plasma") {
      // Navy -> Violet -> Pink -> Yellow
      if (v < 0.33) return [Math.floor(v * 3 * 120), 10, 180];
      if (v < 0.66) return [200, Math.floor((v - 0.33) * 3 * 80), 140];
      return [255, Math.floor(120 + (v - 0.66) * 3 * 135), 40];
    } else {
      // Viridis
      if (v < 0.3) return [30, Math.floor(v * 3.3 * 80), 100];
      if (v < 0.7) return [40, Math.floor(80 + (v - 0.3) * 2.5 * 140), 90];
      return [Math.floor(40 + (v - 0.7) * 3.3 * 210), 220, 40];
    }
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;
    let lastTime = 0;
    let phase = 0;

    const render = (time: number) => {
      if (!isRunning) {
        animationFrameRef.current = requestAnimationFrame(render);
        return;
      }

      if (time - lastTime >= fftRateMs) {
        lastTime = time;
        phase += 0.08;

        // Generate synthetic FFT bin line (width elements)
        const rowData = new Uint8ClampedArray(width);
        const noiseFloor = 30 + Math.random() * 15;

        for (let x = 0; x < width; x++) {
          const normX = x / width;
          let power = noiseFloor + Math.random() * 8;

          // Main carrier / signals
          const signal1Center = 0.48 + Math.sin(phase * 0.4) * 0.05;
          const dist1 = Math.abs(normX - signal1Center);
          if (dist1 < 0.04) {
            power += (1 - dist1 / 0.04) * (140 + Math.sin(phase * 2 + x * 0.1) * 30);
          }

          // Secondary frequency-hopping signal
          const hopCenter = 0.2 + ((Math.floor(phase * 3) % 7) / 8) * 0.6;
          const dist2 = Math.abs(normX - hopCenter);
          if (dist2 < 0.02) {
            power += (1 - dist2 / 0.02) * (180 + Math.random() * 40);
          }

          // Jamming burst
          if (isJammingActive) {
            const jamDist = Math.abs(normX - 0.5);
            if (jamDist < 0.25) {
              power += (1 - jamDist / 0.25) * (120 + Math.random() * 80);
            }
          }

          // Apply gain
          const scaledPower = Math.min(255, power * (gainDb / 20));
          rowData[x] = scaledPower;
        }

        // Shift history
        historyRef.current.unshift(rowData);
        if (historyRef.current.length > height) {
          historyRef.current.pop();
        }

        // Draw image data
        const imgData = ctx.createImageData(width, height);
        const data = imgData.data;

        for (let y = 0; y < historyRef.current.length; y++) {
          const row = historyRef.current[y];
          for (let x = 0; x < width; x++) {
            const val = row[x];
            const [r, g, b] = getColormapRgb(val, colorMap);
            const pixelIdx = (y * width + x) * 4;
            data[pixelIdx] = r;
            data[pixelIdx + 1] = g;
            data[pixelIdx + 2] = b;
            data[pixelIdx + 3] = 255;
          }
        }

        ctx.putImageData(imgData, 0, 0);

        // Draw frequency scale grid overlay
        ctx.strokeStyle = "rgba(255, 255, 255, 0.12)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        for (let i = 1; i < 5; i++) {
          const x = (width / 5) * i;
          ctx.moveTo(x, 0);
          ctx.lineTo(x, height);
        }
        ctx.stroke();

        // Draw center frequency marker
        ctx.strokeStyle = "rgba(239, 68, 68, 0.6)";
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(width / 2, 0);
        ctx.lineTo(width / 2, height);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      animationFrameRef.current = requestAnimationFrame(render);
    };

    animationFrameRef.current = requestAnimationFrame(render);

    return () => {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
    };
  }, [isRunning, colorMap, gainDb, fftRateMs, isJammingActive]);

  const minFreq = (centerFreqMHz - bandwidthMHz / 2).toFixed(2);
  const maxFreq = (centerFreqMHz + bandwidthMHz / 2).toFixed(2);

  return (
    <div id="rf-waterfall-card" className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col">
      {/* Header bar */}
      <div className="px-4 py-3 bg-slate-950/80 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Zap className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-bold text-slate-200 tracking-wide uppercase flex items-center gap-2">
              HW-Accelerated RF Spectrogram Waterfall (60 FPS)
              {isJammingActive && (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse">
                  JAMMING DETECTED
                </span>
              )}
            </div>
            <div className="text-[11px] text-slate-400 font-mono">
              Center: {centerFreqMHz.toFixed(2)} MHz | Span: {bandwidthMHz.toFixed(2)} MHz | FFT Resolution: 512 bins
            </div>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2">
          <button
            id="rf-waterfall-toggle-play"
            onClick={() => setIsRunning(!isRunning)}
            className={`px-2.5 py-1 text-xs font-semibold rounded-lg border transition-colors flex items-center gap-1.5 ${
              isRunning
                ? "bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700"
                : "bg-emerald-600 border-emerald-500 text-white"
            }`}
          >
            {isRunning ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            {isRunning ? "Pause" : "Resume"}
          </button>

          <div className="flex items-center bg-slate-800 rounded-lg p-0.5 border border-slate-700">
            {(["tactical", "inferno", "plasma", "viridis"] as const).map((map) => (
              <button
                key={map}
                onClick={() => setColorMap(map)}
                className={`px-2 py-1 text-[11px] font-mono rounded capitalize transition-all ${
                  colorMap === map
                    ? "bg-slate-700 text-emerald-400 font-semibold shadow-sm"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {map}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5 bg-slate-800/80 px-2 py-1 rounded-lg border border-slate-700 text-[11px] font-mono text-slate-300">
            <span>Gain:</span>
            <input
              type="range"
              min="10"
              max="40"
              value={gainDb}
              onChange={(e) => setGainDb(Number(e.target.value))}
              className="w-16 accent-emerald-500 cursor-pointer h-1"
            />
            <span className="w-7 text-right">{gainDb}dB</span>
          </div>
        </div>
      </div>

      {/* Waterfall Canvas Display */}
      <div className="relative bg-black flex-1 flex flex-col items-center justify-center p-2">
        <canvas
          ref={canvasRef}
          width={540}
          height={220}
          className="w-full h-56 rounded border border-slate-800/80 bg-black block"
        />

        {/* Frequency Axis Marker Bar */}
        <div className="w-full flex justify-between px-2 pt-1 text-[10px] font-mono text-slate-400 border-t border-slate-800/60 mt-1">
          <span>{minFreq} MHz</span>
          <span>{(centerFreqMHz - bandwidthMHz / 4).toFixed(2)} MHz</span>
          <span className="text-red-400 font-bold">{centerFreqMHz.toFixed(2)} MHz (Fc)</span>
          <span>{(centerFreqMHz + bandwidthMHz / 4).toFixed(2)} MHz</span>
          <span>{maxFreq} MHz</span>
        </div>
      </div>
    </div>
  );
};
