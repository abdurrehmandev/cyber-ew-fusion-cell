import React, { useEffect, useRef, useState } from "react";
import {
  Radio,
  Volume2,
  VolumeX,
  Play,
  Pause,
  Sliders,
  Activity,
  Waveform,
  Terminal,
  ShieldAlert,
  Zap,
  RotateCcw
} from "lucide-react";
import { DemodulatedSignalProfile, RadioDemodMode } from "../types";

interface Props {
  selectedSignal?: any | null;
}

const MORSE_MAP: Record<string, string> = {
  A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.", H: "....",
  I: "..", J: ".---", K: "-.-", L: ".-..", M: "--", N: "-.", O: "---", P: ".--.",
  Q: "--.-", R: ".-.", S: "...", T: "-", U: "..-", V: "...-", W: ".--", X: "-..-",
  Y: "-.--", Z: "--..", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
  "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.", "0": "-----"
};

export const TacticalRadioAudioDemodulator: React.FC<Props> = ({ selectedSignal }) => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [mode, setMode] = useState<RadioDemodMode>("NFM (Voice)");
  const [freqMHz, setFreqMHz] = useState(selectedSignal ? selectedSignal.freq_mhz : 433.92);
  const [volume, setVolume] = useState(0.4);
  const [squelchThresholdDb, setSquelchThresholdDb] = useState(-85);
  const [rogerBeep, setRogerBeep] = useState(true);
  const [morseMessage, setMorseMessage] = useState("CQ CQ TACTICAL EW INTERCEPT 0x9F4E");
  const [decodedTranscript, setDecodedTranscript] = useState<string[]>([
    "[04:15:02Z] RX LOCK: 433.920 MHz GFSK // Intercepted Hostile Telemetry Node",
    "[04:15:05Z] SQUELCH OPEN: Signal Strength -74 dBm (SNR +18.2 dB)",
    "[04:15:08Z] AFSK PACKET: SRC=UAV_RECON_04 DST=BASE_STATION_CMD [CRC: VALID]",
    "[04:15:12Z] TELEMETRY: WAYPOINT_LOCK=SUBSTATION_14 ALT=140m BATT=84%"
  ]);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const gainNodeRef = useRef<GainNode | null>(null);
  const activeNodesRef = useRef<{ osc?: OscillatorNode; noise?: AudioBufferSourceNode; filter?: BiquadFilterNode }[]>([]);
  const animFrameIdRef = useRef<number | null>(null);

  useEffect(() => {
    if (selectedSignal) {
      if (typeof selectedSignal.freq_mhz === "number") {
        setFreqMHz(selectedSignal.freq_mhz);
      }
      const proto = String(selectedSignal.protocol || selectedSignal.protocol_detected || "");
      const sigType = String(selectedSignal.signal_type || selectedSignal.modulation || selectedSignal.emitter_classification || "");
      if (proto.includes("Morse") || sigType.includes("CW")) {
        setMode("CW (Morse Code)");
      } else if (proto.includes("FHSS") || sigType.includes("FHSS") || sigType.includes("Hopping")) {
        setMode("FHSS (Frequency Hop)");
      } else if (proto.includes("Packet") || proto.includes("Telemetry") || sigType.includes("Digital") || sigType.includes("FSK")) {
        setMode("AFSK / APRS (Data)");
      } else {
        setMode("NFM (Voice)");
      }
    }
  }, [selectedSignal]);

  const initAudio = () => {
    if (!audioCtxRef.current) {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      const ctx = new AudioCtx();
      const analyser = ctx.createAnalyser();
      analyser.fftSize = 512;
      analyser.smoothingTimeConstant = 0.8;

      const masterGain = ctx.createGain();
      masterGain.gain.value = volume;
      masterGain.connect(analyser);
      analyser.connect(ctx.destination);

      audioCtxRef.current = ctx;
      analyserRef.current = analyser;
      gainNodeRef.current = masterGain;
    }

    if (audioCtxRef.current && audioCtxRef.current.state === "suspended") {
      audioCtxRef.current.resume();
    }
  };

  const stopAudioGenerators = () => {
    activeNodesRef.current.forEach(({ osc, noise }) => {
      try {
        if (osc) osc.stop();
        if (noise) noise.stop();
      } catch (e) {}
    });
    activeNodesRef.current = [];
  };

  const playRogerBeep = (ctx: AudioContext, dest: AudioNode) => {
    if (!rogerBeep) return;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(1750, ctx.currentTime);
    osc.frequency.setValueAtTime(1200, ctx.currentTime + 0.08);

    gain.gain.setValueAtTime(0.2, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.16);

    osc.connect(gain);
    gain.connect(dest);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.18);
  };

  const startDemodulationSound = () => {
    initAudio();
    const ctx = audioCtxRef.current;
    const masterGain = gainNodeRef.current;
    if (!ctx || !masterGain) return;

    stopAudioGenerators();

    if (mode === "NFM (Voice)") {
      // Create filtered radio noise + voice carrier tone
      const bufferSize = ctx.sampleRate * 2;
      const noiseBuffer = ctx.createBuffer(1, bufferSize, ctx.sampleRate);
      const output = noiseBuffer.getChannelData(0);
      for (let i = 0; i < bufferSize; i++) {
        output[i] = (Math.random() * 2 - 1) * 0.15;
      }

      const whiteNoise = ctx.createBufferSource();
      whiteNoise.buffer = noiseBuffer;
      whiteNoise.loop = true;

      const bandpass = ctx.createBiquadFilter();
      bandpass.type = "bandpass";
      bandpass.frequency.value = 1450;
      bandpass.Q.value = 2.5;

      const voiceGain = ctx.createGain();
      voiceGain.gain.value = 0.25;

      whiteNoise.connect(bandpass);
      bandpass.connect(voiceGain);
      voiceGain.connect(masterGain);
      whiteNoise.start();

      // Modulated voice-like harmonic tone
      const osc = ctx.createOscillator();
      const oscGain = ctx.createGain();
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(320, ctx.currentTime);

      const lfo = ctx.createOscillator();
      lfo.frequency.value = 4.5;
      const lfoGain = ctx.createGain();
      lfoGain.gain.value = 40;
      lfo.connect(lfoGain);
      lfoGain.connect(osc.frequency);
      lfo.start();

      oscGain.gain.value = 0.08;
      osc.connect(oscGain);
      oscGain.connect(masterGain);
      osc.start();

      activeNodesRef.current.push({ noise: whiteNoise, osc });
    } else if (mode === "CW (Morse Code)") {
      const osc = ctx.createOscillator();
      const cwGain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.value = 750; // Standard 750Hz CW sidetone

      cwGain.gain.setValueAtTime(0, ctx.currentTime);

      // Play Morse sequence
      let t = ctx.currentTime + 0.05;
      const dit = 0.06; // 60ms unit
      const cleanMsg = morseMessage.toUpperCase();

      for (let char of cleanMsg) {
        if (char === " ") {
          t += dit * 4;
          continue;
        }
        const code = MORSE_MAP[char] || "";
        for (let symbol of code) {
          const dur = symbol === "." ? dit : dit * 3;
          cwGain.gain.setValueAtTime(0.25, t);
          cwGain.gain.setValueAtTime(0, t + dur);
          t += dur + dit;
        }
        t += dit * 2;
      }

      osc.connect(cwGain);
      cwGain.connect(masterGain);
      osc.start();
      osc.stop(t + 0.2);

      activeNodesRef.current.push({ osc });
    } else if (mode === "AFSK / APRS (Data)") {
      // Bell 202 AFSK 1200/2200Hz FSK Burst
      const osc = ctx.createOscillator();
      const afskGain = ctx.createGain();
      osc.type = "sine";
      afskGain.gain.value = 0.2;

      let t = ctx.currentTime;
      for (let i = 0; i < 40; i++) {
        const isMark = Math.random() > 0.5;
        const freq = isMark ? 1200 : 2200;
        osc.frequency.setValueAtTime(freq, t);
        t += 0.015;
      }

      osc.connect(afskGain);
      afskGain.connect(masterGain);
      osc.start();
      osc.stop(t);

      activeNodesRef.current.push({ osc });
    } else if (mode === "FHSS (Frequency Hop)") {
      const osc = ctx.createOscillator();
      const hopGain = ctx.createGain();
      osc.type = "triangle";
      hopGain.gain.value = 0.22;

      let t = ctx.currentTime;
      const hopFrequencies = [450, 820, 1600, 950, 1320, 680, 2100, 1150];
      for (let i = 0; i < 50; i++) {
        const f = hopFrequencies[i % hopFrequencies.length];
        osc.frequency.setValueAtTime(f, t);
        t += 0.025;
      }

      osc.connect(hopGain);
      hopGain.connect(masterGain);
      osc.start();
      osc.stop(t);

      activeNodesRef.current.push({ osc });
    } else {
      // AM / WFM default
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.value = 1000;
      gain.gain.value = 0.15;
      osc.connect(gain);
      gain.connect(masterGain);
      osc.start();
      activeNodesRef.current.push({ osc });
    }

    setIsPlaying(true);
  };

  const handleTogglePlay = () => {
    if (isPlaying) {
      if (audioCtxRef.current && gainNodeRef.current) {
        playRogerBeep(audioCtxRef.current, gainNodeRef.current);
      }
      stopAudioGenerators();
      setIsPlaying(false);
    } else {
      startDemodulationSound();
    }
  };

  // Volume slider update
  const handleVolumeChange = (newVol: number) => {
    setVolume(newVol);
    if (gainNodeRef.current) {
      gainNodeRef.current.gain.value = newVol;
    }
  };

  // Render Oscilloscope & Spectrum on Canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const render = () => {
      const width = canvas.width;
      const height = canvas.height;

      // Dark background with tactical grid
      ctx.fillStyle = "#050b14";
      ctx.fillRect(0, 0, width, height);

      // Draw CRT Radar / Oscilloscope Reticle Grid
      ctx.strokeStyle = "#132338";
      ctx.lineWidth = 1;
      const stepX = width / 10;
      const stepY = height / 6;

      for (let x = 0; x <= width; x += stepX) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y <= height; y += stepY) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Center crosshairs
      ctx.strokeStyle = "#1e3a5f";
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(0, height / 2);
      ctx.lineTo(width, height / 2);
      ctx.moveTo(width / 2, 0);
      ctx.lineTo(width / 2, height);
      ctx.stroke();

      const analyser = analyserRef.current;
      if (analyser && isPlaying) {
        const timeData = new Uint8Array(analyser.frequencyBinCount);
        analyser.getByteTimeDomainData(timeData);

        // Draw Oscilloscope Beam (Emerald Phosphor Beam)
        ctx.lineWidth = 2;
        ctx.strokeStyle = "#10b981";
        ctx.shadowColor = "#10b981";
        ctx.shadowBlur = 8;
        ctx.beginPath();

        const sliceWidth = width / timeData.length;
        let x = 0;

        for (let i = 0; i < timeData.length; i++) {
          const v = timeData[i] / 128.0;
          const y = (v * height) / 2;

          if (i === 0) {
            ctx.moveTo(x, y);
          } else {
            ctx.lineTo(x, y);
          }
          x += sliceWidth;
        }

        ctx.stroke();
        ctx.shadowBlur = 0;

        // Draw Mini FFT Spectrum Bars at Bottom
        const freqData = new Uint8Array(analyser.frequencyBinCount);
        analyser.getByteFrequencyData(freqData);

        ctx.fillStyle = "rgba(6, 182, 212, 0.35)";
        const barWidth = (width / (freqData.length / 2)) * 1.5;
        let barX = 0;

        for (let i = 0; i < freqData.length / 2; i++) {
          const barHeight = (freqData[i] / 255) * (height * 0.4);
          ctx.fillRect(barX, height - barHeight, barWidth - 1, barHeight);
          barX += barWidth;
        }
      } else {
        // Flat baseline trace when idle
        ctx.lineWidth = 1.5;
        ctx.strokeStyle = "#059669";
        ctx.beginPath();
        ctx.moveTo(0, height / 2);
        ctx.lineTo(width, height / 2);
        ctx.stroke();

        ctx.fillStyle = "#64748b";
        ctx.font = "11px 'JetBrains Mono', monospace";
        ctx.textAlign = "center";
        ctx.fillText("AUDIO DSP IDLE // PRESS DEMODULATE TO ENGAGE RX SYNTHESIZER", width / 2, height / 2 - 12);
      }

      animFrameIdRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      if (animFrameIdRef.current) cancelAnimationFrame(animFrameIdRef.current);
    };
  }, [isPlaying]);

  return (
    <div id="tactical-radio-audio-demodulator" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-100 tracking-wide">
                Tactical RF Audio Demodulator & DSP Oscilloscope
              </h3>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                isPlaying ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40" : "bg-slate-800 text-slate-400 border-slate-700"
              }`}>
                {isPlaying ? "RX ACTIVE // DEMODULATING" : "RX STANDBY"}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Real-time software-defined radio (SDR) audio demodulation, CW Morse decoding, and CRT waveform analysis.
            </p>
          </div>
        </div>

        {/* Master Audio Engagement Controls */}
        <div className="flex items-center gap-2">
          <button
            id="demod-play-toggle-btn"
            onClick={handleTogglePlay}
            className={`px-4 py-2 rounded-lg text-xs font-bold font-mono flex items-center gap-2 shadow-lg transition-all cursor-pointer ${
              isPlaying
                ? "bg-red-600 hover:bg-red-500 text-white shadow-red-600/20"
                : "bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-600/20"
            }`}
          >
            {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
            {isPlaying ? "Mute Demodulator" : "Demodulate Signal"}
          </button>
        </div>
      </div>

      {/* Main Grid: Visual Oscilloscope + Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left: 60 FPS CRT Oscilloscope & FFT Canvas */}
        <div className="lg:col-span-2 space-y-3">
          <div className="relative rounded-xl overflow-hidden border border-slate-800 bg-slate-950 shadow-inner">
            <div className="absolute top-2.5 left-3 flex items-center gap-3 z-10 font-mono text-[10px] text-emerald-400 bg-black/60 px-2.5 py-1 rounded border border-emerald-500/30">
              <Activity className="w-3.5 h-3.5" />
              <span>CH1: {freqMHz.toFixed(3)} MHz</span>
              <span className="text-cyan-400">MODE: {mode}</span>
              <span className="text-amber-400">GAIN: {(volume * 100).toFixed(0)}%</span>
            </div>

            <canvas
              ref={canvasRef}
              width={640}
              height={220}
              className="w-full h-[220px] block"
            />
          </div>

          {/* Mode Selector Buttons */}
          <div className="flex flex-wrap items-center gap-1.5 bg-slate-950/80 p-2 rounded-xl border border-slate-800">
            {(["NFM (Voice)", "CW (Morse Code)", "AFSK / APRS (Data)", "FHSS (Frequency Hop)", "AM (Airband)"] as RadioDemodMode[]).map((m) => (
              <button
                key={m}
                onClick={() => {
                  setMode(m);
                  if (isPlaying) {
                    setTimeout(() => startDemodulationSound(), 50);
                  }
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer ${
                  mode === m
                    ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
                }`}
              >
                {m}
              </button>
            ))}
          </div>
        </div>

        {/* Right: DSP Tuning & Demod Parameter Knobs */}
        <div className="space-y-4 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
          <div>
            <div className="flex items-center justify-between text-xs font-mono text-slate-300 mb-1">
              <span className="flex items-center gap-1.5"><Volume2 className="w-3.5 h-3.5 text-emerald-400" /> Audio Sidetone Gain</span>
              <span className="text-emerald-400">{(volume * 100).toFixed(0)}%</span>
            </div>
            <input
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={volume}
              onChange={(e) => handleVolumeChange(parseFloat(e.target.value))}
              className="w-full accent-emerald-500 cursor-pointer"
            />
          </div>

          <div>
            <div className="flex items-center justify-between text-xs font-mono text-slate-300 mb-1">
              <span className="flex items-center gap-1.5"><Sliders className="w-3.5 h-3.5 text-cyan-400" /> Squelch Threshold</span>
              <span className="text-cyan-400">{squelchThresholdDb} dBm</span>
            </div>
            <input
              type="range"
              min="-120"
              max="-50"
              step="1"
              value={squelchThresholdDb}
              onChange={(e) => setSquelchThresholdDb(parseInt(e.target.value))}
              className="w-full accent-cyan-500 cursor-pointer"
            />
          </div>

          {/* Toggle Switches */}
          <div className="pt-2 border-t border-slate-800 space-y-2">
            <label className="flex items-center justify-between cursor-pointer">
              <span className="text-xs text-slate-300 font-mono">CTCSS Roger Beep</span>
              <input
                type="checkbox"
                checked={rogerBeep}
                onChange={(e) => setRogerBeep(e.target.checked)}
                className="w-4 h-4 accent-emerald-500 rounded cursor-pointer"
              />
            </label>
          </div>

          {/* CW Morse Code Custom Input when in CW mode */}
          {mode === "CW (Morse Code)" && (
            <div className="pt-2 border-t border-slate-800 space-y-1.5">
              <label className="text-[11px] font-mono text-slate-400 block">Morse Message Stream</label>
              <input
                type="text"
                value={morseMessage}
                onChange={(e) => setMorseMessage(e.target.value)}
                className="w-full px-2.5 py-1 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-amber-300 focus:outline-none focus:border-amber-500"
              />
            </div>
          )}

          {/* Signal Intercept Metas */}
          <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
            <div className="flex justify-between">
              <span>Tuned Freq:</span>
              <span className="text-emerald-400 font-bold">{freqMHz.toFixed(3)} MHz</span>
            </div>
            <div className="flex justify-between">
              <span>Filter Bandwidth:</span>
              <span className="text-slate-200">12.5 kHz (Narrow)</span>
            </div>
            <div className="flex justify-between">
              <span>Squelch State:</span>
              <span className="text-emerald-400 font-bold">OPEN (Carrier Detected)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Decoded Bitstream & Live Transcript Terminal */}
      <div className="p-3.5 rounded-xl bg-black/80 border border-slate-800 space-y-2">
        <div className="flex items-center justify-between text-xs font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span className="text-slate-200 font-bold">Real-Time Demodulated Bitstream Transcript</span>
          </div>
          <span className="text-[10px] text-slate-500">Auto-decoding GFSK / AFSK 1200bps</span>
        </div>
        <div className="font-mono text-xs text-emerald-400 space-y-1 max-h-28 overflow-y-auto">
          {decodedTranscript.map((line, idx) => (
            <div key={idx} className="truncate">{line}</div>
          ))}
        </div>
      </div>
    </div>
  );
};
