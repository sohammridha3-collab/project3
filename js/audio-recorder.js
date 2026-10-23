/* ==========================================================================
   ScamShield AI — Audio Recorder & In-Browser PCM WAV Normalizer
   Captures microphone audio, boosts low-voice recordings, and normalizes
   uploaded call audio to clean 16kHz 16-bit mono WAV.
   Zero external libraries required (Pure Web Audio API)
   ========================================================================== */

(function () {
  "use strict";

  // Encodes raw Float32Array PCM samples into standard RIFF WAV Blob
  function encodeWAV(samples, sampleRate) {
    const buffer = new ArrayBuffer(44 + samples.length * 2);
    const view = new DataView(buffer);

    // RIFF chunk descriptor
    writeString(view, 0, "RIFF");
    view.setUint32(4, 36 + samples.length * 2, true);
    writeString(view, 8, "WAVE");

    // "fmt " sub-chunk
    writeString(view, 12, "fmt ");
    view.setUint32(16, 16, true); // Subchunk1Size (16 for PCM)
    view.setUint16(20, 1, true);  // AudioFormat (1 for PCM)
    view.setUint16(22, 1, true);  // NumChannels (1 for Mono)
    view.setUint32(24, sampleRate, true); // SampleRate
    view.setUint32(28, sampleRate * 2, true); // ByteRate (SampleRate * NumChannels * BitsPerSample/8)
    view.setUint16(32, 2, true);  // BlockAlign (NumChannels * BitsPerSample/8)
    view.setUint16(34, 16, true); // BitsPerSample (16-bit)

    // "data" sub-chunk
    writeString(view, 36, "data");
    view.setUint32(40, samples.length * 2, true);

    // Write PCM samples (float to signed 16-bit int)
    let offset = 44;
    for (let i = 0; i < samples.length; i++, offset += 2) {
      let s = Math.max(-1, Math.min(1, samples[i]));
      view.setInt16(offset, s < 0 ? s * 0x8000 : s * 0x7FFF, true);
    }

    return new Blob([view], { type: "audio/wav" });
  }

  function writeString(view, offset, string) {
    for (let i = 0; i < string.length; i++) {
      view.setUint8(offset + i, string.charCodeAt(i));
    }
  }

  // Downsamples an AudioBuffer to target sample rate (default 16000 Hz)
  function downsampleAudioBuffer(audioBuffer, targetSampleRate = 16000) {
    const sourceData = audioBuffer.getChannelData(0); // Use first channel
    if (audioBuffer.sampleRate === targetSampleRate) {
      return sourceData;
    }
    const ratio = audioBuffer.sampleRate / targetSampleRate;
    const newLength = Math.round(sourceData.length / ratio);
    const result = new Float32Array(newLength);
    let offsetResult = 0;
    let offsetSource = 0;

    while (offsetResult < result.length) {
      const nextOffsetSource = Math.round((offsetResult + 1) * ratio);
      let accum = 0;
      let count = 0;
      for (let i = offsetSource; i < nextOffsetSource && i < sourceData.length; i++) {
        accum += sourceData[i];
        count++;
      }
      result[offsetResult] = count > 0 ? accum / count : 0;
      offsetResult++;
      offsetSource = nextOffsetSource;
    }
    return result;
  }

  // Automatic Gain Control (AGC) & Peak Normalization for Low-Voice and Quiet Call Audio
  function normalizePcmSamples(samples, targetPeak = 0.92, maxBoost = 15.0) {
    let peak = 0;
    for (let i = 0; i < samples.length; i++) {
      const abs = Math.abs(samples[i]);
      if (abs > peak) peak = abs;
    }

    // Only amplify if sound is non-zero (above ambient silence threshold 0.002)
    if (peak > 0.002) {
      const gainFactor = Math.min(targetPeak / peak, maxBoost);
      if (gainFactor > 1.05) {
        const output = new Float32Array(samples.length);
        for (let i = 0; i < samples.length; i++) {
          const scaled = samples[i] * gainFactor;
          // Soft clamp to avoid harsh digital clipping
          output[i] = Math.max(-1, Math.min(1, scaled));
        }
        return {
          samples: output,
          boosted: true,
          factor: Math.round(gainFactor * 10) / 10,
          originalPeak: peak
        };
      }
    }

    return {
      samples: samples,
      boosted: false,
      factor: 1.0,
      originalPeak: peak
    };
  }

  // Audio Recorder Class
  class ScamAudioRecorder {
    constructor(options = {}) {
      this.stream = null;
      this.audioContext = null;
      this.scriptProcessor = null;
      this.audioSource = null;
      this.gainNode = null;
      this.analyser = null;
      this.muteNode = null;
      this.recordedChunks = [];
      this.isRecording = false;
      this.timerInterval = null;
      this.elapsedSeconds = 0;

      // Gain multiplier (default 2.5x pre-amplification for low voices / call recordings)
      this.gainMultiplier = typeof options.gain === "number" ? options.gain : 2.5;
      this.autoBoost = options.autoBoost !== false;

      this.onTick = null;
      this.onStop = null;
      this.onError = null;
      this.onLevel = null; // Real-time volume meter & voice detector callback
    }

    setGain(multiplier) {
      this.gainMultiplier = Math.max(0.5, Math.min(10.0, multiplier));
      if (this.gainNode && this.audioContext) {
        try {
          this.gainNode.gain.setValueAtTime(this.gainMultiplier, this.audioContext.currentTime);
        } catch (e) {
          this.gainNode.gain.value = this.gainMultiplier;
        }
      }
    }

    async start() {
      if (this.isRecording) return;

      try {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
          throw new Error("Microphone recording is not supported in this browser environment.");
        }

        // Request audio with optimal speech recognition settings
        // Disabling noiseSuppression prevents webRTC from cutting quiet voices & whispers
        let stream = null;
        try {
          stream = await navigator.mediaDevices.getUserMedia({
            audio: {
              channelCount: 1,
              echoCancellation: true,
              noiseSuppression: false, // Critical: keeps low voice and soft calls intact
              autoGainControl: true,   // System/hardware auto-gain
              googAutoGainControl: true,
              googNoiseSuppression: false,
              googHighpassFilter: false
            }
          });
        } catch (e) {
          // Fallback to basic audio constraint if device doesn't support advanced keys
          stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        }
        this.stream = stream;

        const AudioContextClass = window.AudioContext || window.webkitAudioContext;
        this.audioContext = new AudioContextClass();
        if (this.audioContext.state === "suspended") {
          await this.audioContext.resume();
        }

        this.audioSource = this.audioContext.createMediaStreamSource(this.stream);

        // Hardware/Software Gain Booster Node for low voice & call recordings
        this.gainNode = this.audioContext.createGain();
        this.gainNode.gain.setValueAtTime(this.gainMultiplier, this.audioContext.currentTime);

        // Analyser node for live volume VU meter
        this.analyser = this.audioContext.createAnalyser();
        this.analyser.fftSize = 512;
        this.analyser.smoothingTimeConstant = 0.3;

        // ScriptProcessorNode to capture raw PCM samples
        this.scriptProcessor = this.audioContext.createScriptProcessor(4096, 1, 1);
        this.recordedChunks = [];

        this.scriptProcessor.onaudioprocess = e => {
          if (!this.isRecording) return;
          const input = e.inputBuffer.getChannelData(0);
          this.recordedChunks.push(new Float32Array(input));

          // Calculate real-time RMS and peak volume
          let sumSquares = 0;
          let maxAbs = 0;
          for (let i = 0; i < input.length; i++) {
            const val = input[i];
            const absVal = Math.abs(val);
            if (absVal > maxAbs) maxAbs = absVal;
            sumSquares += val * val;
          }
          const rms = Math.sqrt(sumSquares / input.length);
          const rmsPercent = Math.min(100, Math.round(rms * 450));
          const peakPercent = Math.min(100, Math.round(maxAbs * 125));
          const isVoice = rms > 0.006 || maxAbs > 0.025;
          const isLowVoice = isVoice && (maxAbs < 0.2 || rms < 0.04);

          if (typeof this.onLevel === "function") {
            this.onLevel({
              rmsPercent,
              peakPercent,
              isVoice,
              isLowVoice,
              rms,
              maxAbs
            });
          }
        };

        // Connect chain: source -> gain -> analyser -> scriptProcessor -> muteNode -> destination
        this.audioSource.connect(this.gainNode);
        this.gainNode.connect(this.analyser);
        this.analyser.connect(this.scriptProcessor);

        // Silent node before destination prevents speaker feedback while keeping processor active
        this.muteNode = this.audioContext.createGain();
        this.muteNode.gain.setValueAtTime(0, this.audioContext.currentTime);
        this.scriptProcessor.connect(this.muteNode);
        this.muteNode.connect(this.audioContext.destination);

        this.isRecording = true;
        this.elapsedSeconds = 0;

        // Timer
        this.timerInterval = setInterval(() => {
          this.elapsedSeconds++;
          if (typeof this.onTick === "function") {
            const mins = String(Math.floor(this.elapsedSeconds / 60)).padStart(2, "0");
            const secs = String(this.elapsedSeconds % 60).padStart(2, "0");
            this.onTick(this.elapsedSeconds, `${mins}:${secs}`);
          }
        }, 1000);

      } catch (err) {
        this.cleanup();
        if (err.name === "NotAllowedError" || err.name === "PermissionDeniedError") {
          throw new Error("Microphone access was denied. Please grant microphone permission in your browser to record audio.");
        }
        throw err;
      }
    }

    stop() {
      if (!this.isRecording) return;

      clearInterval(this.timerInterval);
      this.isRecording = false;

      // Concatenate raw chunks
      let totalLength = 0;
      this.recordedChunks.forEach(chunk => totalLength += chunk.length);
      const fullBuffer = new Float32Array(totalLength);
      let offset = 0;
      this.recordedChunks.forEach(chunk => {
        fullBuffer.set(chunk, offset);
        offset += chunk.length;
      });

      // Downsample to 16 kHz
      const originalRate = this.audioContext ? this.audioContext.sampleRate : 44100;
      const fakeAudioBuffer = {
        sampleRate: originalRate,
        getChannelData: () => fullBuffer
      };
      const downsampledSamples = downsampleAudioBuffer(fakeAudioBuffer, 16000);

      // Dynamic Auto-Gain Normalization for Low Voice and Quiet Audio
      const norm = normalizePcmSamples(downsampledSamples, 0.92, 15.0);

      // Create standard WAV Blob
      const wavBlob = encodeWAV(norm.samples, 16000);
      const duration = Math.round((norm.samples.length / 16000) * 10) / 10;

      this.cleanup();

      const result = {
        blob: wavBlob,
        duration: duration,
        boosted: norm.boosted,
        boostFactor: norm.factor,
        originalPeak: norm.originalPeak
      };

      if (typeof this.onStop === "function") {
        this.onStop(wavBlob, duration, result);
      }

      return result;
    }

    cleanup() {
      this.isRecording = false;
      if (this.timerInterval) clearInterval(this.timerInterval);
      if (this.scriptProcessor) {
        this.scriptProcessor.disconnect();
        this.scriptProcessor = null;
      }
      if (this.muteNode) {
        this.muteNode.disconnect();
        this.muteNode = null;
      }
      if (this.analyser) {
        this.analyser.disconnect();
        this.analyser = null;
      }
      if (this.gainNode) {
        this.gainNode.disconnect();
        this.gainNode = null;
      }
      if (this.audioSource) {
        this.audioSource.disconnect();
        this.audioSource = null;
      }
      if (this.audioContext) {
        this.audioContext.close();
        this.audioContext = null;
      }
      if (this.stream) {
        this.stream.getTracks().forEach(track => track.stop());
        this.stream = null;
      }
      this.recordedChunks = [];
    }
  }

  // Converts any uploaded audio file (MP3, M4A, WebM, OGG, WAV) to a normalized 16kHz PCM WAV Blob
  // Automatically amplifies quiet call recordings
  async function normalizeAudioFileToWav(file) {
    const arrayBuffer = await file.arrayBuffer();
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    const ctx = new AudioContextClass();

    try {
      const decodedBuffer = await ctx.decodeAudioData(arrayBuffer);
      const downsampledSamples = downsampleAudioBuffer(decodedBuffer, 16000);
      const norm = normalizePcmSamples(downsampledSamples, 0.92, 15.0);
      const wavBlob = encodeWAV(norm.samples, 16000);
      const duration = Math.round((norm.samples.length / 16000) * 10) / 10;
      return {
        blob: wavBlob,
        duration: duration,
        boosted: norm.boosted,
        boostFactor: norm.factor,
        originalPeak: norm.originalPeak
      };
    } finally {
      ctx.close();
    }
  }

  // Expose to window.ScamAudio
  window.ScamAudio = Object.freeze({
    Recorder: ScamAudioRecorder,
    normalizeAudioFileToWav: normalizeAudioFileToWav,
    normalizePcmSamples: normalizePcmSamples
  });

})();
