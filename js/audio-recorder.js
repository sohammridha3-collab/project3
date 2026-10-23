/* ==========================================================================
   ScamShield AI — Audio Recorder & In-Browser PCM WAV Normalizer
   Captures microphone audio and converts uploads to clean 16kHz 16-bit mono WAV
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

  // Audio Recorder Class
  class ScamAudioRecorder {
    constructor() {
      this.stream = null;
      this.audioContext = null;
      this.scriptProcessor = null;
      this.audioSource = null;
      this.recordedChunks = [];
      this.isRecording = false;
      this.timerInterval = null;
      this.elapsedSeconds = 0;

      this.onTick = null;
      this.onStop = null;
      this.onError = null;
    }

    async start() {
      if (this.isRecording) return;

      try {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
          throw new Error("Microphone recording is not supported in this browser environment.");
        }

        // Request permission explicitly
        this.stream = await navigator.mediaDevices.getUserMedia({
          audio: {
            channelCount: 1,
            echoCancellation: true,
            noiseSuppression: true
          }
        });

        const AudioContextClass = window.AudioContext || window.webkitAudioContext;
        this.audioContext = new AudioContextClass();
        this.audioSource = this.audioContext.createMediaStreamSource(this.stream);
        
        // Use ScriptProcessorNode to capture raw PCM samples
        this.scriptProcessor = this.audioContext.createScriptProcessor(4096, 1, 1);
        this.recordedChunks = [];

        this.scriptProcessor.onaudioprocess = e => {
          if (!this.isRecording) return;
          const input = e.inputBuffer.getChannelData(0);
          this.recordedChunks.push(new Float32Array(input));
        };

        this.audioSource.connect(this.scriptProcessor);
        this.scriptProcessor.connect(this.audioContext.destination);

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
          throw new Error("Microphone access was denied. Please grant permission in your browser to record audio.");
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

      // Create standard WAV Blob
      const wavBlob = encodeWAV(downsampledSamples, 16000);
      const duration = Math.round((downsampledSamples.length / 16000) * 10) / 10;

      this.cleanup();

      if (typeof this.onStop === "function") {
        this.onStop(wavBlob, duration);
      }

      return { blob: wavBlob, duration };
    }

    cleanup() {
      this.isRecording = false;
      if (this.timerInterval) clearInterval(this.timerInterval);
      if (this.scriptProcessor) {
        this.scriptProcessor.disconnect();
        this.scriptProcessor = null;
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
  async function normalizeAudioFileToWav(file) {
    const arrayBuffer = await file.arrayBuffer();
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    const ctx = new AudioContextClass();

    try {
      const decodedBuffer = await ctx.decodeAudioData(arrayBuffer);
      const downsampledSamples = downsampleAudioBuffer(decodedBuffer, 16000);
      const wavBlob = encodeWAV(downsampledSamples, 16000);
      const duration = Math.round((downsampledSamples.length / 16000) * 10) / 10;
      return { blob: wavBlob, duration };
    } finally {
      ctx.close();
    }
  }

  // Expose to window.ScamAudio
  window.ScamAudio = Object.freeze({
    Recorder: ScamAudioRecorder,
    normalizeAudioFileToWav: normalizeAudioFileToWav
  });

})();
