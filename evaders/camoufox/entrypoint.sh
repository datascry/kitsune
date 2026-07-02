#!/bin/sh
# evaders/camoufox/entrypoint — provision the container's ENVIRONMENT (real audio/TTS) + display, then run.
# KS_PROVISION gives real (not JS-faked) devices/voices so the environment-floor tells go silent coherently.
set -e

if [ "$KS_PROVISION" = "1" ]; then
  export XDG_RUNTIME_DIR=/tmp/xdg
  mkdir -p "$XDG_RUNTIME_DIR"
  # Real audio hardware: a PulseAudio daemon with a null sink + null source, exposed over an ANONYMOUS-auth
  # unix socket so the root browser can connect (system mode otherwise restricts to the pulse-access group —
  # the barrier the first attempt hit). Firefox reads PULSE_SERVER and enumerates the devices NATIVELY, so
  # br.media_devices_empty goes silent WITHOUT a JS fake (which coherence would catch).
  pulseaudio --system --daemonize --disallow-exit \
    -L "module-null-sink sink_name=spk" \
    -L "module-null-source source_name=mic" \
    -L "module-native-protocol-unix auth-anonymous=1 socket=/tmp/pulse.sock" >/dev/null 2>&1 || true
  export PULSE_SERVER=unix:/tmp/pulse.sock
  # Real TTS voices: speech-dispatcher (espeak-ng backend) gives Firefox's Web Speech getVoices() a real,
  # OS-coherent (Linux) voice set → br.voices_empty silent WITHOUT a JS patch.
  speech-dispatcher -d >/dev/null 2>&1 || true
fi

if [ "$KS_REAL_INPUT" = "1" ]; then
  # Headful on a real Xvfb display (xvfb-run's readiness probe hangs on this base image) so XTEST input lands.
  Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp >/dev/null 2>&1 &
  sleep 2
  export DISPLAY=:99
fi

exec python /run.py
