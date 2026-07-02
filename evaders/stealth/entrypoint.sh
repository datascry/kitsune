#!/bin/sh
# evaders/stealth/entrypoint — provision the container ENVIRONMENT (real audio/TTS) then run the driver.
# KS_PROVISION gives Chromium real (not JS-faked) devices/voices so the environment-floor tells go silent coherently.
set -e

if [ "$KS_PROVISION" = "1" ]; then
  export XDG_RUNTIME_DIR=/tmp/xdg
  mkdir -p "$XDG_RUNTIME_DIR"
  # Real audio hardware over an anonymous-auth PulseAudio socket (system mode otherwise restricts to the
  # pulse-access group). Chromium reads PULSE_SERVER and enumerates the devices NATIVELY, so br.media_devices_empty
  # goes silent WITHOUT a JS fake (which coherence would catch). Mirrors the camoufox provisioner.
  pulseaudio --system --daemonize --disallow-exit \
    -L "module-null-sink sink_name=spk" \
    -L "module-null-source source_name=mic" \
    -L "module-native-protocol-unix auth-anonymous=1 socket=/tmp/pulse.sock" >/dev/null 2>&1 || true
  export PULSE_SERVER=unix:/tmp/pulse.sock
  # Real TTS voices: speech-dispatcher (espeak-ng backend) gives Chromium's Web Speech getVoices() a real,
  # OS-coherent voice set → br.voices_empty silent WITHOUT a JS patch.
  speech-dispatcher -d >/dev/null 2>&1 || true
fi

# HEADFUL needs a real X server; xvfb-run stays a CHILD of this sh (PID 1) so PID 1 reaps Chromium zombies.
if [ "$HEADFUL" = "1" ]; then
  xvfb-run -a node run.mjs
else
  exec node run.mjs
fi
