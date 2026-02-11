#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "python3/python not found in PATH" >&2
    exit 127
  fi
fi

CAPTURE_SECONDS=300
SPEEDUP=10
OUTPUT_SECONDS=""
OUTPUT_DIR="artifacts/readme"
FONT_PATH=""
CAPTURE_CMD="PYTHONPATH=src \"${PYTHON_BIN}\" -m helianthus_vrc_explorer scan --dst 0x15 --host 127.0.0.1 --port 8888 --planner-ui textual --preset recommended --output-dir artifacts/from-ha"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --capture-seconds)
      CAPTURE_SECONDS="$2"
      shift 2
      ;;
    --speedup)
      SPEEDUP="$2"
      shift 2
      ;;
    --output-seconds|--duration)
      OUTPUT_SECONDS="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --font-path)
      FONT_PATH="$2"
      shift 2
      ;;
    --command)
      CAPTURE_CMD="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [--capture-seconds 300] [--speedup 10] [--output-seconds 30] [--output-dir artifacts/readme] [--font-path /path.ttf] [--command \"...\"]" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$OUTPUT_SECONDS" ]]; then
  OUTPUT_SECONDS="$("$PYTHON_BIN" - <<PY
capture = float("$CAPTURE_SECONDS")
speed = float("$SPEEDUP")
if speed <= 0:
    raise SystemExit("speedup must be > 0")
print(max(1.0, capture / speed))
PY
)"
fi

mkdir -p "$OUTPUT_DIR"
TXT_PATH="$OUTPUT_DIR/preview.txt"
PNG_PATH="$OUTPUT_DIR/preview.png"
GIF_PATH="$OUTPUT_DIR/preview.gif"

echo "Capturing TTY session to $TXT_PATH ..."
CAPTURE_CMD="$CAPTURE_CMD" CAPTURE_SECONDS="$CAPTURE_SECONDS" TERM="xterm-256color" \
  script -q "$TXT_PATH" /bin/zsh -lc '
    set -euo pipefail
    eval "$CAPTURE_CMD" &
    pid=$!
    sleep "$CAPTURE_SECONDS"
    kill -INT "$pid" >/dev/null 2>&1 || true
    wait "$pid" || true
  '

echo "Rendering preview assets (Tango theme, Anonymous Pro) ..."
render_cmd=(
  "$PYTHON_BIN"
  scripts/render_tui_preview.py
  --input "$TXT_PATH"
  --png "$PNG_PATH"
  --gif "$GIF_PATH"
  --duration "$OUTPUT_SECONDS"
)
if [[ -n "$FONT_PATH" ]]; then
  render_cmd+=(--font-path "$FONT_PATH")
fi
"${render_cmd[@]}"

echo "Done."
echo "  Transcript: $TXT_PATH"
echo "  GIF:        $GIF_PATH"
echo "  PNG:        $PNG_PATH"
echo "  Capture:    ${CAPTURE_SECONDS}s (speed x${SPEEDUP} -> ${OUTPUT_SECONDS}s)"
