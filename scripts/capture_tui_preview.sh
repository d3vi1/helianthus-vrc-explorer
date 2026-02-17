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
COLS=140
ROWS=42
FPS=20
POSTER_PERCENT=40
FONT_SIZE=16
CAPTURE_CMD="PYTHONPATH=src \"${PYTHON_BIN}\" -m helianthus_vrc_explorer scan --host 127.0.0.1 --port 8888 --planner-ui auto --preset recommended --redact --output-dir artifacts/from-ha"

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
    --cols)
      COLS="$2"
      shift 2
      ;;
    --rows)
      ROWS="$2"
      shift 2
      ;;
    --fps)
      FPS="$2"
      shift 2
      ;;
    --poster-percent)
      POSTER_PERCENT="$2"
      shift 2
      ;;
    --font-size)
      FONT_SIZE="$2"
      shift 2
      ;;
    --command)
      CAPTURE_CMD="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [--capture-seconds 300] [--speedup 10] [--output-seconds 30] [--cols 140] [--rows 42] [--fps 20] [--poster-percent 40] [--font-size 16] [--output-dir artifacts/readme] [--font-path /path.ttf] [--command \"...\"]" >&2
      exit 2
      ;;
  esac
done

if ! command -v asciinema >/dev/null 2>&1; then
  echo "asciinema is required (brew install asciinema)" >&2
  exit 127
fi
if ! command -v agg >/dev/null 2>&1; then
  echo "agg is required (brew install agg)" >&2
  exit 127
fi

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
CAST_PATH="$OUTPUT_DIR/preview.cast"

echo "Recording asciicast to $CAST_PATH ..."
ASCIINEMA_CMD='
  set -euo pipefail
  # Run capture command detached from stdin so backgrounded transports
  # (notably ssh) are not stopped by terminal job control (SIGTTIN).
  # On zsh, background jobs can lose terminal output; force stdout/stderr
  # back to the controlling TTY.
  eval "$CAPTURE_CMD" </dev/null >/dev/tty 2>&1 &
  pid=$!
  sleep "$CAPTURE_SECONDS"
  kill -INT "$pid" >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5; do
    kill -0 "$pid" >/dev/null 2>&1 || break
    sleep 1
  done
  kill -TERM "$pid" >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5; do
    kill -0 "$pid" >/dev/null 2>&1 || break
    sleep 1
  done
  kill -KILL "$pid" >/dev/null 2>&1 || true
  wait "$pid" || true
'
CAPTURE_CMD="$CAPTURE_CMD" CAPTURE_SECONDS="$CAPTURE_SECONDS" TERM="xterm-256color" \
  asciinema rec \
    --overwrite \
    --headless \
    --window-size "${COLS}x${ROWS}" \
    --idle-time-limit 2.0 \
    -c "/bin/zsh -lc '$ASCIINEMA_CMD'" \
    "$CAST_PATH"

echo "Applying Tango theme metadata ..."
"$PYTHON_BIN" - <<PY
import json
from pathlib import Path
cast_path = Path("$CAST_PATH")
lines = cast_path.read_text(encoding="utf-8").splitlines()
if not lines:
    raise SystemExit("Empty cast file")
header = json.loads(lines[0])
header["theme"] = {
    "fg": "#D3D7CF",
    "bg": "#2E3436",
    "palette": (
        "#2E3436:#CC0000:#4E9A06:#C4A000:#3465A4:#75507B:#06989A:#D3D7CF:"
        "#555753:#EF2929:#8AE234:#FCE94F:#729FCF:#AD7FA8:#34E2E2:#EEEEEC"
    ),
}
lines[0] = json.dumps(header, separators=(",", ":"))
cast_path.write_text("\\n".join(lines) + "\\n", encoding="utf-8")
PY

echo "Rendering GIF with agg ..."
agg_cmd=(
  agg
  --speed "$SPEEDUP"
  --fps-cap "$FPS"
  --cols "$COLS"
  --rows "$ROWS"
  --font-size "$FONT_SIZE"
  --font-family "Anonymous Pro,JetBrains Mono,Fira Code,SF Mono,Menlo,Consolas"
  "$CAST_PATH"
  "$GIF_PATH"
)
if [[ -n "$FONT_PATH" ]]; then
  FONT_DIR="$(dirname "$FONT_PATH")"
  agg_cmd=(agg --font-dir "$FONT_DIR" "${agg_cmd[@]:1}")
fi
"${agg_cmd[@]}"

echo "Extracting PNG poster frame ..."
"$PYTHON_BIN" - <<PY
from pathlib import Path

from PIL import Image

gif_path = Path("$GIF_PATH")
png_path = Path("$PNG_PATH")
percent = float("$POSTER_PERCENT")
percent = max(0.0, min(100.0, percent))

with Image.open(gif_path) as image:
    frames = getattr(image, "n_frames", 1)
    index = int(round((frames - 1) * (percent / 100.0)))
    for i in range(index + 1):
        image.seek(i)
    frame = image.convert("RGBA")
    frame.save(png_path)

print(f"Poster frame index: {index}/{frames - 1}")
PY

echo "Exporting plain transcript ..."
asciinema convert --overwrite --output-format txt "$CAST_PATH" "$TXT_PATH"

echo "Done."
echo "  Cast:       $CAST_PATH"
echo "  Transcript: $TXT_PATH"
echo "  GIF:        $GIF_PATH"
echo "  PNG:        $PNG_PATH"
echo "  Capture:    ${CAPTURE_SECONDS}s (speed x${SPEEDUP} -> ${OUTPUT_SECONDS}s)"
