#!/usr/bin/env bash
# Unworldly Demo — Fallback recording using asciinema + agg
# Usage: bash demo/record.sh
# Outputs: assets/demo.gif
# Requires: asciinema (https://asciinema.org) + agg (https://github.com/asciinema/agg)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CAST_FILE="$SCRIPT_DIR/demo.cast"
GIF_FILE="$PROJECT_ROOT/assets/demo.gif"

mkdir -p "$PROJECT_ROOT/assets"

echo "Recording demo..."
asciinema rec "$CAST_FILE" \
    --cols 100 \
    --rows 30 \
    --command "python $SCRIPT_DIR/simulate.py" \
    --overwrite

echo "Converting to GIF..."
agg "$CAST_FILE" "$GIF_FILE" \
    --font-family "JetBrains Mono" \
    --font-size 14 \
    --theme asciinema \
    --fps-cap 15

echo "Done! GIF saved to: $GIF_FILE"
echo "Cast file: $CAST_FILE (not committed — listed in .gitignore)"
