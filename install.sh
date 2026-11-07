#!/bin/sh
# Install the `cea` CLI and the Claude Code skill for the current user.
#   ./install.sh            -> ~/.local/bin/cea + ~/.claude/skills/cea
#   PREFIX=/usr/local ./install.sh
set -eu
ROOT=$(cd "$(dirname "$0")" && pwd)
BIN_DIR="${PREFIX:-$HOME/.local}/bin"
SKILL_DIR="${CLAUDE_HOME:-$HOME/.claude}/skills"

command -v python3 >/dev/null || { echo "cea needs python3 (3.10+)"; exit 1; }
mkdir -p "$BIN_DIR" "$SKILL_DIR"
ln -sf "$ROOT/bin/cea" "$BIN_DIR/cea"
rm -rf "$SKILL_DIR/cea"
ln -s "$ROOT/skills/cea" "$SKILL_DIR/cea"
echo "installed: $BIN_DIR/cea  and  $SKILL_DIR/cea (Claude Code skill)"

case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "note: add $BIN_DIR to your PATH";; esac
if command -v docker >/dev/null || command -v podman >/dev/null; then
  echo "next: cea doctor   (the first 'cea check' builds the sandbox image)"
else
  echo "warning: install Docker or Podman - cea runs targets inside a container"
fi
