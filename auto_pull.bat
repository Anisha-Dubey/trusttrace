@echo off
title TRUSTTRACE Auto-Pull Watcher
echo Starting TRUSTTRACE Auto-Pull Watcher (polling every 10s)...
echo Press Ctrl+C at any time to stop.
python scripts/auto_pull.py --interval 10
pause
