#!/bin/sh
set -e

CONTAINER_NAME="logsentry-$$"
LOG_FILE=""

while getopts "h:" opt; do
  case $opt in
    h) LOG_FILE="$OPTARG" ;;
    *) echo "Usage: $0 [-h logfile]" >&2; exit 1 ;;
  esac
done

shift $((OPTIND-1))

if [ -n "$LOG_FILE" ]; then
  CMD="python main.py watch $LOG_FILE --once"
else
  CMD="python main.py --help"
fi

docker build -t logsentry:latest .

if [ -n "$LOG_FILE" ]; then
  echo "[*] Running LogSentry on $LOG_FILE"
  docker run --rm -v "$(pwd):/data" -w /data "$CONTAINER_NAME" $CMD
else
  echo "[*] Running LogSentry help"
  docker run --rm "$CONTAINER_NAME"
fi

docker rmi logsentry:latest >/dev/null 2>&1 || true