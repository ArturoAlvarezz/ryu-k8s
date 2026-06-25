#!/bin/sh
set -eu

if [ "${1:-}" = "sh" ] || [ "${1:-}" = "bash" ]; then
    exec "$@"
fi

exec python3 /app/attack_menu.py "$@"
