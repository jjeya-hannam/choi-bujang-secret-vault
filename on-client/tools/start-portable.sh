#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")/.."
command -v node >/dev/null 2>&1 || { printf '%s\n' 'Node.js 24.19.0 is required. Install it from the official Node.js website.'; exit 1; }
printf '%s\n' 'Student demo source app. This is not an approved course runtime.' 'Open http://127.0.0.1:5189 and stop with Ctrl+C.'
exec node src/server.mjs --demo
