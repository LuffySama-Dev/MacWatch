#!/bin/bash

set -euo pipefail

TCP_PORT="${1:-52123}"
UDP_PORT="${2:-52124}"
WAIT_FOR_PORT_SCAN=20
WAIT_FOR_STARTUP_SCAN=12
LAUNCH_AGENTS_DIRECTORY="${HOME}/Library/LaunchAgents"
TEST_LABEL="com.macwatch.telemetry-test.$$"
TEST_PLIST="${LAUNCH_AGENTS_DIRECTORY}/${TEST_LABEL}.plist"
TCP_PID=""
UDP_PID=""

usage() {
    printf 'Usage: %s [tcp-port] [udp-port]\n' "$0"
    printf 'Defaults: TCP 52123 and UDP 52124 (loopback only).\n'
}

valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 49152 ] && [ "$1" -le 65535 ]
}

cleanup() {
    if [ -n "$TCP_PID" ]; then
        kill "$TCP_PID" 2>/dev/null || true
        wait "$TCP_PID" 2>/dev/null || true
    fi
    if [ -n "$UDP_PID" ]; then
        kill "$UDP_PID" 2>/dev/null || true
        wait "$UDP_PID" 2>/dev/null || true
    fi
    if [ -e "$TEST_PLIST" ]; then
        rm -f -- "$TEST_PLIST"
    fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    usage
    exit 0
fi

if ! valid_port "$TCP_PORT" || ! valid_port "$UDP_PORT" || [ "$TCP_PORT" = "$UDP_PORT" ]; then
    printf 'Choose two different ports between 49152 and 65535.\n' >&2
    usage >&2
    exit 2
fi

if ! pgrep -x MacWatch >/dev/null 2>&1; then
    printf 'MacWatch is not running. Start the MacWatch Xcode scheme, then retry.\n' >&2
    exit 1
fi

if /usr/sbin/lsof -nP -iTCP:"$TCP_PORT" -sTCP:LISTEN 2>/dev/null | grep -q .; then
    printf 'TCP port %s is already in use. Choose another high port.\n' "$TCP_PORT" >&2
    exit 1
fi

if /usr/sbin/lsof -nP -iUDP:"$UDP_PORT" 2>/dev/null | grep -q .; then
    printf 'UDP port %s is already in use. Choose another high port.\n' "$UDP_PORT" >&2
    exit 1
fi

mkdir -p "$LAUNCH_AGENTS_DIRECTORY"
if [ -e "$TEST_PLIST" ]; then
    printf 'Refusing to overwrite existing file: %s\n' "$TEST_PLIST" >&2
    exit 1
fi

printf 'MacWatch telemetry validation\n'
printf 'Keep MacWatch running. This takes about one minute.\n\n'
printf '1/3 Creating a disabled test LaunchAgent and loopback listeners...\n'

/usr/bin/plutil -create xml1 "$TEST_PLIST"
/usr/bin/plutil -insert Label -string "$TEST_LABEL" "$TEST_PLIST"
/usr/bin/plutil -insert Disabled -bool true "$TEST_PLIST"
/usr/bin/plutil -insert ProgramArguments -json '["/usr/bin/true"]' "$TEST_PLIST"

/usr/bin/nc -4 -l -k 127.0.0.1 "$TCP_PORT" >/dev/null 2>&1 &
TCP_PID=$!
/usr/bin/nc -4 -u -l -k 127.0.0.1 "$UDP_PORT" >/dev/null 2>&1 &
UDP_PID=$!

sleep 1
if ! kill -0 "$TCP_PID" 2>/dev/null || ! kill -0 "$UDP_PID" 2>/dev/null; then
    printf 'A temporary listener failed to start. Nothing will be left behind.\n' >&2
    exit 1
fi

printf '    TCP 127.0.0.1:%s and UDP 127.0.0.1:%s are open temporarily.\n' "$TCP_PORT" "$UDP_PORT"
sleep "$WAIT_FOR_PORT_SCAN"

printf '2/3 Modifying the disabled test LaunchAgent...\n'
/usr/bin/plutil -insert MacWatchTestRevision -integer 2 "$TEST_PLIST"
sleep "$WAIT_FOR_STARTUP_SCAN"

printf '3/3 Closing listeners and removing the test LaunchAgent...\n'
kill "$TCP_PID" "$UDP_PID" 2>/dev/null || true
wait "$TCP_PID" 2>/dev/null || true
wait "$UDP_PID" 2>/dev/null || true
TCP_PID=""
UDP_PID=""
rm -f -- "$TEST_PLIST"
sleep "$WAIT_FOR_PORT_SCAN"

printf '\nDone. No test listener or plist remains.\n'
printf 'Expected event kinds:\n'
printf '  startupAdded, startupModified, startupRemoved\n'
printf '  listeningEndpointOpened, listeningEndpointClosed\n'
printf '\nEvents appear locally first. For SigNoz, wait for the configured export interval\n'
printf 'or press "Send clearly labeled test event" in MacWatch to flush the queue.\n'
printf 'SigNoz filter:\n'
printf "  service.name = 'macwatch' AND event.kind IN ('startupAdded', 'startupModified', 'startupRemoved', 'listeningEndpointOpened', 'listeningEndpointClosed')\n"
