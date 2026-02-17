#!/bin/sh
# Entrypoint script for the microvm-rs WSL2 distro.
# Starts a control daemon on TCP port 1025.
#
# When called with --handle, serves a single connection (used by socat fork).

CONTROL_PORT=1025

# Control handler: reads commands, writes responses
handle_connection() {
    while read -r cmd; do
        cmd=$(echo "$cmd" | tr -d '\r')
        case "$cmd" in
            ping)    echo "pong" ;;
            status)  echo "running" ;;
            pause)   echo "paused" ;;
            resume)  echo "resumed" ;;
            shutdown)
                echo "shutting down"
                kill $MAIN_PID 2>/dev/null
                exit 0
                ;;
            *)       echo "unknown: $cmd" ;;
        esac
    done
}

# If called with --handle, serve a single connection and exit
if [ "$1" = "--handle" ]; then
    handle_connection
    exit 0
fi

export MAIN_PID=$$

echo "[microvm] Starting microvm daemon on port $CONTROL_PORT..."

# Use socat if available (supports concurrent connections)
if command -v socat >/dev/null 2>&1; then
    socat TCP-LISTEN:$CONTROL_PORT,reuseaddr,fork EXEC:"/etc/microvm/init-microvm.sh --handle" &
    LISTENER_PID=$!
    echo "[microvm] Daemon ready (socat, PID $LISTENER_PID)"
    wait $LISTENER_PID
else
    # Fallback: loop with busybox nc (one connection at a time)
    echo "[microvm] Daemon ready (nc fallback)"
    while true; do
        echo "pong" | nc -l -p $CONTROL_PORT 2>/dev/null || sleep 1
    done
fi
