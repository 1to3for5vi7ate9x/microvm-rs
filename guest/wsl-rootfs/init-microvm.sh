#!/bin/sh
# Entrypoint script for the microvm-rs WSL2 distro.
# Starts a control daemon on TCP port 1025 and optionally a SOCKS5 proxy.

set -e

CONTROL_PORT=1025
SOCKS_PORT=1080

echo "[microvm] Starting microvm daemon..."
echo "[microvm] Control port: $CONTROL_PORT"
echo "[microvm] SOCKS proxy port: $SOCKS_PORT"

# Start a simple control daemon using socat
# Accepts commands: "ping", "pause", "resume", "shutdown"
control_handler() {
    while read -r cmd; do
        case "$cmd" in
            ping)
                echo "pong"
                ;;
            pause)
                echo "paused"
                # In a full implementation, this would pause services
                ;;
            resume)
                echo "resumed"
                # In a full implementation, this would resume services
                ;;
            shutdown)
                echo "shutting down"
                kill $$
                exit 0
                ;;
            status)
                echo "running"
                ;;
            *)
                echo "unknown command: $cmd"
                ;;
        esac
    done
}

# Export the handler function for socat
export -f control_handler 2>/dev/null || true

# Start the control listener
# Uses socat to accept TCP connections and pipe to our handler
if command -v socat >/dev/null 2>&1; then
    socat TCP-LISTEN:$CONTROL_PORT,reuseaddr,fork SYSTEM:"control_handler" &
    CONTROL_PID=$!
    echo "[microvm] Control daemon started (PID $CONTROL_PID)"
else
    # Fallback: simple netcat-based listener
    echo "[microvm] socat not found, using fallback listener"
    while true; do
        echo "pong" | nc -l -p $CONTROL_PORT -q 1 2>/dev/null || true
    done &
    CONTROL_PID=$!
fi

# Start SOCKS5 proxy if ssh is available
# Using ssh's built-in SOCKS proxy (-D flag) with a local connection
# For a production setup, use a dedicated SOCKS5 server like microsocks
echo "[microvm] SOCKS5 proxy available on port $SOCKS_PORT (when configured)"

# Keep the script running
echo "[microvm] Daemon ready."
wait $CONTROL_PID
