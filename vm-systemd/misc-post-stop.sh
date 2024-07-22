#!/bin/sh

USERNAME="$(qubesdb-read /default-user || echo 'user')"
INCOMING_DIR="/home/$USERNAME/QubesIncoming"

# Check for opt-out mechanism
if [ -f /run/qubes-service/no-qubesincoming-cleanup ]; then
    exit 0
fi

# cleanup QubesIncoming/
if [ -d "$INCOMING_DIR" ]; then
    find "$INCOMING_DIR" -mindepth 1 -maxdepth 1 -type f -empty -delete
    find "$INCOMING_DIR" -mindepth 1 -maxdepth 1 -type d -empty -delete
fi

# Save default applications for DispVM
exit 0
