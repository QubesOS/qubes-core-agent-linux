#!/bin/sh

# Disable GVFS usage for GIO clients
if [ -f /run/qubes-service/minimal-netvm ] || [ -f /run/qubes-service/minimal-usbvm ]; then
  echo "GIO_USE_VFS=local"
fi
