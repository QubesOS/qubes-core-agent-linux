#!/bin/sh

# Disable GVFS usage for GIO clients
if [ -f /run/qubes-service/minimal-netvm ]; then
  echo "GIO_USE_VFS=local"
fi
