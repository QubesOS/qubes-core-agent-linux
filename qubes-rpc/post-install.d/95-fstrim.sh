#!/usr/bin/sh

# perform fstrim on all partitions after finishing update-related I/O

# only run if storage is persistent
if [ -f /run/qubes/persistent-full ]
then
    echo "Trimming qube storage. This may take some time..."
    if command -v fstrim >/dev/null; then
      fstrim -av
    else
      # /usr/sbin might not be in $PATH, fall back to the absolute path
      # if necessary
      /usr/sbin/fstrim -av
    fi
fi
