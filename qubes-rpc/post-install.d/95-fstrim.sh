#!/usr/bin/sh

# perform fstrim on all partitions after finishing update-related I/O

# only run if storage is persistent
if [ -f /run/qubes/persistent-full ]
then
    echo "Trimming qube storage. This may take some time..."
    fstrim -av
fi
