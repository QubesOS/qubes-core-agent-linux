#!/bin/sh

# cleanup QubesIncoming/
if [ -d /home/user/QubesIncomming ]; then
    find /home/user/QubesIncoming -mindepth 1 -type f -empty -delete
    find /home/user/QubesIncoming -mindepth 1 -type d -empty -delete
fi

# Save default applications for DispVM
exit 0
