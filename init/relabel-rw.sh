#!/bin/bash --
set -eu
if [ /.qubes-relabeled -nt /rw/.autorelabel ]; then
    restorecon -RF /rw /home /usr/local
    touch /rw/.autorelabel
fi
