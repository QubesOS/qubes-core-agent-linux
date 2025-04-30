#!/bin/bash

DOM0_UPDATES_DIR=/var/lib/qubes/dom0-updates

if ! [ -d "$DOM0_UPDATES_DIR" ]; then
    echo "Dom0 updates dir does not exists: $DOM0_UPDATES_DIR" >&2
    exit 1
fi

mkdir -p $DOM0_UPDATES_DIR/etc

# remove converted sqlite db if legacy db is newer, to force conversion again
# legacy db could be only in the /var/lib/rpm location, but sqlite could be in any
if [ -e "$DOM0_UPDATES_DIR/var/lib/rpm/rpmdb.sqlite" ] && \
       [ "$DOM0_UPDATES_DIR/var/lib/rpm/Packages" -nt "$DOM0_UPDATES_DIR/var/lib/rpm/rpmdb.sqlite" ]; then
    rm -f -- "$DOM0_UPDATES_DIR/var/lib/rpm/rpmdb.sqlite"*
elif [ -e "$DOM0_UPDATES_DIR/usr/lib/sysimage/rpm/rpmdb.sqlite" ] && \
         [ "$DOM0_UPDATES_DIR/var/lib/rpm/Packages" -nt "$DOM0_UPDATES_DIR/usr/lib/sysimage/rpm/rpmdb.sqlite" ]; then
    # remove the whole directory, to make the logic below happy
    rm -rf -- "$DOM0_UPDATES_DIR/usr/lib/sysimage/rpm"
fi

# Check if we need to copy rpmdb somewhere else
DOM0_DBPATH=/var/lib/rpm
if [ -d "$DOM0_UPDATES_DIR/usr/lib/sysimage/rpm" ] && ! [ -L "$DOM0_UPDATES_DIR/usr/lib/sysimage/rpm" ]; then
    DOM0_DBPATH=/usr/lib/sysimage/rpm
fi
DBPATH=$(rpm --eval '%{_dbpath}')
if [ ! "$DBPATH" = "$DOM0_DBPATH" ]; then
    mkdir -p "$DOM0_UPDATES_DIR$DBPATH"
    rm -rf -- "$DOM0_UPDATES_DIR$DBPATH"
    cp -r "$DOM0_UPDATES_DIR$DOM0_DBPATH" "$DOM0_UPDATES_DIR$DBPATH"
fi
# Rebuild rpm database in case of different rpm version
rm -f -- "$DOM0_UPDATES_DIR$DBPATH"/__*
rpm --root=$DOM0_UPDATES_DIR --rebuilddb

exit 0
