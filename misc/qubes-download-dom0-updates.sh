#!/bin/bash

DOM0_UPDATES_DIR=/var/lib/qubes/dom0-updates

GUI=1
CLEAN=0
CHECK_ONLY=0
OPTS="--installroot $DOM0_UPDATES_DIR --config=$DOM0_UPDATES_DIR/etc/yum.conf"
# DNF uses /etc/yum.repos.d, even when --installroot is specified
OPTS="$OPTS --setopt=reposdir=$DOM0_UPDATES_DIR/etc/yum.repos.d"
PKGLIST=
YUM_ACTION=

export LC_ALL=C

while [ -n "$1" ]; do
    case "$1" in
        --doit)
            # ignore
            ;;
        --nogui)
            GUI=0
            ;;
        --gui)
            GUI=1
            ;;
        --clean)
            CLEAN=1
            ;;
        --check-only)
            CHECK_ONLY=1
            ;;
        --action=*)
            YUM_ACTION=${1#--action=}
            ;;
        -*)
            OPTS="$OPTS $1"
            ;;
        *)
            PKGLIST="$PKGLIST $1"
            if [ -z "$YUM_ACTION" ]; then
                YUM_ACTION=install
            fi
            ;;
    esac
    shift
done

if [ -z "$YUM_ACTION" ]; then
    YUM_ACTION=upgrade
fi

YUM="yum"
if type dnf >/dev/null 2>&1; then
    YUM="dnf --best --allowerasing"
fi

if ! [ -d "$DOM0_UPDATES_DIR" ]; then
    echo "Dom0 updates dir does not exists: $DOM0_UPDATES_DIR" >&2
    exit 1
fi

mkdir -p $DOM0_UPDATES_DIR/etc

if [ -e /etc/debian_version ]; then
    # Default rpm configuration on Debian uses ~/.rpmdb for rpm database (as
    # rpm isn't native package manager there)
    mkdir -p "$DOM0_UPDATES_DIR$HOME"
    ln -nsf "$DOM0_UPDATES_DIR/var/lib/rpm" "$DOM0_UPDATES_DIR$HOME/.rpmdb"
fi
# Rebuild rpm database in case of different rpm version
rm -f $DOM0_UPDATES_DIR/var/lib/rpm/__*
rpm --root=$DOM0_UPDATES_DIR --rebuilddb

if [ "$CLEAN" = "1" ]; then
    # shellcheck disable=SC2086
    $YUM $OPTS clean all
    rm -f "$DOM0_UPDATES_DIR"/packages/*
    rm -rf "$DOM0_UPDATES_DIR"/var/cache/yum/*
fi

# just check for updates, but don't download any package
if [ "x$PKGLIST" = "x" ] && [ "$CHECK_ONLY" = "1" ]; then
    echo "Checking for dom0 updates..." >&2
    # shellcheck disable=SC2086
    UPDATES_FULL=$($YUM $OPTS check-update)
    check_update_retcode=$?
    if [ "$check_update_retcode" -eq 1 ]; then
        # Exit here if yum have reported an error. Exit code 100 isn't an
        # error, it's "updates available" info, so check specifically for exit code 1
        exit 1
    fi
    if [ $check_update_retcode -eq 100 ]; then
        echo "Available updates: "
        echo "$UPDATES_FULL"
        exit 100
    else
        echo "No new updates available"
        if [ "$GUI" = 1 ]; then
            zenity --info --text="No new updates available"
        fi
        exit 0
    fi
fi

# now, we will download something
YUM_COMMAND="fakeroot $YUM $YUM_ACTION -y --downloadonly"
# check for --downloadonly option - if not supported (Debian), fallback to
# yumdownloader
if ! $YUM --help | grep -q downloadonly; then
    if [ "$YUM_ACTION" != "install" ] && [ "$YUM_ACTION" != "upgrade" ]; then
        echo "ERROR: yum version installed in VM $(hostname) does not suppport --downloadonly option" >&2
        echo "ERROR: only 'install' and 'upgrade' actions supported ($YUM_ACTION not)" >&2
        if [ "$GUI" = 1 ]; then
            zenity --error --text="yum version too old for '$YUM_ACTION' action, see console for details"
        fi
        exit 1
    fi
    if [ "$YUM_ACTION" = "upgrade" ]; then
        # shellcheck disable=SC2086
        UPDATES_FULL=$($YUM $OPTS check-update $PKGLIST)
        check_update_retcode=$?
        UPDATES_FULL=$(echo "$UPDATES_FULL" | grep -v "^Loaded plugins:\|^Last metadata\|^$")
        UPDATES=$(echo "$UPDATES_FULL" | grep -v "^Obsoleting\|Could not" | cut -f 1 -d ' ')
        if [ "$check_update_retcode" -eq 0 ]; then
            # exit code 0 means no updates available - regardless of stdout messages
            echo "No new updates available"
            exit 0
        fi
        PKGLIST=$UPDATES
    fi
    YUM_COMMAND="yumdownloader --destdir=$DOM0_UPDATES_DIR/packages --resolve"
fi

mkdir -p "$DOM0_UPDATES_DIR/packages"

set -e

if [ "$GUI" = 1 ]; then
    ( echo "1"
    # shellcheck disable=SC2086
    $YUM_COMMAND $OPTS $PKGLIST
    echo 100 ) | zenity --progress --pulsate --auto-close --auto-kill \
         --text="Downloading updates for Dom0, please wait..." --title="Qubes Dom0 updates"
else
    # shellcheck disable=SC2086
    $YUM_COMMAND $OPTS $PKGLIST
fi

find "$DOM0_UPDATES_DIR/var/cache/yum" -name '*.rpm' -print0 |\
    xargs -0 -r ln -f -t "$DOM0_UPDATES_DIR/packages/"

if ls "$DOM0_UPDATES_DIR"/packages/*.rpm > /dev/null 2>&1; then
    cmd="/usr/lib/qubes/qrexec-client-vm dom0 qubes.ReceiveUpdates /usr/lib/qubes/qfile-agent"
    qrexec_exit_code=0
    $cmd "$DOM0_UPDATES_DIR"/packages/*.rpm || { qrexec_exit_code=$? ; true; };
    if [ ! "$qrexec_exit_code" = "0" ]; then
        echo "'$cmd $DOM0_UPDATES_DIR/packages/*.rpm' failed with exit code ${qrexec_exit_code}!" >&2
        exit "$qrexec_exit_code"
    fi
else
    echo "No packages downloaded"
fi
