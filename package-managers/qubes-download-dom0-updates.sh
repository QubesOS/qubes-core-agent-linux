#!/bin/bash

DOM0_UPDATES_DIR=/var/lib/qubes/dom0-updates

GUI=1
CLEAN=0
CHECK_ONLY=0
OPTS=(--installroot "$DOM0_UPDATES_DIR")
if [ -f "$DOM0_UPDATES_DIR/etc/dnf/dnf.conf" ]; then
    OPTS+=("--config=$DOM0_UPDATES_DIR/etc/dnf/dnf.conf")
elif [ -f "$DOM0_UPDATES_DIR/etc/yum.conf" ]; then
    OPTS+=("--config=$DOM0_UPDATES_DIR/etc/yum.conf")
fi
# DNF uses /etc/yum.repos.d, even when --installroot is specified
OPTS+=("--setopt=reposdir=$DOM0_UPDATES_DIR/etc/yum.repos.d")
OPTS+=("--setopt=cachedir=$DOM0_UPDATES_DIR/var/cache/dnf")
# Disarm protected packages mechanism, let dom0 evaluate it instead
OPTS+=("--setopt=protected_packages=")
CLEAN_OPTS=("${OPTS[@]}")
PKGLIST=()

# Executable (yum or dnf)
UPDATE_CMD=
# Action (install, search, upgrade, ...)
UPDATE_ACTION=
# Arguments (--downloadonly, -y, --refresh, ...)
UPDATE_ARGUMENTS=()
# Finall fakeroot command to be executed
UPDATE_COMMAND=

export LC_ALL=C

while [ -n "$1" ]; do
    case "$1" in
        --doit|--force-xen-upgrade|--console|--show-output)
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
            UPDATE_ACTION=check-update
            ;;
        --action=*)
            UPDATE_ACTION=${1#--action=}
            ;;
        -*)
            # we already add these options for DNF, and Yum doesn’t support them
            case $1 in (--best|--allowerasing) :;; (*) OPTS+=("$1");; esac
            ;;
        *)
            PKGLIST+=( "${1}" )
            if [ -z "$UPDATE_ACTION" ]; then
                UPDATE_ACTION=install
            fi
            ;;
    esac
    shift
done

if [ -z "$UPDATE_ACTION" ]; then
    UPDATE_ACTION=upgrade
fi

if type dnf >/dev/null 2>&1 || type dnf5 >/dev/null 2>&1; then
    if type dnf5 >/dev/null 2>&1; then
        UPDATE_CMD=dnf5
    else
        UPDATE_CMD=dnf
    fi
    UPDATE_ARGUMENTS+=(--noplugins -y)
    CLEAN_OPTS+=(--noplugins -y)
    "$UPDATE_CMD" "$UPDATE_ACTION" "${OPTS[@]}" --help 2>/dev/null | grep -q -- '--best' && UPDATE_ARGUMENTS+=(--best)
    "$UPDATE_CMD" "$UPDATE_ACTION" "${OPTS[@]}" --help 2>/dev/null | grep -q -- '--allowerasing' && UPDATE_ARGUMENTS+=(--allowerasing)
    if [ "$UPDATE_CMD" = "dnf5" ] && [ "$CHECK_ONLY" = "1" ]; then
        UPDATE_ACTION=check-upgrade
    fi
else
    UPDATE_CMD=yum
    UPDATE_ARGUMENTS=(-y)
fi

if ! [ -d "$DOM0_UPDATES_DIR" ]; then
    echo "Dom0 updates dir does not exists: $DOM0_UPDATES_DIR" >&2
    exit 1
fi

"$(dirname "$0")/qubes-download-dom0-updates-init.sh" ; RETCODE=$?
if [ $RETCODE -ne 0 ]; then
    echo "qubes-download-dom0-updates-init.sh failed with exit code ${RETCODE}!" >&2
    exit $RETCODE
fi

if [ "$CLEAN" = "1" ]; then
    # shellcheck disable=SC2086
    $UPDATE_CMD clean all "${CLEAN_OPTS[@]}"
    rm -f "$DOM0_UPDATES_DIR"/packages/*
    rm -rf "$DOM0_UPDATES_DIR"/var/cache/*
fi

# just check for updates, but don't download any package
if [ ${#PKGLIST[@]} -eq 0 ] && [ "$CHECK_ONLY" = "1" ]; then
    # shellcheck disable=SC2086
    UPDATES_FULL=$($UPDATE_CMD $UPDATE_ACTION "${UPDATE_ARGUMENTS[@]}" "${OPTS[@]}")
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

# now, we will download something (or perform search, list or other tasks)
UPDATE_COMMAND=(fakeroot "$UPDATE_CMD" "$UPDATE_ACTION" "${UPDATE_ARGUMENTS[@]}")

# DNF4 supported --downloadonly option for all actions. DNF5 fails for list,
# search, info and similar actions if --downloadonly is specified. The below
# condition is a smart way to check if --downloadonly option is applicable to
# the action.
"$UPDATE_CMD" "$UPDATE_ACTION" "${OPTS[@]}" --help 2>/dev/null | grep -q downloadonly && UPDATE_COMMAND+=(--downloadonly)

mkdir -p "$DOM0_UPDATES_DIR/packages"

if [ "$UPDATE_ACTION" = "download" ];  then
   UPDATE_COMMAND+=(--destdir="$DOM0_UPDATES_DIR/packages")
fi

set -e

"${UPDATE_COMMAND[@]}" "${OPTS[@]}" "${PKGLIST[@]}"

"$(dirname "$0")/qubes-download-dom0-updates-finish.sh" ; RETCODE=$?
exit $RETCODE
