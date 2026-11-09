#!/bin/bash

# Check if at least two arguments are provided: actions + file(s)
if [ "$#" -le 1 ]; then
    echo "Not enough arguments provided. Aborting..."
fi

# Action
action="$1"

shift

# copy and move handle a list of files where other actions don't
case "$action" in
    copy)
        /usr/lib/qubes/qvm-copy-to-vm.gnome "$@"
        ;;
    move)
        /usr/lib/qubes/qvm-move-to-vm.gnome "$@"
        ;;
    img)
        for file in "$@"
        do
            /usr/lib/qubes/qvm-convert-img.gnome "$file"
        done
        ;;
    pdf)
        for file in "$@"
        do
            /usr/lib/qubes/qvm-convert-pdf.gnome "$file"
        done
        ;;
    openvm)
        for file in "$@"
        do
            if [ -d "$file" ];
            then
                zenity --notification --text "Directory $file found, cannot open directories in other VMs." --timeout 3 &
                exit 1
            fi
        done
        for file in "$@"
        do
            #shellcheck disable=SC2016
            qvm-open-in-vm '@default' "$file" | zenity --notification --text "Opening $file in qube..." --timeout 3 &
        done
        ;;
    opendvm|viewdvm)
        # several files and directories are opened in the same disposable,
        # read-only
        if [ "$#" -eq 1 ]; then
            text="Opening $1 in disposable qube..."
        else
            text="Opening $# items in disposable qube..."
        fi
        if [ "$action" = viewdvm ]; then
            set -- --view-only -- "$@"
        else
            set -- -- "$@"
        fi
        qvm-open-in-dvm "$@" | zenity --notification --text "$text" --timeout 3 &
        ;;
    *)
        echo "Unknown action. Aborting..."
        exit 1
      ;;
esac
