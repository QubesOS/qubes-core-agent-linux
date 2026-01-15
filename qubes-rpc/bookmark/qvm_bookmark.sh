#!/bin/sh

incoming_dir="$HOME/QubesIncoming"
bookmark_created_basename="qubes-incoming-bookmark-created"

dir="$HOME/.config/gtk-3.0"
test -d "$dir" || exit 0
created="$dir/$bookmark_created_basename"
! test -e "$created" || exit 0
printf '%s\n' "file://$incoming_dir" >> "$dir"/bookmarks
touch -- "$created"
