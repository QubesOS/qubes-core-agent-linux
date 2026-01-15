#!/bin/sh

incoming_dir="$HOME/QubesIncoming"
bookmark_created_basename="qubes-incoming-bookmark-created"

for dir in \
  "$HOME/.config/gtk-3.0" \
  "$HOME/.config/gtk-4.0"
do
  test -d "$dir" || continue
  created="$dir/$bookmark_created_basename"
  ! test -e "$created" || continue
  printf '%s\n' "file://$incoming_dir" >> "$dir"/bookmarks
  touch -- "$created"
done
