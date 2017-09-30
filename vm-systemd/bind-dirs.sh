#!/bin/bash -e
# vim: set ts=4 sw=4 sts=4 et :
#
# bind-dirs
# Binds directories which allows changes in TemplateBasedVM to persist.
# https://www.qubes-os.org/doc/bind-dirs/
#
# To umount all bind-dirs, just pass any arg in $1, like umount
#
# Copyright (C) 2014 - 2015 Jason Mehring <nrgaway@gmail.com>
# Copyright (C) 2014 - 2015 Patrick Schleizer <adrelanos@riseup.net>
# License: GPL-2+
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   as published by the Free Software Foundation; either version 2
#   of the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Source Qubes library.
# shellcheck source=init/functions
source /usr/lib/qubes/init/functions

prerequisite() {
   if ! is_rwonly_persistent ; then
      true "No TemplateBasedVM detected. Exiting."
      exit 0
   fi
}

init() {
   [ -n "$rw_dest_dir" ] || rw_dest_dir="/rw/bind-dirs"
   [ -n "$symlink_level_max" ] || symlink_level_max="10"
   mkdir --parents "$rw_dest_dir"
   shopt -s nullglob
   shopt -s dotglob
}

legacy() {
   ## The legacy function gets overwritten by Whonix:
   ## https://github.com/Whonix/qubes-whonix/blob/master/usr/lib/qubes-bind-dirs.d/41_qubes-whonix-legacy.conf
   ## Please do not remove this legacy function without coordination with Whonix.
   true
}

bind_dirs() {
   ## legend
   ## fso: file system object
   ## ro: read-only
   ## rw: read-write

   for fso_ro in "${binds[@]}"; do
      local symlink_level_counter
      symlink_level_counter="0"

      while true; do
         if [ -h "$fso_ro" ]; then
            ## Resolving where there symlink points to, and using the result
            ## for bind mount instead.
            symlink_level_counter="$(( symlink_level_counter + 1 ))"
            true "$fso_ro is a symlink"
            fso_real_location="$(realpath "$fso_ro")"
            fso_ro="$fso_real_location"
         else
            true "$fso_ro is not a symlink"
            break
         fi
         if [ "$symlink_level_counter" -ge "$symlink_level_max" ]; then
            break
         fi
      done

      true "fso_ro: $fso_ro"
      fso_rw="${rw_dest_dir}${fso_ro}"

      # Make sure fso_ro is not mounted.
      umount "$fso_ro" 2> /dev/null || true

      if [ -n "$1" ]; then
         true "Umounting $1 only..."
         continue
      fi

      if [ -d "$fso_rw" ] || [ -f "$fso_rw" ]; then
         if [ ! -e "$fso_ro" ]; then
            ## Create empty file or directory if path exists in /rw to allow to bind mount none existing files/dirs.
            test -d "$fso_rw" && mkdir --parents "$fso_ro"
            test -f "$fso_rw" && touch "$fso_ro"
         fi
      else
         if [ -d "$fso_ro" ] || [ -f "$fso_ro" ]; then
            ## Initially copy over data directories to /rw if rw directory does not exist.
            echo "Initializing $rw_dest_dir with files from $fso_ro" >&2
            cp --archive --recursive --parents "$fso_ro" "$rw_dest_dir"
         else
            true "$fso_ro is neither a directory nor a file and the path does not exist below /rw, skipping."
            continue
         fi
      fi

      # Bind the fso.
      echo "Bind mounting $fso_rw onto $fso_ro" >&2
      mount --bind "$fso_rw" "$fso_ro"
   done
}

main() {
   prerequisite "$@"
   init "$@"
   legacy "$@"
   bind_dirs "$@"
}

binds=()
for source_folder in /usr/lib/qubes-bind-dirs.d /etc/qubes-bind-dirs.d /rw/config/qubes-bind-dirs.d ; do
   true "source_folder: $source_folder"
   if [ ! -d "$source_folder" ]; then
      continue
   fi
   for file_name in "$source_folder/"*".conf" ; do
      bash -n "$file_name"
      # shellcheck source=/dev/null
      source "$file_name"
   done
done

main "$@"

true "OK: END."
