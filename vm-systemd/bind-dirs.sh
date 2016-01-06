#!/bin/bash -e
# vim: set ts=4 sw=4 sts=4 et :
#
# bind-dirs
# Binds directories which allows changes in TemplateBasedVM to persist.
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

set -x

prerequisite() {
   qubes_vm_persistence="$(qubesdb-read /qubes-vm-persistence)"
   if [ ! "$qubes_vm_persistence" = "rw-only" ]; then
      true "No TemplateBasedVM detected. Exiting."
      exit 0
   fi
}

init() {
   [ -n "$rw_dest_dir" ] || rw_dest_dir="/rw/bind-dirs"
   [ -n "$symlink_level_max" ] || symlink_level_max="10"
   mkdir --parents "$rw_dest_dir"
}

legacy() {
   if [ -d /rw/srv/qubes-whonix ]; then
      mv /rw/srv/qubes-whonix /rw/bind-dirs || true
   fi
   if [ -d /rw/srv/whonix ]; then
      mv /rw/srv/whonix /rw/bind-dirs || true
   fi
}

bind_dirs() {
   ## legend
   ## fso: file system object
   ## ro: read-only
   ## rw: read-write

   for fso_ro in ${binds[@]}; do
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

      # Initially copy over data directories to /rw if rw directory does not exist.
      if [ -d "$fso_ro" ]; then
         if [ ! -d "$fso_rw" ]; then
            cp --archive --recursive --parents "$fso_ro" "$rw_dest_dir"
         fi
      elif [ -f "$fso_ro" ]; then
         if [ ! -f "$fso_rw" ]; then
            cp --archive --recursive "$fso_ro" "$fso_rw"
         fi
      else
         true "$fso_ro is neither a directory nor a file or does not exist, skipping."
         continue
      fi

      # Bind the fso.
      mount --bind "$fso_rw" "$fso_ro"
   done
}

main() {
   prerequisite "$@"
   init "$@"
   legacy "$@"
   bind_dirs "$@"
}

for source_folder in /usr/lib/qubes-bind-dirs.d /etc/qubes-bind-dirs.d /rw/config/qubes-bind-dirs.d ; do
   true "source_folder: $source_folder"
   if [ ! -d "$source_folder" ]; then
      continue
   fi
   for file_name in "$source_folder/"*".conf" ; do
      bash -n "$file_name"
      source "$file_name"
   done
done

main "$@"
