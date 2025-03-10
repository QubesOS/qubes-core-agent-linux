#!/bin/bash -e
shopt -s nullglob dotglob
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

readonly DEFAULT_RW_BIND_DIR="/rw/bind-dirs"

prerequisite() {
   if is_fully_persistent ; then
      echo "No TemplateBasedVM/DisposableVM detected. Exiting."
      exit 0
   fi
}

init() {
   [ -n "$rw_dest_dir" ] || rw_dest_dir="$DEFAULT_RW_BIND_DIR"
   [ -n "$symlink_level_max" ] || symlink_level_max="10"
   mkdir --parents "$rw_dest_dir"
}

legacy() {
   ## The legacy function gets overwritten by Whonix:
   ## https://github.com/Whonix/qubes-whonix/blob/master/usr/lib/qubes-bind-dirs.d/41_qubes-whonix-legacy.conf
   ## Please do not remove this legacy function without coordination with Whonix.
   true
}

rw_from_ro() {
  ro="$1"
  # special cases for files/dirs in /home or /usr/local
  if [[ "$ro" =~ ^/home/ ]]; then
    # use /rw/home for /home/... binds
    rw="/rw${ro}"
  elif [[ "$ro" =~ ^/usr/local/ ]]; then
    # use /rw/usrlocal for /usr/local/... binds
    rw="/rw/usrlocal/$(echo "$ro" | cut -d/ -f4-)"
  else
    [ -z "$rw_dest_dir" ] && rw="${DEFAULT_RW_BIND_DIR}${ro}" || rw="${rw_dest_dir}${ro}"
  fi
  echo "$rw"
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
            echo "$fso_ro is not a symlink"
            break
         fi
         if [ "$symlink_level_counter" -ge "$symlink_level_max" ]; then
            break
         fi
      done

      true "fso_ro: $fso_ro"
      fso_rw="$(rw_from_ro "$fso_ro")"

      # Make sure fso_ro is not mounted.
      umount "$fso_ro" 2> /dev/null || true

      if [ -n "$1" ]; then
         true "Umounting $1 only..."
         continue
      fi

      if [ -d "$fso_rw" ] || [ -f "$fso_rw" ]; then
         if [ ! -e "$fso_ro" ]; then
            ## Create empty file or directory if path exists in /rw to allow to bind mount none existing files/dirs.
            # shellcheck disable=SC2046
            test -d "$fso_rw" && mk_parent_dirs "$fso_ro" $(stat --printf "%U %G" "$fso_rw")
            if [ -f "$fso_rw" ]; then
              parent_directory="$(dirname "$fso_ro")"
              # shellcheck disable=SC2046
              test -d "$parent_directory" || mk_parent_dirs "$parent_directory" $(stat --printf "%U %G" "$fso_rw")
              touch "$fso_ro"
            fi
         fi
      else
         if [ -d "$fso_ro" ] || [ -f "$fso_ro" ]; then
            ## Initially copy over data directories to /rw if rw directory does not exist.
            echo "Initializing $fso_rw with files from $fso_ro" >&2
            parent_directory="$(dirname "$fso_rw")"
            test -d "$parent_directory" || mkdir --parents "$parent_directory"
            cp --archive --recursive "$fso_ro" "$fso_rw"
         else
            echo "$fso_ro is neither a directory nor a file and the path does not exist below /rw, skipping."
            continue
         fi
      fi

      # Bind the fso.
      echo "Bind mounting $fso_rw onto $fso_ro" >&2
      mount --bind -o x-gvfs-hide "$fso_rw" "$fso_ro"
   done
}

mk_parent_dirs() {
  local target="$1"
  local owner="$2"
  local group="$3"
  local depth="$4"
  [[ "$depth" -gt 100 ]] && echo "Maximum recursion depth reached" >&2 && return 1
  [ -e "$target" ] && return 0
  mk_parent_dirs "$(dirname "$target")" "$owner" "$group" "$(( depth + 1 ))" || return 1
  mkdir "$target" || return 1
  chown "$owner":"$group" "$target" || return 1
  return 0
}

main() {
   prerequisite "$@"
   init "$@"
   legacy "$@"
   bind_dirs "$@"
}

binds=()
sources=( "/usr/lib/qubes-bind-dirs.d" "/etc/qubes-bind-dirs.d" )
if [ ! -f "/var/run/qubes-service/custom-persist" ]; then
    sources+=( "/rw/config/qubes-bind-dirs.d" )
fi

for source_folder in "${sources[@]}"; do
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

# read binds in QubesDB if custom-persist feature is enabled
if is_custom_persist_enabled; then
  while read -r qubes_persist_entry; do
    [[ "$qubes_persist_entry" =~ =\ (.*)$ ]] || continue
    target="${BASH_REMATCH[1]}"

    # if the first char is not a slash, options should be extracted from
    # the value
    if [[ "$target" != /* ]]; then
      resource_type="$(echo "$target" | cut -d':' -f1)"
      owner="$(echo "$target" | cut -d':' -f2)"
      group="$(echo "$target" | cut -d':' -f3)"
      mode="$(echo "$target" | cut -d':' -f4)"
      path="$(echo "$target" | cut -d':' -f5-)"

      if [ -z "$path" ] || [[ "$path" != /* ]]; then
        echo "Skipping invalid custom-persist value '${target}'" >&2
        continue
      fi

      rw_path="$(rw_from_ro "${path}")"
      # create resource if it does not exist
      if ! [ -e "${path}" ] && ! [ -e "$rw_path" ]; then
        if [ "$resource_type" = "file" ]; then
          # for files, we need to create parent directories
          parent_directory="$(dirname "$rw_path")"
          echo "custom-persist: pre-creating file ${rw_path} with rights ${owner}:${group} ${mode}"
          if [ ! -d "$parent_directory" ]; then
            if ! mk_parent_dirs "$parent_directory" "$owner" "$group"; then
              echo "Unable to create ${rw_path} parent dirs, skipping"
              continue
            fi
          fi
          touch "${rw_path}"
        elif [ "$resource_type" = "dir" ]; then
          echo "custom-persist: pre-creating directory ${rw_path} with rights ${owner}:${group} ${mode}"
          if ! mk_parent_dirs "$rw_path" "$owner" "$group"; then
            echo "Unable to create ${rw_path} parent dirs, skipping"
            continue
          fi
        else
          echo "Invalid entry ${target}, skipping"
          continue
        fi
        chown "$owner":"$group" "${rw_path}"
        chmod "$mode" "${rw_path}"
      fi
      target="$path"
    fi
    [[ "$target" =~ ^(\/home|\/usr\/local)$ ]] && continue
    binds+=( "$target" )
  done <<< "$(qubesdb-multiread /persist/)"
fi

main "$@"

true "OK: END."
