#!/bin/sh
if [ ! -e ~/.config/gtk-3.0/qubes-incoming-bookmark-created ]
then
  echo "file:///home/user/QubesIncoming" >> ~/.config/gtk-3.0/bookmarks
  touch ~/.config/gtk-3.0/qubes-incoming-bookmark-created
fi
