#!/usr/bin/python3 --
import fcntl
import os
import pwd
from urllib import parse
def main():
    homedir = pwd.getpwuid(os.getuid()).pw_dir
    bookmark_dir = homedir + '/.config/gtk-3.0/'
    created_path = 'qubes-incoming-bookmark-created'
    bookmark_path = 'bookmarks'

    d = os.open(bookmark_dir, os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    fcntl.lockf(d, fcntl.LOCK_EX)
    try:
        os.stat(bookmark_path, dir_fd=d)
        return
    except FileNotFoundError:
        with open(bookmark_dir + bookmark_path, "w", ) as f:
            f.write("file://" + parse.quote(homedir))
        with open(bookmark_dir + created_path, "w") as f:
            pass
if __name__ == '__main__':
    main()
