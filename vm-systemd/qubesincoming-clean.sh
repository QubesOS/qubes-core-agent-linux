#!/bin/bash

test ! -d /home/user/QubesIncoming || find '/home/user/QubesIncoming/' -mindepth 1 -type d -exec rmdir '{}' \;
