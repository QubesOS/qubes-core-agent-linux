#!/bin/bash

set -e
set -o pipefail

qubesdb-read /qubes-random-seed | base64 -d > /dev/urandom
qubesdb-rm /qubes-random-seed
