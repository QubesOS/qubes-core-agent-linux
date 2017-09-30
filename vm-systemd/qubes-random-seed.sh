#!/bin/bash

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

set -e
set -o pipefail

reload_random_seed
