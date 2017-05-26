#!/bin/sh

# Actually send requested features to dom0. Then dom0 will evaluate them and
# adjust appropriate settings (or ignore).

qvm-features-request --commit
