#!/bin/bash --
qubesdb-read -w /qubes-random-seed > /dev/urandom && exec qubesdb-rm /qubes-random-seed
