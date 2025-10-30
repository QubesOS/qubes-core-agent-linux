#!/usr/bin/sh

# perform fstrim on all partitions after finishing update-related I/O

# abort if not in a template
if [ "$(qubesdb-read /type)" = "TemplateVM" ]
then
    fstrim -av
fi
