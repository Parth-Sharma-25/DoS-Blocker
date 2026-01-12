#!/bin/bash

ipset flush dosblock

if [ -f /var/run/dos_blocklist.txt ]; then
    sort -u /var/run/dos_blocklist.txt | while read ip; do
        ipset add dosblock "$ip"
    done
fi
