#!/bin/bash

declare -A host_up

if ["$1" == ""]
then
echo "Usage: ./check_subnet.sh [subnet]"
else
nmap -A -T4 -Pn $1 -oN "~/tmpdata.txt" 
fi

# for i in $(nmap 127.0.0.1 | grep "report for" | cut -c22-);do echo $i; done
