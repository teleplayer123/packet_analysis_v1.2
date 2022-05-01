#!/bin/sh

query=$1
res=$(whois $1 | grep Organization)
echo $res "("$1")"