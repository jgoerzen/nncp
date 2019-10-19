#!/bin/sh -ex

name=$1-$(date '+%Y%M%d%H%m%S')
read cmdline

tmp=$(mktemp)
wget --output-document=$tmp $cmdline
xz -9 $tmp
nncp-file -nice $NNCP_NICE $tmp.xz $NNCP_SENDER:$name.xz
rm $tmp.xz
