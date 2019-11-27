#!/bin/sh -ex

name=$1-$(date '+%Y%M%d%H%m%S')
read cmdline

tmp=$(mktemp)
wget --output-document=$tmp $cmdline
zstd --rm $tmp
nncp-file -nice $NNCP_NICE $tmp.zst $NNCP_SENDER:$name.zst
rm $tmp.zst
