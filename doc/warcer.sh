#!/bin/sh -ex

name="$1"-$(date '+%Y%M%d%H%m%S')
read cmdline

tmp=$(mktemp -d)
cd $tmp
wget \
    --page-requisites \
    --convert-links \
    --adjust-extension \
    --restrict-file-names=ascii \
    --span-hosts \
    --random-wait \
    --execute robots=off \
    --reject '*.woff*,*.ttf,*.eot,*.js' \
    --tries 10 \
    --warc-file "$name" \
    --no-warc-compression \
    --no-warc-keep-log \
    $cmdline || :
zstd --rm "$name".warc
nncp-file -nice $NNCP_NICE "$name".warc.zst $NNCP_SENDER:
rm -r $tmp
