#!/bin/sh

TORRENTS_DIR=/storage/torrents
REMOTE=stargrave.org

if [ "$2" -eq 0 ]; then
    # downloaded .torrent/.metalink
    exit 0
fi

if [ "$2" -gt 1 ]; then
    cd "$3"
    while [ "$(pwd)" != $TORRENTS_DIR ]; do
        name="$(basename "$(pwd)")"
        cd ..
    done
    tartmp=$(mktemp ./finished.XXXXXX)
    tar cf $tartmp "$name"
    nncp-file $tartmp $REMOTE:"$name".tar
    rm $tartmp
else
    nncp-file "$3" $REMOTE:
fi
