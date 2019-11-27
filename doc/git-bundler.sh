#!/bin/sh -ex

tmp=$(mktemp)

cleanup()
{
    rm -f $tmp
}
trap cleanup HUP PIPE INT QUIT TERM EXIT

read revs
cd $HOME/git/$1.git
git bundle create $tmp $revs
nncp-file -nice $NNCP_NICE $tmp $NNCP_SENDER:$1-$(date '+%Y%M%d%H%m%S').bundle
