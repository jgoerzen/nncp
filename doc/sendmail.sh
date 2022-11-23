#!/bin/sh -e

tmp=`mktemp`
trap "rm -f $tmp" HUP PIPE INT QUIT TERM EXIT
cat > $tmp
sendmail -f "`reformail -x Return-Path: < $tmp`" $@ < $tmp
