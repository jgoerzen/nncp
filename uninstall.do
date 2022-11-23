redo-ifchange config
. ./config
for cmd in `cat bin/cmd.list` ; do rm -f $BINDIR/$cmd ; done
rm -f $INFODIR/nncp.info
rm -fr $DOCDIR
