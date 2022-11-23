redo-ifchange config bin/all doc/nncp.info
. ./config

mkdir -p $BINDIR
for cmd in `cat bin/cmd.list` ; do
    cp -f bin/$cmd $BINDIR
    chmod 755 $BINDIR/$cmd
done

mkdir -p $INFODIR
cp -f doc/nncp.info $INFODIR
chmod 644 $INFODIR/nncp.info

mkdir -p $DOCDIR
cp -f -L AUTHORS NEWS NEWS.RU README README.RU THANKS $DOCDIR
chmod 644 $DOCDIR/*
