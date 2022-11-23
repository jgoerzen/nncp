redo-ifchange config install
. ./config
for cmd in `cat bin/cmd.list` ; do
    strip $BINDIR/$cmd
done
