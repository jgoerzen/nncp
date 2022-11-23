redo-ifchange src/nncp.go
perl -ne 'print "$1\n" if /Version.* = "(.*)"$/' < src/nncp.go
