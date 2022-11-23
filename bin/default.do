cd ../src
redo-ifchange ../config *.go cmd/$1/*.go
. ../config
GO=${GO:-go}
mod=`$GO list -m`
GO_LDFLAGS="$GO_LDFLAGS -X $mod.DefaultCfgPath=$CFGPATH"
GO_LDFLAGS="$GO_LDFLAGS -X $mod.DefaultSendmailPath=$SENDMAIL"
GO_LDFLAGS="$GO_LDFLAGS -X $mod.DefaultSpoolPath=$SPOOLPATH"
GO_LDFLAGS="$GO_LDFLAGS -X $mod.DefaultLogPath=$LOGPATH"
$GO build -o ../bin/$3 $GO_CFLAGS -ldflags "$GO_LDFLAGS" ./cmd/$1
