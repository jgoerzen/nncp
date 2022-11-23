redo-ifchange config
exec >&2
. ./config
cd src
GO=${GO:-go}
$GO test -failfast ./...
