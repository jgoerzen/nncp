cd ../src
GO=${GO:-go}
$GO build -o ../bin/$3 github.com/hjson/hjson-go/hjson-cli
