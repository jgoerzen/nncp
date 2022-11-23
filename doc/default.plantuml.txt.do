src=${1%.txt}
redo-ifchange $src ../config
. ../config
$PLANTUML -tutxt -pipe < $src
