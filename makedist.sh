#!/bin/sh -ex

cur=$(pwd)
tmp=$(mktemp -d)
release=$1
[ -n "$release" ]

git clone . $tmp/nncp-$release
cd $tmp/nncp-$release
git checkout v$release
redo VERSION
cd src
go mod vendor
modvendor -v -copy="**/*_test.go **/words.go **/README.md **/main.go"
cd vendor
rm -r \
    github.com/flynn/noise/vector* \
    github.com/gorhill/cronexpr/APLv2 \
    github.com/hjson/hjson-go/build_release.sh \
    github.com/klauspost/compress/gen.sh \
    github.com/klauspost/compress/gzhttp \
    github.com/klauspost/compress/internal/snapref \
    github.com/klauspost/compress/s2* \
    github.com/klauspost/compress/snappy \
    github.com/klauspost/compress/zstd/snappy.go \
    golang.org/x/sys/plan9 \
    golang.org/x/sys/windows
find github.com/klauspost/compress golang.org/x/sys -name "*_test.go" -delete
find . -type d -exec rmdir {} + 2>/dev/null || :
cd ../..
rm -r ports
find . \( \
    -name .gitignore -o \
    -name .travis.yml -o \
    -name .goreleaser.yml -o \
    -name .gitattributes \) -delete

mkdir contrib
cp ~/work/redo/apenwarr/minimal/do contrib/do

cat > doc/download.texi <<EOF
@node Tarballs
@section Prepared tarballs
You can obtain releases source code prepared tarballs from
@url{http://www.nncpgo.org/} and from one of its
@url{http://www.nncpgo.org/Mirrors.html, mirrors}.
EOF
perl -i -ne 'print unless /include pedro/' doc/index.texi doc/about.ru.texi
perl -p -i -e 's/^(.verbatiminclude) .*$/$1 PUBKEY.asc/g' doc/integrity.texi
mv doc/.well-known/openpgpkey/nncpgo.org/hu/i4cdqgcarfjdjnba6y4jnf498asg8c6p.asc PUBKEY.asc
ln -s ../PUBKEY.asc doc
redo doc/all

########################################################################
# Supplementary files autogeneration
########################################################################
texi=$(TMPDIR=doc mktemp)

mkinfo() {
    ${MAKEINFO:-makeinfo} --plaintext \
        --set-customization-variable ASCII_PUNCTUATION=1 \
        -D "VERSION `cat VERSION`" $@
}

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle NEWS
@node News
@unnumbered News
`sed -n '6,$p' < doc/news.texi`
@bye
EOF
mkinfo --output NEWS $texi

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle NEWS.RU
@node Новости
@unnumbered Новости
`sed -n '3,$p' < doc/news.ru.texi | sed 's/^@subsection/@section/'`
@bye
EOF
mkinfo --output NEWS.RU $texi

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle INSTALL
@include install.texi
@bye
EOF
mkinfo --output INSTALL $texi

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle THANKS
`cat doc/thanks.texi`
@bye
EOF
mkinfo --output THANKS $texi

rm -f $texi
rm -r doc/.well-known

########################################################################

perl -i -npe "s/GO build/GO build -mod=vendor/" bin/default.do bin/hjson-cli.do
perl -i -npe "s/GO list/GO list -mod=vendor/" bin/default.do
perl -i -npe "s/GO test/GO test -mod=vendor/" test.do
rm makedist.sh VERSION.do
rm -r .git
redo-cleanup full
find . -type d -exec chmod 755 {} +
find . -type f -exec chmod 644 {} +
find . -type f -name "*.sh" -exec chmod +x {} +
chmod +x contrib/do

cd ..
tar cvf nncp-"$release".tar --uid=0 --gid=0 --numeric-owner nncp-"$release"
xz -9v nncp-"$release".tar
tarball=nncp-"$release".tar.xz
gpg --detach-sign --sign --local-user releases@nncpgo.org "$tarball"
gpg --enarmor < "$tarball".sig |
    sed "/^Comment:/d ; s/ARMORED FILE/SIGNATURE/" > "$tarball".asc
meta4-create -file "$tarball" -mtime "$tarball" -sig "$tarball".asc \
    http://www.nncpgo.org/download/"$tarball" \
    http://y.www.nncpgo.org/download/"$tarball" \
    https://nncp.mirrors.quux.org/download/"$tarball" > "$tarball".meta4

size=$(( $(stat -f %z $tarball) / 1024 ))
hash=$(gpg --print-md SHA256 < $tarball)
release_date=$(date "+%Y-%m-%d")

mv -v $tmp/"$tarball" $tmp/"$tarball".sig $tmp/"$tarball".meta4 $cur/doc/download

release_underscored=`echo $release | tr . _`
cat <<EOF
An entry for documentation:
@item @ref{Release $release_underscored, $release} @tab $release_date @tab $size KiB
@tab
    @url{download/nncp-${release}.tar.xz.meta4, meta4}
    @url{download/nncp-${release}.tar.xz, link}
    @url{download/nncp-${release}.tar.xz.sig, sig}
@tab @code{$hash}
EOF

cd $cur

cat <<EOF
Subject: [EN] NNCP $release release announcement

I am pleased to announce NNCP $release release availability!

NNCP (Node to Node copy) is a collection of utilities simplifying
secure store-and-forward files and mail exchanging.

This utilities are intended to help build up small size (dozens of
nodes) ad-hoc friend-to-friend (F2F) statically routed darknet
delay-tolerant networks for fire-and-forget secure reliable files, file
requests, Internet mail and commands transmission. All packets are
integrity checked, end-to-end encrypted (E2EE), explicitly authenticated
by known participants public keys. Onion encryption is applied to
relayed packets. Each node acts both as a client and server, can use
push and poll behaviour model. Also there is multicasting areas support.

Out-of-box offline sneakernet/floppynet, dead drops, sequential and
append-only CD-ROM/tape storages, air-gapped computers support. But
online TCP daemon with full-duplex resumable data transmission exists.

------------------------ >8 ------------------------

The main improvements for that release are:

$(git cat-file -p v$release | sed -n '6,/^.*BEGIN/p' | sed '$d')

------------------------ >8 ------------------------

NNCP's home page is: http://www.nncpgo.org/

Source code and its signature for that version can be found here:

    http://www.nncpgo.org/download/nncp-${release}.tar.xz ($size KiB)
    http://www.nncpgo.org/download/nncp-${release}.tar.xz.sig

SHA256 hash: $hash
GPG key ID: 0x2B25868E75A1A953 NNCP releases <releases@nncpgo.org>
Fingerprint: 92C2 F0AE FE73 208E 46BF  F3DE 2B25 868E 75A1 A953

There are mirrors where you can also get the source code tarballs:
http://www.nncpgo.org/Mirrors.html

Please send questions regarding the use of NNCP, bug reports and patches
to mailing list: http://lists.cypherpunks.ru/nncp_002ddevel.html
EOF
echo mutt -s \"[EN] NNCP $release release announcement\" \
    nncp-devel@lists.cypherpunks.ru \
    -a $cur/doc/download/"$tarball".meta4

cat <<EOF
Subject: [RU] Состоялся релиз NNCP $release

Я рад сообщить о выходе релиза NNCP $release!

NNCP (Node to Node copy) это набор утилит упрощающий безопасный обмен
файлами и почтой в режиме сохранить-и-переслать.

Эти утилиты предназначены помочь с построением одноранговых устойчивых к
разрывам сетей небольшого размера (дюжины узлов), в режиме друг-к-другу
(F2F) со статической маршрутизацией для безопасной надёжной передачи
файлов, запросов на передачу файлов, Интернет почты и команд по принципу
выстрелил-и-забыл. Все пакеты проверяются на целостность, шифруются по
принципу точка-точка (E2EE), аутентифицируются известными публичными
ключами участников. Луковичное (onion) шифрование применяется ко всем
ретранслируемым пакетам. Каждый узел выступает одновременно в роли
клиента и сервера, может использовать как push, так и poll модель
поведения. А также есть поддержка мультивещательной рассылки пакетов.

Поддержка из коробки offline флоппинета, тайников для сброса информации
(dead drop), последовательных и только-для-записи CD-ROM/ленточных
хранилищ, компьютеров с "воздушным зазором" (air-gap). Но также
существует и online TCP демон с полнодуплексной возобновляемой передачей
данных.

------------------------ >8 ------------------------

Основные усовершенствования в этом релизе:

$(git cat-file -p v$release | sed -n '6,/^.*BEGIN/p' | sed '$d')

------------------------ >8 ------------------------

Домашняя страница NNCP: http://www.nncpgo.org/
Коротко об утилитах: http://www.nncpgo.org/Ob-utilitakh.html

Исходный код и его подпись для этой версии находятся здесь:

    http://www.nncpgo.org/download/nncp-${release}.tar.xz ($size KiB)
    http://www.nncpgo.org/download/nncp-${release}.tar.xz.sig

SHA256 хэш: $hash
Идентификатор GPG ключа: 0x2B25868E75A1A953 NNCP releases <releases@nncpgo.org>
Отпечаток: 92C2 F0AE FE73 208E 46BF  F3DE 2B25 868E 75A1 A953

Есть и зеркала где вы также можете получить архивы с исходным кодом:
http://www.nncpgo.org/Mirrors.html

Пожалуйста, все вопросы касающиеся использования NNCP, отчёты об ошибках
и патчи отправляйте в nncp-devel почтовую рассылку:
http://lists.cypherpunks.ru/nncp_002ddevel.html
EOF
echo mutt -s \"[RU] Состоялся релиз NNCP $release\" \
    nncp-devel@lists.cypherpunks.ru \
    -a $cur/doc/download/"$tarball".meta4
