#!/bin/sh

testname=`basename "$0"`
test_description="nncp-rm's behaviour"
. $SHARNESS_TEST_SRCDIR/sharness.sh

rand32() {
    perl <<EOF
open(\$rnd, "<", "/dev/urandom") or die \$!;
read(\$rnd, \$data, 32) or die \$!;
use MIME::Base32;
print MIME::Base32::encode \$data;
print "\n";
EOF
}

randpkts() {
    for i in $(seq $(jot -r 1 10 20)) ; do rand32 ; done
}

PKTS=""
pkts_remove() {
    perl <<EOF
map { \$all{\$_} = 1 } qw($PKTS);
map { delete \$all{\$_} } qw($@);
print join " ", keys %all;
EOF
}

assert_is_deleted() {
    for pkt in $@ ; do
        if [ -e $pkt ] ; then
            echo unexpectedly existing: $pkt >&2
            return 1
        fi
    done
    local pkts=""
    for pkt in `pkts_remove $@` ; do
        if ! [ -e $pkt ] ; then
            echo unexpectedly removed: $pkt >&2
            return 1
        fi
        pkts="$pkts $pkt"
    done
    PKTS="$pkts"
}

now=`date +%s`
nncp-cfgnew > cfg
nncp-cfgdir -cfg cfg -dump cfgdir
echo "$PWD/spool" > cfgdir/spool
echo "$PWD/log" > cfgdir/log
neigh=`rand32`
mkdir -p cfgdir/neigh/neigh
for w in id exchpub signpub ; do echo $neigh > cfgdir/neigh/neigh/$w ; done
mkdir -p spool/tmp spool/$neigh/rx/hdr spool/$neigh/rx/seen spool/$neigh/tx/hdr
date_old=$(date -j -f %s +%FT%T $(( $now - (3600 * 24 * 7) )))

pkts_old_rx=""
pkts_old_rx_hdr=""
for pkt in `randpkts` ; do
    touch -d $date_old spool/$neigh/rx/$pkt spool/$neigh/rx/hdr/$pkt
    pkts_old_rx="$pkts_old_rx spool/$neigh/rx/$pkt"
    pkts_old_rx_hdr="$pkts_old_rx_hdr spool/$neigh/rx/hdr/$pkt"
done

pkts_old_tx=""
pkts_old_tx_hdr=""
for pkt in `randpkts` ; do
    touch -d $date_old spool/$neigh/tx/$pkt spool/$neigh/tx/hdr/$pkt
    pkts_old_tx="$pkts_old_tx spool/$neigh/tx/$pkt"
    pkts_old_tx_hdr="$pkts_old_tx_hdr spool/$neigh/tx/hdr/$pkt"
done

pkts_old_part=""
for pkt in `randpkts` ; do
    touch -d $date_old spool/$neigh/rx/$pkt.part
    pkts_old_part="$pkts_old_part spool/$neigh/rx/$pkt.part"
done

pkts_old_nock=""
for pkt in `randpkts` ; do
    touch -d $date_old spool/$neigh/rx/$pkt.nock
    pkts_old_nock="$pkts_old_nock spool/$neigh/rx/$pkt.nock"
done

pkts_old_seen=""
for pkt in `randpkts` ; do
    touch -d $date_old spool/$neigh/rx/seen/$pkt
    pkts_old_seen="$pkts_old_seen spool/$neigh/rx/seen/$pkt"
done

pkts_new_rx=""
pkts_new_rx_hdr=""
for pkt in `randpkts` ; do
    touch spool/$neigh/rx/$pkt spool/$neigh/rx/hdr/$pkt
    pkts_new_rx="$pkts_new_rx spool/$neigh/rx/$pkt"
    pkts_new_rx_hdr="$pkts_new_rx_hdr spool/$neigh/rx/hdr/$pkt"
done

pkts_new_tx=""
pkts_new_tx_hdr=""
for pkt in `randpkts` ; do
    touch spool/$neigh/tx/$pkt spool/$neigh/tx/hdr/$pkt
    pkts_new_tx="$pkts_new_tx spool/$neigh/tx/$pkt"
    pkts_new_tx_hdr="$pkts_new_tx_hdr spool/$neigh/tx/hdr/$pkt"
done

pkts_new_part=""
for pkt in `randpkts` ; do
    touch spool/$neigh/rx/$pkt.part
    pkts_new_part="$pkts_new_part spool/$neigh/rx/$pkt.part"
done

pkts_new_nock=""
for pkt in `randpkts` ; do
    touch spool/$neigh/rx/$pkt.nock
    pkts_new_nock="$pkts_new_nock spool/$neigh/rx/$pkt.nock"
done

pkts_new_seen=""
for pkt in `randpkts` ; do
    touch spool/$neigh/rx/seen/$pkt
    pkts_new_seen="$pkts_new_seen spool/$neigh/rx/seen/$pkt"
done

pkts_tmp_old=""
for pkt in `randpkts` ; do
    touch -d $date_old spool/tmp/$pkt
    pkts_tmp_old="$pkts_tmp_old spool/tmp/$pkt"
done

pkts_tmp_new=""
for pkt in `randpkts` ; do
    touch spool/tmp/$pkt
    pkts_tmp_new="$pkts_tmp_new spool/tmp/$pkt"
done

pkts_hdr_excess_old_rx=""
for pkt in `randpkts` ; do
    touch -d $date_old spool/$neigh/rx/hdr/$pkt
    pkts_hdr_excess_old_rx="$pkts_hdr_excess_old_rx spool/$neigh/rx/hdr/$pkt"
done

pkts_hdr_excess_old_tx=""
for pkt in `randpkts` ; do
    touch -d $date_old spool/$neigh/tx/hdr/$pkt
    pkts_hdr_excess_old_tx="$pkts_hdr_excess_old_tx spool/$neigh/tx/hdr/$pkt"
done

pkts_hdr_excess_new_rx=""
for pkt in `randpkts` ; do
    touch spool/$neigh/rx/hdr/$pkt
    pkts_hdr_excess_new_rx="$pkts_hdr_excess_new_rx spool/$neigh/rx/hdr/$pkt"
done

pkts_hdr_excess_new_tx=""
for pkt in `randpkts` ; do
    touch spool/$neigh/tx/hdr/$pkt
    pkts_hdr_excess_new_tx="$pkts_hdr_excess_new_tx spool/$neigh/tx/hdr/$pkt"
done

pkts_area_old=""
pkts_area_new=""
for area in `randpkts` ; do
    mkdir -p spool/$neigh/area/$area
    for pkt in `randpkts` ; do
        touch -d $date_old spool/$neigh/area/$area/$pkt
        pkts_area_old="$pkts_area_old spool/$neigh/area/$area/$pkt"
    done
    for pkt in `randpkts` ; do
        touch spool/$neigh/area/$area/$pkt
        pkts_area_new="$pkts_area_new spool/$neigh/area/$area/$pkt"
    done
done

pkts_specified=""
for pkt in `randpkts` ; do
    touch spool/$neigh/rx/$pkt
    pkts_specified="$pkts_specified spool/$neigh/rx/$pkt"
done
for pkt in `randpkts` ; do
    touch spool/$neigh/tx/$pkt
    pkts_specified="$pkts_specified spool/$neigh/tx/$pkt"
done
for pkt in `randpkts` ; do
    touch spool/$neigh/rx/seen/$pkt
    pkts_specified="$pkts_specified spool/$neigh/rx/seen/$pkt"
done

PKTS="
$pkts_old_rx
$pkts_old_rx_hdr
$pkts_old_tx
$pkts_old_tx_hdr
$pkts_old_part
$pkts_old_nock
$pkts_old_seen
$pkts_new_rx
$pkts_new_rx_hdr
$pkts_new_tx
$pkts_new_tx_hdr
$pkts_new_part
$pkts_new_nock
$pkts_new_seen
$pkts_tmp_old
$pkts_tmp_new
$pkts_hdr_excess_old_rx
$pkts_hdr_excess_old_tx
$pkts_hdr_excess_new_rx
$pkts_hdr_excess_new_tx
$pkts_area_old
$pkts_area_new
$pkts_specified
"
rmcmd="nncp-rm -quiet -cfg cfgdir -all"
older="-older 6d"

$rmcmd -pkt <<EOF
$pkts_specified
EOF
test_expect_success "Only -pkt" "assert_is_deleted $pkts_specified"

$rmcmd $older -tmp
test_expect_success "Old -tmp" "assert_is_deleted $pkts_tmp_old"

$rmcmd -tmp
test_expect_success "All -tmp" "assert_is_deleted $pkts_tmp_new"

$rmcmd $older -part
test_expect_success "Old -part" "assert_is_deleted $pkts_old_part"

$rmcmd -part
test_expect_success "All -part" "assert_is_deleted $pkts_new_part"

$rmcmd $older -nock
test_expect_success "Old -nock" "assert_is_deleted $pkts_old_nock"

$rmcmd -nock
test_expect_success "All -nock" "assert_is_deleted $pkts_new_nock"

$rmcmd $older -rx
test_expect_success "Old -rx" "assert_is_deleted $pkts_old_rx $pkts_old_rx_hdr"

$rmcmd $older -tx
test_expect_success "Old -tx" "assert_is_deleted $pkts_old_tx $pkts_old_tx_hdr"

$rmcmd -rx
test_expect_success "All -rx" "assert_is_deleted $pkts_new_rx $pkts_new_rx_hdr"

$rmcmd -tx
test_expect_success "All -tx" "assert_is_deleted $pkts_new_tx $pkts_new_tx_hdr"

$rmcmd $older -seen
test_expect_success "Old -seen" "assert_is_deleted $pkts_old_seen"

$rmcmd -seen
test_expect_success "All -seen" "assert_is_deleted $pkts_new_seen"

$rmcmd $older -rx -hdr
test_expect_success "Old -rx -hdr" "assert_is_deleted $pkts_hdr_excess_old_rx"

$rmcmd $older -tx -hdr
test_expect_success "Old -tx -hdr" "assert_is_deleted $pkts_hdr_excess_old_tx"

$rmcmd -rx -hdr
test_expect_success "All -rx -hdr" "assert_is_deleted $pkts_hdr_excess_new_rx"

$rmcmd -tx -hdr
test_expect_success "All -tx -hdr" "assert_is_deleted $pkts_hdr_excess_new_tx"

$rmcmd $older -area
test_expect_success "Old -area" "assert_is_deleted $pkts_area_old"

$rmcmd -area
test_expect_success "All -area" "assert_is_deleted $pkts_area_new"

test_done
