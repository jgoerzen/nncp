/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2019 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Parse raw NNCP packet.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/klauspost/compress/zstd"
	"go.cypherpunks.ru/nncp/v5"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-pkt -- parse raw packet\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "Packet is read from stdin.")
}

func main() {
	var (
		overheads  = flag.Bool("overheads", false, "Print packet overheads")
		dump       = flag.Bool("dump", false, "Write decrypted/parsed payload to stdout")
		decompress = flag.Bool("decompress", false, "Try to zstd decompress dumped data")
		cfgPath    = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		version    = flag.Bool("version", false, "Print version information")
		warranty   = flag.Bool("warranty", false, "Print warranty information")
	)
	flag.Usage = usage
	flag.Parse()
	if *warranty {
		fmt.Println(nncp.Warranty)
		return
	}
	if *version {
		fmt.Println(nncp.VersionGet())
		return
	}

	if *overheads {
		fmt.Printf(
			"Plain: %d\nEncrypted: %d\nSize: %d\n",
			nncp.PktOverhead,
			nncp.PktEncOverhead,
			nncp.PktSizeOverhead,
		)
		return
	}

	var err error
	beginning := make([]byte, nncp.PktOverhead)
	if _, err = io.ReadFull(os.Stdin, beginning); err != nil {
		log.Fatalln("Not enough data to read")
	}
	var pkt nncp.Pkt
	_, err = xdr.Unmarshal(bytes.NewReader(beginning), &pkt)
	if err == nil && pkt.Magic == nncp.MagicNNCPPv3 {
		if *dump {
			bufW := bufio.NewWriter(os.Stdout)
			var r io.Reader
			r = bufio.NewReader(os.Stdin)
			if *decompress {
				decompressor, err := zstd.NewReader(r)
				if err != nil {
					log.Fatalln(err)
				}
				r = decompressor
			}
			if _, err = io.Copy(bufW, r); err != nil {
				log.Fatalln(err)
			}
			if err = bufW.Flush(); err != nil {
				log.Fatalln(err)
			}
			return
		}
		payloadType := "unknown"
		switch pkt.Type {
		case nncp.PktTypeFile:
			payloadType = "file"
		case nncp.PktTypeFreq:
			payloadType = "file request"
		case nncp.PktTypeExec:
			payloadType = "exec"
		case nncp.PktTypeTrns:
			payloadType = "transitional"
		}
		var path string
		switch pkt.Type {
		case nncp.PktTypeExec:
			path = string(bytes.Replace(
				pkt.Path[:pkt.PathLen],
				[]byte{0},
				[]byte(" "),
				-1,
			))
		case nncp.PktTypeTrns:
			path = nncp.ToBase32(pkt.Path[:pkt.PathLen])
		default:
			path = string(pkt.Path[:pkt.PathLen])
		}
		fmt.Printf(
			"Packet type: plain\nPayload type: %s\nNiceness: %s (%d)\nPath: %s\n",
			payloadType, nncp.NicenessFmt(pkt.Nice), pkt.Nice, path,
		)
		return
	}
	var pktEnc nncp.PktEnc
	_, err = xdr.Unmarshal(bytes.NewReader(beginning), &pktEnc)
	if err == nil && pktEnc.Magic == nncp.MagicNNCPEv4 {
		if *dump {
			ctx, err := nncp.CtxFromCmdline(*cfgPath, "", "", false, false)
			if err != nil {
				log.Fatalln("Error during initialization:", err)
			}
			if ctx.Self == nil {
				log.Fatalln("Config lacks private keys")
			}
			bufW := bufio.NewWriter(os.Stdout)
			if _, _, err = nncp.PktEncRead(
				ctx.Self,
				ctx.Neigh,
				io.MultiReader(
					bytes.NewReader(beginning),
					bufio.NewReader(os.Stdin),
				),
				bufW,
			); err != nil {
				log.Fatalln(err)
			}
			if err = bufW.Flush(); err != nil {
				log.Fatalln(err)
			}
			return
		}
		fmt.Printf(
			"Packet type: encrypted\nNiceness: %s (%d)\nSender: %s\nRecipient: %s\n",
			nncp.NicenessFmt(pktEnc.Nice), pktEnc.Nice, pktEnc.Sender, pktEnc.Recipient,
		)
		return
	}
	log.Fatalln("Unable to determine packet type")
}
