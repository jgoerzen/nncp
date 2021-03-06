/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2020 Sergey Matveev <stargrave@stargrave.org>

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

// NNCP configuration file encrypter/decrypter.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"go.cypherpunks.ru/nncp/v5"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ssh/terminal"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-cfgenc -- encrypt/decrypt configuration file\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] cfg.hjson > cfg.hjson.eblob\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] -d cfg.hjson.eblob > cfg.hjson\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] -dump cfg.hjson.eblob\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
}

func main() {
	var (
		decrypt  = flag.Bool("d", false, "Decrypt the file")
		dump     = flag.Bool("dump", false, "Print human-readable eblob information")
		sOpt     = flag.Int("s", nncp.DefaultS, "Balloon space cost, in 32 bytes chunks")
		tOpt     = flag.Int("t", nncp.DefaultT, "Balloon time cost, number of rounds")
		pOpt     = flag.Int("p", nncp.DefaultP, "Balloon number of parallel jobs")
		version  = flag.Bool("version", false, "Print version information")
		warranty = flag.Bool("warranty", false, "Print warranty information")
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

	if flag.NArg() != 1 {
		usage()
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatalln("Can not read data:", err)
	}
	if *dump {
		var eblob nncp.EBlob
		if _, err := xdr.Unmarshal(bytes.NewReader(data), &eblob); err != nil {
			log.Fatalln(err)
		}
		if eblob.Magic != nncp.MagicNNCPBv3 {
			log.Fatalln(errors.New("Unknown eblob type"))
		}
		fmt.Println("Strengthening function: Balloon with BLAKE2b-256")
		fmt.Printf("Memory space cost: %d bytes\n", eblob.SCost*blake2b.Size256)
		fmt.Printf("Number of rounds: %d\n", eblob.TCost)
		fmt.Printf("Number of parallel jobs: %d\n", eblob.PCost)
		fmt.Printf("Blob size: %d\n", len(eblob.Blob))
		return
	}

	os.Stderr.WriteString("Passphrase:") // #nosec G104
	password, err := terminal.ReadPassword(0)
	if err != nil {
		log.Fatalln(err)
	}
	os.Stderr.WriteString("\n") // #nosec G104

	if *decrypt {
		cfgRaw, err := nncp.DeEBlob(data, password)
		if err != nil {
			log.Fatalln(err)
		}
		os.Stdout.Write(cfgRaw) // #nosec G104
		return
	}

	password1, err := terminal.ReadPassword(0)
	if err != nil {
		log.Fatalln(err)
	}
	os.Stderr.WriteString("\n")                 // #nosec G104
	os.Stderr.WriteString("Repeat passphrase:") // #nosec G104
	password2, err := terminal.ReadPassword(0)
	if err != nil {
		log.Fatalln(err)
	}
	os.Stderr.WriteString("\n") // #nosec G104
	if bytes.Compare(password1, password2) != 0 {
		log.Fatalln(errors.New("Passphrases do not match"))
	}
	eblob, err := nncp.NewEBlob(*sOpt, *tOpt, *pOpt, password1, data)
	if err != nil {
		log.Fatalln(err)
	}
	os.Stdout.Write(eblob) // #nosec G104
}
