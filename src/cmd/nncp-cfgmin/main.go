/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2022 Sergey Matveev <stargrave@stargrave.org>

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

// Stripped NNCP configuration file.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/hjson/hjson-go"
	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-cfgmin -- print stripped configuration\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath  = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		version  = flag.Bool("version", false, "Print version information")
		warranty = flag.Bool("warranty", false, "Print warranty information")
	)
	log.SetFlags(log.Lshortfile)
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

	ctx, err := nncp.CtxFromCmdline(*cfgPath, "", "", false, false, false, false)
	if err != nil {
		log.Fatalln("Error during initialization:", err)
	}

	cfg := nncp.CfgJSON{
		Spool: ctx.Spool,
		Log:   ctx.LogPath,
		Neigh: make(map[string]nncp.NodeJSON),
	}
	for _, node := range ctx.Neigh {
		var noisePub *string
		if node.NoisePub != nil {
			np := nncp.Base32Codec.EncodeToString(node.NoisePub[:])
			noisePub = &np
		}
		cfg.Neigh[node.Name] = nncp.NodeJSON{
			Id:       node.Id.String(),
			ExchPub:  nncp.Base32Codec.EncodeToString(node.ExchPub[:]),
			SignPub:  nncp.Base32Codec.EncodeToString(node.SignPub[:]),
			NoisePub: noisePub,
		}
	}
	raw, err := hjson.Marshal(&cfg)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(raw))
}
