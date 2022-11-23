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

// Convert NNCP Hjson configuration file to the directory layout.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/hjson/hjson-go"
	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-cfgdir -- Convert configuration file to the directory layout.\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [-cfg ...] -dump /path/to/dir\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] -load /path/to/dir > cfg.hjson\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		doDump   = flag.Bool("dump", false, "Dump configuration file to the directory")
		doLoad   = flag.Bool("load", false, "Load directory to create configuration file")
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

	if (!*doDump && !*doLoad) || flag.NArg() != 1 {
		usage()
		os.Exit(1)
	}

	if *doDump {
		cfgRaw, err := ioutil.ReadFile(*cfgPath)
		if err != nil {
			log.Fatalln(err)
		}
		cfg, err := nncp.CfgParse(cfgRaw)
		if err != nil {
			log.Fatalln(err)
		}
		if err = nncp.CfgToDir(flag.Arg(0), cfg); err != nil {
			log.Fatalln(err)
		}
	}
	if *doLoad {
		cfg, err := nncp.DirToCfg(flag.Arg(0))
		if err != nil {
			log.Fatalln(err)
		}
		if _, err = nncp.Cfg2Ctx(cfg); err != nil {
			log.Fatalln(err)
		}
		marshaled, err := hjson.MarshalWithOptions(cfg, hjson.EncoderOptions{
			Eol:            "\n",
			BracesSameLine: true,
			QuoteAlways:    false,
			IndentBy:       "  ",
			AllowMinusZero: false,
		})
		if err != nil {
			log.Fatalln(err)
		}
		os.Stdout.Write(marshaled)
		os.Stdout.WriteString("\n")
	}
}
