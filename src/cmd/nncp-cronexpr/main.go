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

// NNCP cron expression checker.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gorhill/cronexpr"
	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-cronexpr -- cron expression checker\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [-num XXX] CRON-EXPRESSION\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		num      = flag.Uint("num", 10, "Number of future entries to print")
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

	expr, err := cronexpr.Parse(strings.Join(flag.Args(), " "))
	if err != nil {
		log.Fatalln(err)
	}
	now := time.Now()
	fmt.Printf("Now:\t%s\n", now.UTC().Format(time.RFC3339Nano))
	for n, t := range expr.NextN(now, *num) {
		fmt.Printf("%d:\t%s\n", n, t.UTC().Format(time.RFC3339Nano))
	}
}
