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

// Generate new NNCP node keys and configuration file
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/hjson/hjson-go"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"

	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintln(os.Stderr, "nncp-cfgnew -- generate new configuration and keys\nOptions:")
	flag.PrintDefaults()
}

func main() {
	var (
		areaName   = flag.String("area", "", "Generate area's keypairs")
		yggdrasil  = flag.Bool("yggdrasil", false, "Generate Yggdrasil keypair")
		noComments = flag.Bool("nocomments", false, "Do not include descriptive comments")
		version    = flag.Bool("version", false, "Print version information")
		warranty   = flag.Bool("warranty", false, "Print warranty information")
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

	if *yggdrasil {
		pub, prv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println("Public:", hex.EncodeToString(pub))
		fmt.Println("Private:", hex.EncodeToString(prv))
		return
	}

	if *areaName != "" {
		pub, prv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalln(err)
		}
		areaId := nncp.AreaId(blake2b.Sum256(pub[:]))
		var cfgRaw string
		if *noComments {
			cfgRaw = fmt.Sprintf(`areas: {
  %s: {
    id: %s
    # KEEP AWAY keypair from the nodes you want only participate in multicast
    pub: %s
    prv: %s
  }
}`,
				*areaName,
				areaId.String(),
				nncp.Base32Codec.EncodeToString(pub[:]),
				nncp.Base32Codec.EncodeToString(prv[:]),
			)
		} else {
			cfgRaw = fmt.Sprintf(`areas: {
  %s: {
    id: %s

    # KEEP AWAY keypair from the nodes you want only participate in multicast
    pub: %s
    prv: %s

    # List of subscribers you should multicast area messages to
    # subs: ["alice"]

    # Allow incoming files (from the area) saving in that directory
    # incoming: /home/areas/%s/incoming

    # Allow incoming area commands execution
    # exec: {sendmail: ["%s"]}

    # Allow unknown sender's message tossing (relaying will be made anyway)
    # allow-unknown: true
  }
}`,
				*areaName,
				areaId.String(),
				nncp.Base32Codec.EncodeToString(pub[:]),
				nncp.Base32Codec.EncodeToString(prv[:]),
				*areaName,
				nncp.DefaultSendmailPath,
			)
		}
		var cfgGeneral map[string]interface{}
		if err = hjson.Unmarshal([]byte(cfgRaw), &cfgGeneral); err != nil {
			panic(err)
		}
		marshaled, err := json.Marshal(cfgGeneral)
		if err != nil {
			panic(err)
		}
		var areas map[string]nncp.AreaJSON
		if err = json.Unmarshal(marshaled, &areas); err != nil {
			panic(err)
		}
		fmt.Println(cfgRaw)
		return
	}

	nodeOur, err := nncp.NewNodeGenerate()
	if err != nil {
		log.Fatalln(err)
	}
	var cfgRaw string
	if *noComments {
		cfgRaw = fmt.Sprintf(`{
  spool: %s
  log: %s

  self: {
    # DO NOT show anyone your private keys!!!
    id: %s
    exchpub: %s
    exchprv: %s
    signpub: %s
    signprv: %s
    noiseprv: %s
    noisepub: %s
  }

  neigh: {
    self: {
      id: %s
      exchpub: %s
      signpub: %s
      noisepub: %s
      exec: {sendmail: ["%s"]}
    }
  }
}`,
			nncp.DefaultSpoolPath,
			nncp.DefaultLogPath,
			nodeOur.Id.String(),
			nncp.Base32Codec.EncodeToString(nodeOur.ExchPub[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.ExchPrv[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.SignPub[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.SignPrv[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.NoisePrv[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.NoisePub[:]),
			nodeOur.Id.String(),
			nncp.Base32Codec.EncodeToString(nodeOur.ExchPub[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.SignPub[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.NoisePub[:]),
			nncp.DefaultSendmailPath,
		)
	} else {
		cfgRaw = fmt.Sprintf(`{
  # Path to encrypted packets spool directory
  spool: %s
  # Path to log file
  log: %s
  # Enforce specified umask usage
  # umask: "022"
  # Omit progress showing by default
  # noprogress: true
  # Do not use hdr/ files
  # nohdr: true

  # MultiCast Discovery:
  # List of interface regular expressions where to listen for MCD announcements
  mcd-listen: [".*"]
  # Interfaces regular expressions and intervals (in seconds) where to send
  # MCD announcements
  mcd-send: {.*: 10}

  # Yggdrasil related aliases:
  # yggdrasil-aliases: {
  #   myprv: 60bb...27aa
  #   bob-pub: 98de...ac19d
  #   alice-endpoint: tcp://example.com:1234?key=689c...13fb
  #   default-endpoints: tcp://[::1]:2345,alice-endpoint
  # }

  # Enable notification email sending
  # notify: {
  #   file: {
  #     from: nncp@localhost
  #     to: user+file@example.com
  #   }
  #   freq: {
  #     from: nncp@localhost
  #     to: user+freq@example.com
  #   }
  #   # Send some exec commands execution notifications
  #   exec: {
  #     # bob neighbour's "somehandle" notification
  #     bob.somehandle: {
  #       from: nncp+bob@localhost
  #       to: user+somehandle@example.com
  #     }
  #     # Any neighboor's "anotherhandle"
  #     *.anotherhandle: {
  #       from: nncp@localhost
  #       to: user+anotherhandle@example.com
  #     }
  #   }
  # }

  self: {
    # DO NOT show anyone your private keys!!!
    id: %s
    exchpub: %s
    exchprv: %s
    signpub: %s
    signprv: %s
    noiseprv: %s
    noisepub: %s
  }

  neigh: {
    self: {
      # You should give public keys below to your neighbours
      id: %s
      exchpub: %s
      signpub: %s
      noisepub: %s

      exec: {
        # Default self's sendmail command is used for email notifications sending
        sendmail: ["%s"]
      }
    }

    # Example neighbour, most of fields are optional
    # alice: {
    #   id: XJZBK...65IJQ
    #   exchpub: MJACJ...FAI6A
    #   signpub: T4AFC...N2FRQ
    #   noisepub: UBM5K...VI42A
    #
    #   # He is allowed to send email
    #   # exec: {sendmail: ["%s"]}
    #
    #   # Allow incoming files saving in that directory
    #   # incoming: "/home/alice/incoming"
    #
    #   # Transitional nodes path
    #   # via: ["bob", "eve"]
    #
    #   # Inactivity timeout when session with remote peer should be terminated
    #   # onlinedeadline: 1800
    #
    #   # Maximal online session lifetime
    #   # maxonlinetime: 3600
    #
    #   # If neither freq section, nor freq.path exist, then no freqing allowed
    #   # freq: {
    #   #   # Allow freqing from that directory
    #   #   path: "/home/bob/pub"
    #   #   # Send freqed files with chunks
    #   #   # chunked: 1024
    #   #   # Send freqed files with minumal chunk size
    #   #   # minsize: 2048
    #   #   # Maximal allowable freqing file size
    #   #   # maxsize: 4096
    #   # }
    #
    #   # Set maximal packets per second receive and transmit rates
    #   # rxrate: 10
    #   # txrate: 20
    #
    #   # Address aliases
    #   # addrs: {
    #   #   lan: "[fe80::1234%%igb0]:5400"
    #   #   internet: alice.com:3389
    #   # }
    #
    #   # Calls configuration
    #   # calls: [
    #   #   {
    #   #     cron: "*/2 * * * *"
    #   #     onlinedeadline: 1800
    #   #     maxonlinetime: 1750
    #   #     nice: PRIORITY+10
    #   #     rxrate: 10
    #   #     txrate: 20
    #   #     xx: rx
    #   #     addr: lan
    #   #     when-tx-exists: true
    #   #     nock: true
    #   #     mcd-ignore: true
    #   #
    #   #     autotoss: false
    #   #     autotoss-doseen: true
    #   #     autotoss-nofile: true
    #   #     autotoss-nofreq: true
    #   #     autotoss-noexec: true
    #   #     autotoss-notrns: true
    #   #   }
    #   # ]
    # }
  }
}`,
			nncp.DefaultSpoolPath,
			nncp.DefaultLogPath,
			nodeOur.Id.String(),
			nncp.Base32Codec.EncodeToString(nodeOur.ExchPub[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.ExchPrv[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.SignPub[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.SignPrv[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.NoisePrv[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.NoisePub[:]),
			nodeOur.Id.String(),
			nncp.Base32Codec.EncodeToString(nodeOur.ExchPub[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.SignPub[:]),
			nncp.Base32Codec.EncodeToString(nodeOur.NoisePub[:]),
			nncp.DefaultSendmailPath,
			nncp.DefaultSendmailPath,
		)
	}
	if _, err = nncp.CfgParse([]byte(cfgRaw)); err != nil {
		panic(err)
	}
	fmt.Println(cfgRaw)
}
