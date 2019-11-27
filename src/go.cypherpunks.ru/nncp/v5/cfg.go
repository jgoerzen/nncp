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

package nncp

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path"
	"strconv"

	"github.com/gorhill/cronexpr"
	"github.com/hjson/hjson-go"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	CfgPathEnv  = "NNCPCFG"
	CfgSpoolEnv = "NNCPSPOOL"
	CfgLogEnv   = "NNCPLOG"
)

var (
	DefaultCfgPath      string = "/usr/local/etc/nncp.hjson"
	DefaultSendmailPath string = "/usr/sbin/sendmail"
	DefaultSpoolPath    string = "/var/spool/nncp"
	DefaultLogPath      string = "/var/spool/nncp/log"
)

type NodeJSON struct {
	Id       string              `json:"id"`
	ExchPub  string              `json:"exchpub"`
	SignPub  string              `json:"signpub"`
	NoisePub *string             `json:"noisepub,omitempty"`
	Exec     map[string][]string `json:"exec,omitempty"`
	Incoming *string             `json:"incoming,omitempty"`
	Freq     *NodeFreqJSON       `json:"freq,omitempty"`
	Via      []string            `json:"via,omitempty"`
	Calls    []CallJSON          `json:"calls,omitempty"`

	Addrs map[string]string `json:"addrs,omitempty"`

	RxRate         *int  `json:"rxrate,omitempty"`
	TxRate         *int  `json:"txrate,omitempty"`
	OnlineDeadline *uint `json:"onlinedeadline,omitempty"`
	MaxOnlineTime  *uint `json:"maxonlinetime,omitempty"`
}

type NodeFreqJSON struct {
	Path    *string `json:"path,omitempty"`
	Chunked *uint64 `json:"chunked,omitempty"`
	MinSize *uint64 `json:"minsize,omitempty"`
	MaxSize *uint64 `json:"maxsize,omitempty"`
}

type CallJSON struct {
	Cron           string
	Nice           *string `json:"nice,omitempty"`
	Xx             *string `json:"xx,omitempty"`
	RxRate         *int    `json:"rxrate,omitempty"`
	TxRate         *int    `json:"txrate,omitempty"`
	Addr           *string `json:"addr,omitempty"`
	OnlineDeadline *uint   `json:"onlinedeadline,omitempty"`
	MaxOnlineTime  *uint   `json:"maxonlinetime,omitempty"`
}

type NodeOurJSON struct {
	Id       string `json:"id"`
	ExchPub  string `json:"exchpub"`
	ExchPrv  string `json:"exchprv"`
	SignPub  string `json:"signpub"`
	SignPrv  string `json:"signprv"`
	NoisePrv string `json:"noiseprv"`
	NoisePub string `json:"noisepub"`
}

type FromToJSON struct {
	From string
	To   string
}

type NotifyJSON struct {
	File *FromToJSON            `json:"file,omitempty"`
	Freq *FromToJSON            `json:"freq,omitempty"`
	Exec map[string]*FromToJSON `json:"exec,omitempty"`
}

type CfgJSON struct {
	Spool string `json:"spool"`
	Log   string `json:"log"`
	Umask string `json:"umask",omitempty`

	Notify *NotifyJSON `json:"notify,omitempty"`

	Self  *NodeOurJSON        `json:"self"`
	Neigh map[string]NodeJSON `json:"neigh"`
}

func NewNode(name string, yml NodeJSON) (*Node, error) {
	nodeId, err := NodeIdFromString(yml.Id)
	if err != nil {
		return nil, err
	}

	exchPub, err := FromBase32(yml.ExchPub)
	if err != nil {
		return nil, err
	}
	if len(exchPub) != 32 {
		return nil, errors.New("Invalid exchPub size")
	}

	signPub, err := FromBase32(yml.SignPub)
	if err != nil {
		return nil, err
	}
	if len(signPub) != ed25519.PublicKeySize {
		return nil, errors.New("Invalid signPub size")
	}

	var noisePub []byte
	if yml.NoisePub != nil {
		noisePub, err = FromBase32(*yml.NoisePub)
		if err != nil {
			return nil, err
		}
		if len(noisePub) != 32 {
			return nil, errors.New("Invalid noisePub size")
		}
	}

	var incoming *string
	if yml.Incoming != nil {
		inc := path.Clean(*yml.Incoming)
		if !path.IsAbs(inc) {
			return nil, errors.New("Incoming path must be absolute")
		}
		incoming = &inc
	}

	var freqPath *string
	freqChunked := int64(MaxFileSize)
	var freqMinSize int64
	freqMaxSize := int64(MaxFileSize)
	if yml.Freq != nil {
		f := yml.Freq
		if f.Path != nil {
			fPath := path.Clean(*f.Path)
			if !path.IsAbs(fPath) {
				return nil, errors.New("freq.path path must be absolute")
			}
			freqPath = &fPath
		}
		if f.Chunked != nil {
			if *f.Chunked == 0 {
				return nil, errors.New("freq.chunked value must be greater than zero")
			}
			freqChunked = int64(*f.Chunked) * 1024
		}
		if f.MinSize != nil {
			freqMinSize = int64(*f.MinSize) * 1024
		}
		if f.MaxSize != nil {
			freqMaxSize = int64(*f.MaxSize) * 1024
		}
	}

	defRxRate := 0
	if yml.RxRate != nil && *yml.RxRate > 0 {
		defRxRate = *yml.RxRate
	}
	defTxRate := 0
	if yml.TxRate != nil && *yml.TxRate > 0 {
		defTxRate = *yml.TxRate
	}

	defOnlineDeadline := uint(DefaultDeadline)
	if yml.OnlineDeadline != nil {
		if *yml.OnlineDeadline <= 0 {
			return nil, errors.New("OnlineDeadline must be at least 1 second")
		}
		defOnlineDeadline = *yml.OnlineDeadline
	}
	var defMaxOnlineTime uint
	if yml.MaxOnlineTime != nil {
		defMaxOnlineTime = *yml.MaxOnlineTime
	}

	var calls []*Call
	for _, callYml := range yml.Calls {
		expr, err := cronexpr.Parse(callYml.Cron)
		if err != nil {
			return nil, err
		}

		nice := uint8(255)
		if callYml.Nice != nil {
			nice, err = NicenessParse(*callYml.Nice)
			if err != nil {
				return nil, err
			}
		}

		var xx TRxTx
		if callYml.Xx != nil {
			switch *callYml.Xx {
			case "rx":
				xx = TRx
			case "tx":
				xx = TTx
			default:
				return nil, errors.New("xx field must be either \"rx\" or \"tx\"")
			}
		}

		rxRate := defRxRate
		if callYml.RxRate != nil {
			rxRate = *callYml.RxRate
		}
		txRate := defTxRate
		if callYml.TxRate != nil {
			txRate = *callYml.TxRate
		}

		var addr *string
		if callYml.Addr != nil {
			if a, exists := yml.Addrs[*callYml.Addr]; exists {
				addr = &a
			} else {
				addr = callYml.Addr
			}
		}

		onlineDeadline := defOnlineDeadline
		if callYml.OnlineDeadline != nil {
			if *callYml.OnlineDeadline == 0 {
				return nil, errors.New("OnlineDeadline must be at least 1 second")
			}
			onlineDeadline = *callYml.OnlineDeadline
		}

		var maxOnlineTime uint
		if callYml.MaxOnlineTime != nil {
			maxOnlineTime = *callYml.MaxOnlineTime
		}

		calls = append(calls, &Call{
			Cron:           expr,
			Nice:           nice,
			Xx:             xx,
			RxRate:         rxRate,
			TxRate:         txRate,
			Addr:           addr,
			OnlineDeadline: onlineDeadline,
			MaxOnlineTime:  maxOnlineTime,
		})
	}

	node := Node{
		Name:           name,
		Id:             nodeId,
		ExchPub:        new([32]byte),
		SignPub:        ed25519.PublicKey(signPub),
		Exec:           yml.Exec,
		Incoming:       incoming,
		FreqPath:       freqPath,
		FreqChunked:    freqChunked,
		FreqMinSize:    freqMinSize,
		FreqMaxSize:    freqMaxSize,
		Calls:          calls,
		Addrs:          yml.Addrs,
		RxRate:         defRxRate,
		TxRate:         defTxRate,
		OnlineDeadline: defOnlineDeadline,
		MaxOnlineTime:  defMaxOnlineTime,
	}
	copy(node.ExchPub[:], exchPub)
	if len(noisePub) > 0 {
		node.NoisePub = new([32]byte)
		copy(node.NoisePub[:], noisePub)
	}
	return &node, nil
}

func NewNodeOur(yml *NodeOurJSON) (*NodeOur, error) {
	id, err := NodeIdFromString(yml.Id)
	if err != nil {
		return nil, err
	}

	exchPub, err := FromBase32(yml.ExchPub)
	if err != nil {
		return nil, err
	}
	if len(exchPub) != 32 {
		return nil, errors.New("Invalid exchPub size")
	}

	exchPrv, err := FromBase32(yml.ExchPrv)
	if err != nil {
		return nil, err
	}
	if len(exchPrv) != 32 {
		return nil, errors.New("Invalid exchPrv size")
	}

	signPub, err := FromBase32(yml.SignPub)
	if err != nil {
		return nil, err
	}
	if len(signPub) != ed25519.PublicKeySize {
		return nil, errors.New("Invalid signPub size")
	}

	signPrv, err := FromBase32(yml.SignPrv)
	if err != nil {
		return nil, err
	}
	if len(signPrv) != ed25519.PrivateKeySize {
		return nil, errors.New("Invalid signPrv size")
	}

	noisePub, err := FromBase32(yml.NoisePub)
	if err != nil {
		return nil, err
	}
	if len(noisePub) != 32 {
		return nil, errors.New("Invalid noisePub size")
	}

	noisePrv, err := FromBase32(yml.NoisePrv)
	if err != nil {
		return nil, err
	}
	if len(noisePrv) != 32 {
		return nil, errors.New("Invalid noisePrv size")
	}

	node := NodeOur{
		Id:       id,
		ExchPub:  new([32]byte),
		ExchPrv:  new([32]byte),
		SignPub:  ed25519.PublicKey(signPub),
		SignPrv:  ed25519.PrivateKey(signPrv),
		NoisePub: new([32]byte),
		NoisePrv: new([32]byte),
	}
	copy(node.ExchPub[:], exchPub)
	copy(node.ExchPrv[:], exchPrv)
	copy(node.NoisePub[:], noisePub)
	copy(node.NoisePrv[:], noisePrv)
	return &node, nil
}

func CfgParse(data []byte) (*Ctx, error) {
	var err error
	if bytes.Compare(data[:8], MagicNNCPBv3[:]) == 0 {
		os.Stderr.WriteString("Passphrase:")
		password, err := terminal.ReadPassword(0)
		if err != nil {
			log.Fatalln(err)
		}
		os.Stderr.WriteString("\n")
		data, err = DeEBlob(data, password)
		if err != nil {
			return nil, err
		}
	}
	var cfgGeneral map[string]interface{}
	if err = hjson.Unmarshal(data, &cfgGeneral); err != nil {
		return nil, err
	}
	marshaled, err := json.Marshal(cfgGeneral)
	if err != nil {
		return nil, err
	}
	var cfgJSON CfgJSON
	if err = json.Unmarshal(marshaled, &cfgJSON); err != nil {
		return nil, err
	}
	if _, exists := cfgJSON.Neigh["self"]; !exists {
		return nil, errors.New("self neighbour missing")
	}
	var self *NodeOur
	if cfgJSON.Self != nil {
		self, err = NewNodeOur(cfgJSON.Self)
		if err != nil {
			return nil, err
		}
	}
	spoolPath := path.Clean(cfgJSON.Spool)
	if !path.IsAbs(spoolPath) {
		return nil, errors.New("Spool path must be absolute")
	}
	logPath := path.Clean(cfgJSON.Log)
	if !path.IsAbs(logPath) {
		return nil, errors.New("Log path must be absolute")
	}
	var umaskForce *int
	if cfgJSON.Umask != "" {
		r, err := strconv.ParseUint(cfgJSON.Umask, 8, 16)
		if err != nil {
			return nil, err
		}
		rInt := int(r)
		umaskForce = &rInt
	}
	ctx := Ctx{
		Spool:      spoolPath,
		LogPath:    logPath,
		UmaskForce: umaskForce,
		Self:       self,
		Neigh:      make(map[NodeId]*Node, len(cfgJSON.Neigh)),
		Alias:      make(map[string]*NodeId),
	}
	if cfgJSON.Notify != nil {
		if cfgJSON.Notify.File != nil {
			ctx.NotifyFile = cfgJSON.Notify.File
		}
		if cfgJSON.Notify.Freq != nil {
			ctx.NotifyFreq = cfgJSON.Notify.Freq
		}
		if cfgJSON.Notify.Exec != nil {
			ctx.NotifyExec = cfgJSON.Notify.Exec
		}
	}
	vias := make(map[NodeId][]string)
	for name, neighJSON := range cfgJSON.Neigh {
		neigh, err := NewNode(name, neighJSON)
		if err != nil {
			return nil, err
		}
		ctx.Neigh[*neigh.Id] = neigh
		if _, already := ctx.Alias[name]; already {
			return nil, errors.New("Node names conflict")
		}
		ctx.Alias[name] = neigh.Id
		vias[*neigh.Id] = neighJSON.Via
	}
	ctx.SelfId = ctx.Alias["self"]
	for neighId, viasRaw := range vias {
		for _, viaRaw := range viasRaw {
			foundNodeId, err := ctx.FindNode(viaRaw)
			if err != nil {
				return nil, err
			}
			ctx.Neigh[neighId].Via = append(
				ctx.Neigh[neighId].Via,
				foundNodeId.Id,
			)
		}
	}
	return &ctx, nil
}
