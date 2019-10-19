/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2019 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

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
	"errors"
	"log"
	"os"
	"path"

	"github.com/gorhill/cronexpr"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

const (
	CfgPathEnv  = "NNCPCFG"
	CfgSpoolEnv = "NNCPSPOOL"
	CfgLogEnv   = "NNCPLOG"
)

var (
	DefaultCfgPath      string = "/usr/local/etc/nncp.yaml"
	DefaultSendmailPath string = "/usr/sbin/sendmail"
	DefaultSpoolPath    string = "/var/spool/nncp"
	DefaultLogPath      string = "/var/spool/nncp/log"
)

type NodeYAML struct {
	Id          string
	ExchPub     string
	SignPub     string
	NoisePub    *string             `yaml:"noisepub,omitempty"`
	Exec        map[string][]string `yaml:"exec,omitempty"`
	Incoming    *string             `yaml:"incoming,omitempty"`
	Freq        *string             `yaml:"freq,omitempty"`
	FreqChunked *uint64             `yaml:"freqchunked,omitempty"`
	FreqMinSize *uint64             `yaml:"freqminsize,omitempty"`
	Via         []string            `yaml:"via,omitempty"`
	Calls       []CallYAML          `yaml:"calls,omitempty"`

	Addrs map[string]string `yaml:"addrs,omitempty"`

	RxRate         *int  `yaml:"rxrate,omitempty"`
	TxRate         *int  `yaml:"txrate,omitempty"`
	OnlineDeadline *uint `yaml:"onlinedeadline,omitempty"`
	MaxOnlineTime  *uint `yaml:"maxonlinetime,omitempty"`
}

type CallYAML struct {
	Cron           string
	Nice           *string `yaml:"nice,omitempty"`
	Xx             string  `yaml:"xx,omitempty"`
	RxRate         *int    `yaml:"rxrate,omitempty"`
	TxRate         *int    `yaml:"txrate,omitempty"`
	Addr           *string `yaml:"addr,omitempty"`
	OnlineDeadline *uint   `yaml:"onlinedeadline,omitempty"`
	MaxOnlineTime  *uint   `yaml:"maxonlinetime,omitempty"`
}

type NodeOurYAML struct {
	Id       string
	ExchPub  string
	ExchPrv  string
	SignPub  string
	SignPrv  string
	NoisePrv string
	NoisePub string
}

type FromToYAML struct {
	From string
	To   string
}

type NotifyYAML struct {
	File *FromToYAML `yaml:"file,omitempty"`
	Freq *FromToYAML `yaml:"freq,omitempty"`
}

type CfgYAML struct {
	Self  *NodeOurYAML `yaml:"self,omitempty"`
	Neigh map[string]NodeYAML

	Spool  string
	Log    string
	Notify *NotifyYAML `yaml:"notify,omitempty"`
}

func NewNode(name string, yml NodeYAML) (*Node, error) {
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

	var freq *string
	if yml.Freq != nil {
		fr := path.Clean(*yml.Freq)
		if !path.IsAbs(fr) {
			return nil, errors.New("Freq path must be absolute")
		}
		freq = &fr
	}
	var freqChunked int64
	if yml.FreqChunked != nil {
		if *yml.FreqChunked == 0 {
			return nil, errors.New("freqchunked value must be greater than zero")
		}
		freqChunked = int64(*yml.FreqChunked) * 1024
	}
	var freqMinSize int64
	if yml.FreqMinSize != nil {
		freqMinSize = int64(*yml.FreqMinSize) * 1024
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
		switch callYml.Xx {
		case "rx":
			xx = TRx
		case "tx":
			xx = TTx
		case "":
		default:
			return nil, errors.New("xx field must be either \"rx\" or \"tx\"")
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
		Freq:           freq,
		FreqChunked:    freqChunked,
		FreqMinSize:    freqMinSize,
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

func NewNodeOur(yml *NodeOurYAML) (*NodeOur, error) {
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

func (nodeOur *NodeOur) ToYAML() string {
	yml := NodeOurYAML{
		Id:       nodeOur.Id.String(),
		ExchPub:  ToBase32(nodeOur.ExchPub[:]),
		ExchPrv:  ToBase32(nodeOur.ExchPrv[:]),
		SignPub:  ToBase32(nodeOur.SignPub[:]),
		SignPrv:  ToBase32(nodeOur.SignPrv[:]),
		NoisePub: ToBase32(nodeOur.NoisePub[:]),
		NoisePrv: ToBase32(nodeOur.NoisePrv[:]),
	}
	raw, err := yaml.Marshal(&yml)
	if err != nil {
		panic(err)
	}
	return string(raw)
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
	var cfgYAML CfgYAML
	if err = yaml.Unmarshal(data, &cfgYAML); err != nil {
		return nil, err
	}
	if _, exists := cfgYAML.Neigh["self"]; !exists {
		return nil, errors.New("self neighbour missing")
	}
	var self *NodeOur
	if cfgYAML.Self != nil {
		self, err = NewNodeOur(cfgYAML.Self)
		if err != nil {
			return nil, err
		}
	}
	spoolPath := path.Clean(cfgYAML.Spool)
	if !path.IsAbs(spoolPath) {
		return nil, errors.New("Spool path must be absolute")
	}
	logPath := path.Clean(cfgYAML.Log)
	if !path.IsAbs(logPath) {
		return nil, errors.New("Log path must be absolute")
	}
	ctx := Ctx{
		Spool:   spoolPath,
		LogPath: logPath,
		Self:    self,
		Neigh:   make(map[NodeId]*Node, len(cfgYAML.Neigh)),
		Alias:   make(map[string]*NodeId),
	}
	if cfgYAML.Notify != nil {
		if cfgYAML.Notify.File != nil {
			ctx.NotifyFile = cfgYAML.Notify.File
		}
		if cfgYAML.Notify.Freq != nil {
			ctx.NotifyFreq = cfgYAML.Notify.Freq
		}
	}
	vias := make(map[NodeId][]string)
	for name, neighYAML := range cfgYAML.Neigh {
		neigh, err := NewNode(name, neighYAML)
		if err != nil {
			return nil, err
		}
		ctx.Neigh[*neigh.Id] = neigh
		if _, already := ctx.Alias[name]; already {
			return nil, errors.New("Node names conflict")
		}
		ctx.Alias[name] = neigh.Id
		vias[*neigh.Id] = neighYAML.Via
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
