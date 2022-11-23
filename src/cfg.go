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

package nncp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/gorhill/cronexpr"
	"github.com/hjson/hjson-go"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/term"
)

const (
	CfgPathEnv  = "NNCPCFG"
	CfgSpoolEnv = "NNCPSPOOL"
	CfgLogEnv   = "NNCPLOG"
	CfgNoSync   = "NNCPNOSYNC"
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
	Incoming *string             `json:"incoming,omitempty"`
	Exec     map[string][]string `json:"exec,omitempty"`
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
	Cron           string  `json:"cron"`
	Nice           *string `json:"nice,omitempty"`
	Xx             *string `json:"xx,omitempty"`
	RxRate         *int    `json:"rxrate,omitempty"`
	TxRate         *int    `json:"txrate,omitempty"`
	Addr           *string `json:"addr,omitempty"`
	OnlineDeadline *uint   `json:"onlinedeadline,omitempty"`
	MaxOnlineTime  *uint   `json:"maxonlinetime,omitempty"`
	WhenTxExists   bool    `json:"when-tx-exists,omitempty"`
	NoCK           bool    `json:"nock,omitempty"`
	MCDIgnore      bool    `json:"mcd-ignore,omitempty"`

	AutoToss       bool `json:"autotoss,omitempty"`
	AutoTossDoSeen bool `json:"autotoss-doseen,omitempty"`
	AutoTossNoFile bool `json:"autotoss-nofile,omitempty"`
	AutoTossNoFreq bool `json:"autotoss-nofreq,omitempty"`
	AutoTossNoExec bool `json:"autotoss-noexec,omitempty"`
	AutoTossNoTrns bool `json:"autotoss-notrns,omitempty"`
	AutoTossNoArea bool `json:"autotoss-noarea,omitempty"`
}

type NodeOurJSON struct {
	Id       string `json:"id"`
	ExchPub  string `json:"exchpub"`
	ExchPrv  string `json:"exchprv"`
	SignPub  string `json:"signpub"`
	SignPrv  string `json:"signprv"`
	NoisePub string `json:"noisepub"`
	NoisePrv string `json:"noiseprv"`
}

type FromToJSON struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type NotifyJSON struct {
	File *FromToJSON            `json:"file,omitempty"`
	Freq *FromToJSON            `json:"freq,omitempty"`
	Exec map[string]*FromToJSON `json:"exec,omitempty"`
}

type AreaJSON struct {
	Id  string  `json:"id"`
	Pub *string `json:"pub,omitempty"`
	Prv *string `json:"prv,omitempty"`

	Subs []string `json:"subs"`

	Incoming *string             `json:"incoming,omitempty"`
	Exec     map[string][]string `json:"exec,omitempty"`

	AllowUnknown bool `json:"allow-unknown,omitempty"`
}

type CfgJSON struct {
	Spool string  `json:"spool"`
	Log   string  `json:"log"`
	Umask *string `json:"umask,omitempty"`

	OmitPrgrs bool `json:"noprogress,omitempty"`
	NoHdr     bool `json:"nohdr,omitempty"`

	MCDRxIfis []string       `json:"mcd-listen,omitempty"`
	MCDTxIfis map[string]int `json:"mcd-send,omitempty"`

	Notify *NotifyJSON `json:"notify,omitempty"`

	Self  *NodeOurJSON        `json:"self"`
	Neigh map[string]NodeJSON `json:"neigh"`

	Areas map[string]AreaJSON `json:"areas,omitempty"`

	YggdrasilAliases map[string]string `json:"yggdrasil-aliases,omitempty"`
}

func NewNode(name string, cfg NodeJSON) (*Node, error) {
	nodeId, err := NodeIdFromString(cfg.Id)
	if err != nil {
		return nil, err
	}

	exchPub, err := Base32Codec.DecodeString(cfg.ExchPub)
	if err != nil {
		return nil, err
	}
	if len(exchPub) != 32 {
		return nil, errors.New("Invalid exchPub size")
	}

	signPub, err := Base32Codec.DecodeString(cfg.SignPub)
	if err != nil {
		return nil, err
	}
	if len(signPub) != ed25519.PublicKeySize {
		return nil, errors.New("Invalid signPub size")
	}

	var noisePub []byte
	if cfg.NoisePub != nil {
		noisePub, err = Base32Codec.DecodeString(*cfg.NoisePub)
		if err != nil {
			return nil, err
		}
		if len(noisePub) != 32 {
			return nil, errors.New("Invalid noisePub size")
		}
	}

	var incoming *string
	if cfg.Incoming != nil {
		inc := path.Clean(*cfg.Incoming)
		if !path.IsAbs(inc) {
			return nil, errors.New("Incoming path must be absolute")
		}
		incoming = &inc
	}

	var freqPath *string
	var freqChunked int64
	var freqMinSize int64
	freqMaxSize := int64(MaxFileSize)
	if cfg.Freq != nil {
		f := cfg.Freq
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
	if cfg.RxRate != nil && *cfg.RxRate > 0 {
		defRxRate = *cfg.RxRate
	}
	defTxRate := 0
	if cfg.TxRate != nil && *cfg.TxRate > 0 {
		defTxRate = *cfg.TxRate
	}

	defOnlineDeadline := DefaultDeadline
	if cfg.OnlineDeadline != nil {
		if *cfg.OnlineDeadline <= 0 {
			return nil, errors.New("OnlineDeadline must be at least 1 second")
		}
		defOnlineDeadline = time.Duration(*cfg.OnlineDeadline) * time.Second
	}
	var defMaxOnlineTime time.Duration
	if cfg.MaxOnlineTime != nil {
		defMaxOnlineTime = time.Duration(*cfg.MaxOnlineTime) * time.Second
	}

	var calls []*Call
	for _, callCfg := range cfg.Calls {
		expr, err := cronexpr.Parse(callCfg.Cron)
		if err != nil {
			return nil, err
		}

		nice := uint8(255)
		if callCfg.Nice != nil {
			nice, err = NicenessParse(*callCfg.Nice)
			if err != nil {
				return nil, err
			}
		}

		var xx TRxTx
		if callCfg.Xx != nil {
			switch *callCfg.Xx {
			case "rx":
				xx = TRx
			case "tx":
				xx = TTx
			default:
				return nil, errors.New("xx field must be either \"rx\" or \"tx\"")
			}
		}

		rxRate := defRxRate
		if callCfg.RxRate != nil {
			rxRate = *callCfg.RxRate
		}
		txRate := defTxRate
		if callCfg.TxRate != nil {
			txRate = *callCfg.TxRate
		}

		var addr *string
		if callCfg.Addr != nil {
			if a, exists := cfg.Addrs[*callCfg.Addr]; exists {
				addr = &a
			} else {
				addr = callCfg.Addr
			}
		}

		onlineDeadline := defOnlineDeadline
		if callCfg.OnlineDeadline != nil {
			if *callCfg.OnlineDeadline == 0 {
				return nil, errors.New("OnlineDeadline must be at least 1 second")
			}
			onlineDeadline = time.Duration(*callCfg.OnlineDeadline) * time.Second
		}

		call := Call{
			Cron:           expr,
			Nice:           nice,
			Xx:             xx,
			RxRate:         rxRate,
			TxRate:         txRate,
			Addr:           addr,
			OnlineDeadline: onlineDeadline,
		}

		if callCfg.MaxOnlineTime != nil {
			call.MaxOnlineTime = time.Duration(*callCfg.MaxOnlineTime) * time.Second
		}
		call.WhenTxExists = callCfg.WhenTxExists
		call.NoCK = callCfg.NoCK
		call.MCDIgnore = callCfg.MCDIgnore
		call.AutoToss = callCfg.AutoToss
		call.AutoTossDoSeen = callCfg.AutoTossDoSeen
		call.AutoTossNoFile = callCfg.AutoTossNoFile
		call.AutoTossNoFreq = callCfg.AutoTossNoFreq
		call.AutoTossNoExec = callCfg.AutoTossNoExec
		call.AutoTossNoTrns = callCfg.AutoTossNoTrns
		call.AutoTossNoArea = callCfg.AutoTossNoArea

		calls = append(calls, &call)
	}

	node := Node{
		Name:           name,
		Id:             nodeId,
		ExchPub:        new([32]byte),
		SignPub:        ed25519.PublicKey(signPub),
		Exec:           cfg.Exec,
		Incoming:       incoming,
		FreqPath:       freqPath,
		FreqChunked:    freqChunked,
		FreqMinSize:    freqMinSize,
		FreqMaxSize:    freqMaxSize,
		Calls:          calls,
		Addrs:          cfg.Addrs,
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

func NewNodeOur(cfg *NodeOurJSON) (*NodeOur, error) {
	id, err := NodeIdFromString(cfg.Id)
	if err != nil {
		return nil, err
	}

	exchPub, err := Base32Codec.DecodeString(cfg.ExchPub)
	if err != nil {
		return nil, err
	}
	if len(exchPub) != 32 {
		return nil, errors.New("Invalid exchPub size")
	}

	exchPrv, err := Base32Codec.DecodeString(cfg.ExchPrv)
	if err != nil {
		return nil, err
	}
	if len(exchPrv) != 32 {
		return nil, errors.New("Invalid exchPrv size")
	}

	signPub, err := Base32Codec.DecodeString(cfg.SignPub)
	if err != nil {
		return nil, err
	}
	if len(signPub) != ed25519.PublicKeySize {
		return nil, errors.New("Invalid signPub size")
	}

	signPrv, err := Base32Codec.DecodeString(cfg.SignPrv)
	if err != nil {
		return nil, err
	}
	if len(signPrv) != ed25519.PrivateKeySize {
		return nil, errors.New("Invalid signPrv size")
	}

	noisePub, err := Base32Codec.DecodeString(cfg.NoisePub)
	if err != nil {
		return nil, err
	}
	if len(noisePub) != 32 {
		return nil, errors.New("Invalid noisePub size")
	}

	noisePrv, err := Base32Codec.DecodeString(cfg.NoisePrv)
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

func NewArea(ctx *Ctx, name string, cfg *AreaJSON) (*Area, error) {
	areaId, err := AreaIdFromString(cfg.Id)
	if err != nil {
		return nil, err
	}
	subs := make([]*NodeId, 0, len(cfg.Subs))
	for _, s := range cfg.Subs {
		node, err := ctx.FindNode(s)
		if err != nil {
			return nil, err
		}
		subs = append(subs, node.Id)
	}
	area := Area{
		Name:     name,
		Id:       areaId,
		Subs:     subs,
		Exec:     cfg.Exec,
		Incoming: cfg.Incoming,
	}
	if cfg.Pub != nil {
		pub, err := Base32Codec.DecodeString(*cfg.Pub)
		if err != nil {
			return nil, err
		}
		if len(pub) != 32 {
			return nil, errors.New("Invalid pub size")
		}
		area.Pub = new([32]byte)
		copy(area.Pub[:], pub)
	}
	if cfg.Prv != nil {
		if area.Pub == nil {
			return nil, fmt.Errorf("area %s: prv requires pub presence", name)
		}
		prv, err := Base32Codec.DecodeString(*cfg.Prv)
		if err != nil {
			return nil, err
		}
		if len(prv) != 32 {
			return nil, errors.New("Invalid prv size")
		}
		area.Prv = new([32]byte)
		copy(area.Prv[:], prv)
	}
	area.AllowUnknown = cfg.AllowUnknown
	return &area, nil
}

func CfgParse(data []byte) (*CfgJSON, error) {
	var err error
	if bytes.Compare(data[:8], MagicNNCPBv3.B[:]) == 0 {
		os.Stderr.WriteString("Passphrase:")
		password, err := term.ReadPassword(0)
		if err != nil {
			log.Fatalln(err)
		}
		os.Stderr.WriteString("\n")
		data, err = DeEBlob(data, password)
		if err != nil {
			return nil, err
		}
	} else if bytes.Compare(data[:8], MagicNNCPBv2.B[:]) == 0 {
		log.Fatalln(MagicNNCPBv2.TooOld())
	} else if bytes.Compare(data[:8], MagicNNCPBv1.B[:]) == 0 {
		log.Fatalln(MagicNNCPBv1.TooOld())
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
	err = json.Unmarshal(marshaled, &cfgJSON)
	return &cfgJSON, err
}

func Cfg2Ctx(cfgJSON *CfgJSON) (*Ctx, error) {
	if _, exists := cfgJSON.Neigh["self"]; !exists {
		return nil, errors.New("self neighbour missing")
	}
	var self *NodeOur
	if cfgJSON.Self != nil {
		var err error
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
	if cfgJSON.Umask != nil {
		r, err := strconv.ParseUint(*cfgJSON.Umask, 8, 16)
		if err != nil {
			return nil, err
		}
		rInt := int(r)
		umaskForce = &rInt
	}
	showPrgrs := true
	if cfgJSON.OmitPrgrs {
		showPrgrs = false
	}
	hdrUsage := true
	if cfgJSON.NoHdr {
		hdrUsage = false
	}
	ctx := Ctx{
		Spool:      spoolPath,
		LogPath:    logPath,
		UmaskForce: umaskForce,
		ShowPrgrs:  showPrgrs,
		HdrUsage:   hdrUsage,
		Self:       self,
		Neigh:      make(map[NodeId]*Node, len(cfgJSON.Neigh)),
		Alias:      make(map[string]*NodeId),
		MCDRxIfis:  cfgJSON.MCDRxIfis,
		MCDTxIfis:  cfgJSON.MCDTxIfis,

		YggdrasilAliases: cfgJSON.YggdrasilAliases,
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
	ctx.AreaId2Area = make(map[AreaId]*Area, len(cfgJSON.Areas))
	ctx.AreaName2Id = make(map[string]*AreaId, len(cfgJSON.Areas))
	for name, areaJSON := range cfgJSON.Areas {
		area, err := NewArea(&ctx, name, &areaJSON)
		if err != nil {
			return nil, err
		}
		ctx.AreaId2Area[*area.Id] = area
		ctx.AreaName2Id[name] = area.Id
	}
	return &ctx, nil
}
