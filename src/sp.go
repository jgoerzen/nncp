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
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/dustin/go-humanize"
	"github.com/flynn/noise"
)

const (
	MaxSPSize      = 1<<16 - 256
	PartSuffix     = ".part"
	SPHeadOverhead = 4
	CfgDeadline    = "NNCPDEADLINE"
)

type MTHAndOffset struct {
	mth    MTH
	offset uint64
}

type SPCheckerTask struct {
	nodeId *NodeId
	hsh    *[MTHSize]byte
	mth    MTH
	done   chan []byte
}

var (
	SPInfoOverhead    int
	SPFreqOverhead    int
	SPFileOverhead    int
	SPHaltMarshalized []byte
	SPPingMarshalized []byte

	NoiseCipherSuite noise.CipherSuite = noise.NewCipherSuite(
		noise.DH25519,
		noise.CipherChaChaPoly,
		noise.HashBLAKE2b,
	)

	DefaultDeadline = 10 * time.Second
	PingTimeout     = time.Minute

	spCheckerTasks chan SPCheckerTask
	SPCheckerWg    sync.WaitGroup
	spCheckerOnce  sync.Once
)

type FdAndFullSize struct {
	fd       *os.File
	fullSize int64
}

type SPType uint8

const (
	SPTypeInfo SPType = iota
	SPTypeFreq SPType = iota
	SPTypeFile SPType = iota
	SPTypeDone SPType = iota
	SPTypeHalt SPType = iota
	SPTypePing SPType = iota
)

type SPHead struct {
	Type SPType
}

type SPInfo struct {
	Nice uint8
	Size uint64
	Hash *[MTHSize]byte
}

type SPFreq struct {
	Hash   *[MTHSize]byte
	Offset uint64
}

type SPFile struct {
	Hash    *[MTHSize]byte
	Offset  uint64
	Payload []byte
}

type SPDone struct {
	Hash *[MTHSize]byte
}

type SPRaw struct {
	Magic   [8]byte
	Payload []byte
}

type FreqWithNice struct {
	freq *SPFreq
	nice uint8
}

type ConnDeadlined interface {
	io.ReadWriteCloser
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

func init() {
	if v := os.Getenv(CfgDeadline); v != "" {
		i, err := strconv.Atoi(v)
		if err != nil {
			log.Fatalln("Can not convert", CfgDeadline, "to integer:", err)
		}
		DefaultDeadline = time.Duration(i) * time.Second
	}

	var buf bytes.Buffer
	spHead := SPHead{Type: SPTypeHalt}
	if _, err := xdr.Marshal(&buf, spHead); err != nil {
		panic(err)
	}
	SPHaltMarshalized = make([]byte, SPHeadOverhead)
	copy(SPHaltMarshalized, buf.Bytes())
	buf.Reset()

	spHead = SPHead{Type: SPTypePing}
	if _, err := xdr.Marshal(&buf, spHead); err != nil {
		panic(err)
	}
	SPPingMarshalized = make([]byte, SPHeadOverhead)
	copy(SPPingMarshalized, buf.Bytes())
	buf.Reset()

	spInfo := SPInfo{Nice: 123, Size: 123, Hash: new([MTHSize]byte)}
	if _, err := xdr.Marshal(&buf, spInfo); err != nil {
		panic(err)
	}
	SPInfoOverhead = buf.Len()
	buf.Reset()

	spFreq := SPFreq{Hash: new([MTHSize]byte), Offset: 123}
	if _, err := xdr.Marshal(&buf, spFreq); err != nil {
		panic(err)
	}
	SPFreqOverhead = buf.Len()
	buf.Reset()

	spFile := SPFile{Hash: new([MTHSize]byte), Offset: 123}
	if _, err := xdr.Marshal(&buf, spFile); err != nil {
		panic(err)
	}
	SPFileOverhead = buf.Len()
	spCheckerTasks = make(chan SPCheckerTask)
}

func MarshalSP(typ SPType, sp interface{}) []byte {
	var buf bytes.Buffer
	if _, err := xdr.Marshal(&buf, SPHead{typ}); err != nil {
		panic(err)
	}
	if _, err := xdr.Marshal(&buf, sp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func payloadsSplit(payloads [][]byte) [][]byte {
	var outbounds [][]byte
	outbound := make([]byte, 0, MaxSPSize)
	for i, payload := range payloads {
		outbound = append(outbound, payload...)
		if i+1 < len(payloads) && len(outbound)+len(payloads[i+1]) > MaxSPSize {
			outbounds = append(outbounds, outbound)
			outbound = make([]byte, 0, MaxSPSize)
		}
	}
	if len(outbound) > 0 {
		outbounds = append(outbounds, outbound)
	}
	return outbounds
}

type SPState struct {
	Ctx            *Ctx
	Node           *Node
	Nice           uint8
	NoCK           bool
	onlineDeadline time.Duration
	maxOnlineTime  time.Duration
	hs             *noise.HandshakeState
	csOur          *noise.CipherState
	csTheir        *noise.CipherState
	payloads       chan []byte
	pings          chan struct{}
	infosTheir     map[[MTHSize]byte]*SPInfo
	infosOurSeen   map[[MTHSize]byte]uint8
	queueTheir     []*FreqWithNice
	wg             sync.WaitGroup
	RxBytes        int64
	RxLastSeen     time.Time
	RxLastNonPing  time.Time
	TxBytes        int64
	TxLastSeen     time.Time
	TxLastNonPing  time.Time
	started        time.Time
	mustFinishAt   time.Time
	Duration       time.Duration
	RxSpeed        int64
	TxSpeed        int64
	rxLock         *os.File
	txLock         *os.File
	xxOnly         TRxTx
	rxRate         int
	txRate         int
	isDead         chan struct{}
	listOnly       bool
	onlyPkts       map[[MTHSize]byte]bool
	writeSPBuf     bytes.Buffer
	fds            map[string]FdAndFullSize
	fdsLock        sync.RWMutex
	fileHashers    map[string]*MTHAndOffset
	progressBars   map[string]struct{}
	sync.RWMutex
}

func (state *SPState) SetDead() {
	state.Lock()
	defer state.Unlock()
	select {
	case <-state.isDead:
		// Already closed channel, dead
		return
	default:
	}
	close(state.isDead)
	go func() {
		for range state.payloads {
		}
	}()
	go func() {
		for range state.pings {
		}
	}()
}

func (state *SPState) NotAlive() bool {
	select {
	case <-state.isDead:
		return true
	default:
	}
	return false
}

func (state *SPState) dirUnlock() {
	state.Ctx.UnlockDir(state.rxLock)
	state.Ctx.UnlockDir(state.txLock)
}

func (state *SPState) WriteSP(dst io.Writer, payload []byte, ping bool) error {
	state.writeSPBuf.Reset()
	n, err := xdr.Marshal(&state.writeSPBuf, SPRaw{
		Magic:   MagicNNCPSv1.B,
		Payload: payload,
	})
	if err != nil {
		return err
	}
	if n, err = dst.Write(state.writeSPBuf.Bytes()); err == nil {
		state.TxLastSeen = time.Now()
		state.TxBytes += int64(n)
		if !ping {
			state.TxLastNonPing = state.TxLastSeen
		}
	}
	return err
}

func (state *SPState) ReadSP(src io.Reader) ([]byte, error) {
	var sp SPRaw
	n, err := xdr.UnmarshalLimited(src, &sp, 1<<17)
	if err != nil {
		ue := err.(*xdr.UnmarshalError)
		if ue.Err == io.EOF {
			return nil, ue.Err
		}
		return nil, err
	}
	state.RxLastSeen = time.Now()
	state.RxBytes += int64(n)
	if sp.Magic != MagicNNCPSv1.B {
		return nil, BadMagic
	}
	return sp.Payload, nil
}

func (ctx *Ctx) infosOur(nodeId *NodeId, nice uint8, seen *map[[MTHSize]byte]uint8) [][]byte {
	var infos []*SPInfo
	var totalSize int64
	for job := range ctx.Jobs(nodeId, TTx) {
		if job.PktEnc.Nice > nice {
			continue
		}
		if _, known := (*seen)[*job.HshValue]; known {
			continue
		}
		totalSize += job.Size
		infos = append(infos, &SPInfo{
			Nice: job.PktEnc.Nice,
			Size: uint64(job.Size),
			Hash: job.HshValue,
		})
		(*seen)[*job.HshValue] = job.PktEnc.Nice
	}
	sort.Sort(ByNice(infos))
	var payloads [][]byte
	for _, info := range infos {
		payloads = append(payloads, MarshalSP(SPTypeInfo, info))
		pktName := Base32Codec.EncodeToString(info.Hash[:])
		ctx.LogD("sp-info-our", LEs{
			{"Node", nodeId},
			{"Name", pktName},
			{"Size", info.Size},
		}, func(les LEs) string {
			return fmt.Sprintf(
				"Our info: %s/tx/%s (%s)",
				ctx.NodeName(nodeId),
				pktName,
				humanize.IBytes(info.Size),
			)
		})
	}
	if totalSize > 0 {
		ctx.LogI("sp-infos-tx", LEs{
			{"XX", string(TTx)},
			{"Node", nodeId},
			{"Pkts", len(payloads)},
			{"Size", totalSize},
		}, func(les LEs) string {
			return fmt.Sprintf(
				"We have got for %s: %d packets, %s",
				ctx.NodeName(nodeId),
				len(payloads),
				humanize.IBytes(uint64(totalSize)),
			)
		})
	}
	return payloadsSplit(payloads)
}

func (state *SPState) StartI(conn ConnDeadlined) error {
	nodeId := state.Node.Id
	err := state.Ctx.ensureRxDir(nodeId)
	if err != nil {
		return err
	}
	var rxLock *os.File
	if !state.listOnly && (state.xxOnly == "" || state.xxOnly == TRx) {
		rxLock, err = state.Ctx.LockDir(nodeId, string(TRx))
		if err != nil {
			return err
		}
	}
	var txLock *os.File
	if !state.listOnly && (state.xxOnly == "" || state.xxOnly == TTx) {
		txLock, err = state.Ctx.LockDir(nodeId, string(TTx))
		if err != nil {
			return err
		}
	}
	started := time.Now()
	conf := noise.Config{
		CipherSuite: NoiseCipherSuite,
		Pattern:     noise.HandshakeIK,
		Initiator:   true,
		StaticKeypair: noise.DHKey{
			Private: state.Ctx.Self.NoisePrv[:],
			Public:  state.Ctx.Self.NoisePub[:],
		},
		PeerStatic: state.Node.NoisePub[:],
	}
	hs, err := noise.NewHandshakeState(conf)
	if err != nil {
		return err
	}
	state.hs = hs
	state.payloads = make(chan []byte)
	state.pings = make(chan struct{})
	state.infosTheir = make(map[[MTHSize]byte]*SPInfo)
	state.infosOurSeen = make(map[[MTHSize]byte]uint8)
	state.progressBars = make(map[string]struct{})
	state.started = started
	state.rxLock = rxLock
	state.txLock = txLock

	var infosPayloads [][]byte
	if !state.listOnly && (state.xxOnly == "" || state.xxOnly == TTx) {
		infosPayloads = state.Ctx.infosOur(nodeId, state.Nice, &state.infosOurSeen)
	}
	var firstPayload []byte
	if len(infosPayloads) > 0 {
		firstPayload = infosPayloads[0]
	}
	// Pad first payload, to hide actual number of existing files
	for i := 0; i < (MaxSPSize-len(firstPayload))/SPHeadOverhead; i++ {
		firstPayload = append(firstPayload, SPHaltMarshalized...)
	}

	var buf []byte
	var payload []byte
	buf, _, _, err = state.hs.WriteMessage(nil, firstPayload)
	if err != nil {
		state.dirUnlock()
		return err
	}
	les := LEs{{"Node", nodeId}, {"Nice", int(state.Nice)}}
	state.Ctx.LogD("sp-startI", les, func(les LEs) string {
		return fmt.Sprintf(
			"SP with %s (nice %s): sending first message",
			state.Node.Name,
			NicenessFmt(state.Nice),
		)
	})
	conn.SetWriteDeadline(time.Now().Add(DefaultDeadline))
	if err = state.WriteSP(conn, buf, false); err != nil {
		state.Ctx.LogE("sp-startI", les, err, func(les LEs) string {
			return fmt.Sprintf(
				"SP with %s (nice %s): writing",
				state.Node.Name,
				NicenessFmt(state.Nice),
			)
		})
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-startI-wait", les, func(les LEs) string {
		return fmt.Sprintf(
			"SP with %s (nice %s): waiting for first message",
			state.Node.Name,
			NicenessFmt(state.Nice),
		)
	})
	conn.SetReadDeadline(time.Now().Add(DefaultDeadline))
	if buf, err = state.ReadSP(conn); err != nil {
		state.Ctx.LogE("sp-startI-read", les, err, func(les LEs) string {
			return fmt.Sprintf(
				"SP with %s (nice %s): reading",
				state.Node.Name,
				NicenessFmt(state.Nice),
			)
		})
		state.dirUnlock()
		return err
	}
	payload, state.csOur, state.csTheir, err = state.hs.ReadMessage(nil, buf)
	if err != nil {
		state.Ctx.LogE("sp-startI-read", les, err, func(les LEs) string {
			return fmt.Sprintf(
				"SP with %s (nice %s): reading Noise message",
				state.Node.Name,
				NicenessFmt(state.Nice),
			)
		})
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-startI-workers", les, func(les LEs) string {
		return fmt.Sprintf(
			"SP with %s (nice %s): starting workers",
			state.Node.Name,
			NicenessFmt(state.Nice),
		)
	})
	err = state.StartWorkers(conn, infosPayloads, payload)
	if err != nil {
		state.Ctx.LogE("sp-startI-workers", les, err, func(les LEs) string {
			return fmt.Sprintf(
				"SP with %s (nice %s): starting workers",
				state.Node.Name,
				NicenessFmt(state.Nice),
			)
		})
		state.dirUnlock()
	}
	return err
}

func (state *SPState) StartR(conn ConnDeadlined) error {
	started := time.Now()
	conf := noise.Config{
		CipherSuite: NoiseCipherSuite,
		Pattern:     noise.HandshakeIK,
		Initiator:   false,
		StaticKeypair: noise.DHKey{
			Private: state.Ctx.Self.NoisePrv[:],
			Public:  state.Ctx.Self.NoisePub[:],
		},
	}
	hs, err := noise.NewHandshakeState(conf)
	if err != nil {
		return err
	}
	xxOnly := TRxTx("")
	state.hs = hs
	state.payloads = make(chan []byte)
	state.pings = make(chan struct{})
	state.infosOurSeen = make(map[[MTHSize]byte]uint8)
	state.infosTheir = make(map[[MTHSize]byte]*SPInfo)
	state.progressBars = make(map[string]struct{})
	state.started = started
	state.xxOnly = xxOnly

	var buf []byte
	var payload []byte
	logMsg := func(les LEs) string {
		return fmt.Sprintf(
			"SP nice %s: waiting for first message",
			NicenessFmt(state.Nice),
		)
	}
	les := LEs{{"Nice", int(state.Nice)}}
	state.Ctx.LogD("sp-startR", les, logMsg)
	conn.SetReadDeadline(time.Now().Add(DefaultDeadline))
	if buf, err = state.ReadSP(conn); err != nil {
		state.Ctx.LogE("sp-startR-read", les, err, logMsg)
		return err
	}
	if payload, _, _, err = state.hs.ReadMessage(nil, buf); err != nil {
		state.Ctx.LogE("sp-startR-read", les, err, logMsg)
		return err
	}

	var node *Node
	for _, n := range state.Ctx.Neigh {
		if n.NoisePub == nil {
			continue
		}
		if subtle.ConstantTimeCompare(state.hs.PeerStatic(), n.NoisePub[:]) == 1 {
			node = n
			break
		}
	}
	if node == nil {
		peerId := Base32Codec.EncodeToString(state.hs.PeerStatic())
		err = errors.New("unknown peer: " + peerId)
		state.Ctx.LogE("sp-startR-unknown", append(les, LE{"Peer", peerId}), err, logMsg)
		return err
	}
	state.Node = node
	state.rxRate = node.RxRate
	state.txRate = node.TxRate
	state.onlineDeadline = node.OnlineDeadline
	state.maxOnlineTime = node.MaxOnlineTime
	les = LEs{{"Node", node.Id}, {"Nice", int(state.Nice)}}

	if err = state.Ctx.ensureRxDir(node.Id); err != nil {
		return err
	}
	var rxLock *os.File
	if xxOnly == "" || xxOnly == TRx {
		rxLock, err = state.Ctx.LockDir(node.Id, string(TRx))
		if err != nil {
			return err
		}
	}
	state.rxLock = rxLock
	var txLock *os.File
	if xxOnly == "" || xxOnly == TTx {
		txLock, err = state.Ctx.LockDir(node.Id, string(TTx))
		if err != nil {
			return err
		}
	}
	state.txLock = txLock

	var infosPayloads [][]byte
	if xxOnly == "" || xxOnly == TTx {
		infosPayloads = state.Ctx.infosOur(node.Id, state.Nice, &state.infosOurSeen)
	}
	var firstPayload []byte
	if len(infosPayloads) > 0 {
		firstPayload = infosPayloads[0]
	}
	// Pad first payload, to hide actual number of existing files
	for i := 0; i < (MaxSPSize-len(firstPayload))/SPHeadOverhead; i++ {
		firstPayload = append(firstPayload, SPHaltMarshalized...)
	}

	state.Ctx.LogD("sp-startR-write", les, func(les LEs) string {
		return fmt.Sprintf(
			"SP with %s (nice %s): sending first message",
			node.Name, NicenessFmt(state.Nice),
		)
	})
	buf, state.csTheir, state.csOur, err = state.hs.WriteMessage(nil, firstPayload)
	if err != nil {
		state.dirUnlock()
		return err
	}
	conn.SetWriteDeadline(time.Now().Add(DefaultDeadline))
	if err = state.WriteSP(conn, buf, false); err != nil {
		state.Ctx.LogE("sp-startR-write", les, err, func(les LEs) string {
			return fmt.Sprintf(
				"SP with %s (nice %s): writing",
				node.Name, NicenessFmt(state.Nice),
			)
		})
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-startR-workers", les, func(les LEs) string {
		return fmt.Sprintf(
			"SP with %s (nice %s): starting workers",
			node.Name, NicenessFmt(state.Nice),
		)
	})
	err = state.StartWorkers(conn, infosPayloads, payload)
	if err != nil {
		state.dirUnlock()
	}
	return err
}

func (state *SPState) closeFd(pth string) {
	state.fdsLock.Lock()
	if s, exists := state.fds[pth]; exists {
		delete(state.fds, pth)
		s.fd.Close()
	}
	state.fdsLock.Unlock()
}

func (state *SPState) StartWorkers(
	conn ConnDeadlined,
	infosPayloads [][]byte,
	payload []byte,
) error {
	les := LEs{{"Node", state.Node.Id}, {"Nice", int(state.Nice)}}
	state.fds = make(map[string]FdAndFullSize)
	state.fileHashers = make(map[string]*MTHAndOffset)
	state.isDead = make(chan struct{})
	if state.maxOnlineTime > 0 {
		state.mustFinishAt = state.started.Add(state.maxOnlineTime)
	}
	if !state.NoCK {
		spCheckerOnce.Do(func() { go SPChecker(state.Ctx) })
		go func() {
			for job := range state.Ctx.JobsNoCK(state.Node.Id) {
				if job.PktEnc.Nice <= state.Nice {
					spCheckerTasks <- SPCheckerTask{
						nodeId: state.Node.Id,
						hsh:    job.HshValue,
						done:   state.payloads,
					}
				}
			}
		}()
	}

	// Remaining handshake payload sending
	if len(infosPayloads) > 1 {
		state.wg.Add(1)
		go func() {
			for _, payload := range infosPayloads[1:] {
				state.Ctx.LogD(
					"sp-queue-remaining",
					append(les, LE{"Size", int64(len(payload))}),
					func(les LEs) string {
						return fmt.Sprintf(
							"SP with %s (nice %s): queuing remaining payload (%s)",
							state.Node.Name, NicenessFmt(state.Nice),
							humanize.IBytes(uint64(len(payload))),
						)
					},
				)
				state.payloads <- payload
			}
			state.wg.Done()
		}()
	}

	// Processing of first payload and queueing its responses
	logMsg := func(les LEs) string {
		return fmt.Sprintf(
			"SP with %s (nice %s): processing first payload (%s)",
			state.Node.Name, NicenessFmt(state.Nice),
			humanize.IBytes(uint64(len(payload))),
		)
	}
	state.Ctx.LogD("sp-process", append(les, LE{"Size", int64(len(payload))}), logMsg)
	replies, err := state.ProcessSP(payload)
	if err != nil {
		state.Ctx.LogE("sp-process", les, err, logMsg)
		return err
	}
	state.wg.Add(1)
	go func() {
		for _, reply := range replies {
			state.Ctx.LogD(
				"sp-queue-reply",
				append(les, LE{"Size", int64(len(reply))}),
				func(les LEs) string {
					return fmt.Sprintf(
						"SP with %s (nice %s): queuing reply (%s)",
						state.Node.Name, NicenessFmt(state.Nice),
						humanize.IBytes(uint64(len(payload))),
					)
				},
			)
			state.payloads <- reply
		}
		state.wg.Done()
	}()

	// Periodic jobs
	state.wg.Add(1)
	go func() {
		deadlineTicker := time.NewTicker(time.Second)
		pingTicker := time.NewTicker(PingTimeout)
		for {
			select {
			case <-state.isDead:
				state.wg.Done()
				deadlineTicker.Stop()
				pingTicker.Stop()
				return
			case now := <-deadlineTicker.C:
				if now.Sub(state.RxLastNonPing) >= state.onlineDeadline &&
					now.Sub(state.TxLastNonPing) >= state.onlineDeadline {
					goto Deadlined
				}
				if state.maxOnlineTime > 0 && state.mustFinishAt.Before(now) {
					goto Deadlined
				}
				if now.Sub(state.RxLastSeen) >= 2*PingTimeout {
					goto Deadlined
				}
				break
			Deadlined:
				state.SetDead()
				conn.Close()
			case now := <-pingTicker.C:
				if now.After(state.TxLastSeen.Add(PingTimeout)) {
					state.wg.Add(1)
					go func() {
						state.pings <- struct{}{}
						state.wg.Done()
					}()
				}
			}
		}
	}()

	// Spool checker and INFOs sender of appearing files
	if !state.listOnly && (state.xxOnly == "" || state.xxOnly == TTx) {
		state.wg.Add(1)
		go func() {
			dw, err := state.Ctx.NewDirWatcher(
				filepath.Join(state.Ctx.Spool, state.Node.Id.String(), string(TTx)),
				time.Second,
			)
			if err != nil {
				state.Ctx.LogE("sp-queue-dir-watch", les, err, logMsg)
				log.Fatalln(err)
			}
			for {
				select {
				case <-state.isDead:
					dw.Close()
					state.wg.Done()
					return
				case <-dw.C:
					for _, payload := range state.Ctx.infosOur(
						state.Node.Id,
						state.Nice,
						&state.infosOurSeen,
					) {
						state.Ctx.LogD(
							"sp-queue-info",
							append(les, LE{"Size", int64(len(payload))}),
							func(les LEs) string {
								return fmt.Sprintf(
									"SP with %s (nice %s): queuing new info (%s)",
									state.Node.Name, NicenessFmt(state.Nice),
									humanize.IBytes(uint64(len(payload))),
								)
							},
						)
						state.payloads <- payload
					}
				}
			}
		}()
	}

	// Sender
	state.wg.Add(1)
	go func() {
		defer conn.Close()
		defer state.SetDead()
		defer state.wg.Done()
		buf := make([]byte, MaxSPSize-SPHeadOverhead-SPFileOverhead)
		for {
			if state.NotAlive() {
				return
			}
			var payload []byte
			var ping bool
			select {
			case <-state.pings:
				state.Ctx.LogD("sp-got-ping", les, func(les LEs) string {
					return fmt.Sprintf(
						"SP with %s (nice %s): got ping",
						state.Node.Name, NicenessFmt(state.Nice),
					)
				})
				payload = SPPingMarshalized
				ping = true
			case payload = <-state.payloads:
				state.Ctx.LogD(
					"sp-got-payload",
					append(les, LE{"Size", int64(len(payload))}),
					func(les LEs) string {
						return fmt.Sprintf(
							"SP with %s (nice %s): got payload (%s)",
							state.Node.Name, NicenessFmt(state.Nice),
							humanize.IBytes(uint64(len(payload))),
						)
					},
				)
			default:
				state.RLock()
				if len(state.queueTheir) == 0 {
					state.RUnlock()
					time.Sleep(100 * time.Millisecond)
					continue
				}
				freq := state.queueTheir[0].freq
				state.RUnlock()
				if state.txRate > 0 {
					time.Sleep(time.Second / time.Duration(state.txRate))
				}
				pktName := Base32Codec.EncodeToString(freq.Hash[:])
				lesp := append(
					les,
					LE{"XX", string(TTx)},
					LE{"Pkt", pktName},
					LE{"Size", int64(freq.Offset)},
				)
				logMsg := func(les LEs) string {
					return fmt.Sprintf(
						"SP with %s (nice %s): tx/%s (%s)",
						state.Node.Name, NicenessFmt(state.Nice),
						pktName,
						humanize.IBytes(freq.Offset),
					)
				}
				state.Ctx.LogD("sp-queue", lesp, func(les LEs) string {
					return logMsg(les) + ": queueing"
				})
				pth := filepath.Join(
					state.Ctx.Spool,
					state.Node.Id.String(),
					string(TTx),
					Base32Codec.EncodeToString(freq.Hash[:]),
				)
				state.fdsLock.RLock()
				fdAndFullSize, exists := state.fds[pth]
				state.fdsLock.RUnlock()
				if !exists {
					state.Ctx.LogD("sp-queue-open", lesp, func(les LEs) string {
						return logMsg(les) + ": opening"
					})
					fd, err := os.Open(pth)
					if err != nil {
						state.Ctx.LogE("sp-queue-open", lesp, err, func(les LEs) string {
							return logMsg(les) + ": opening"
						})
						return
					}
					fi, err := fd.Stat()
					if err != nil {
						state.Ctx.LogE("sp-queue-stat", lesp, err, func(les LEs) string {
							return logMsg(les) + ": stating"
						})
						return
					}
					fdAndFullSize = FdAndFullSize{fd: fd, fullSize: fi.Size()}
					state.fdsLock.Lock()
					state.fds[pth] = fdAndFullSize
					state.fdsLock.Unlock()
				}
				fd := fdAndFullSize.fd
				fullSize := fdAndFullSize.fullSize
				lesp = append(lesp, LE{"FullSize", fullSize})
				var bufRead []byte
				if freq.Offset < uint64(fullSize) {
					state.Ctx.LogD("sp-file-seek", lesp, func(les LEs) string {
						return logMsg(les) + ": seeking"
					})
					if _, err = fd.Seek(int64(freq.Offset), io.SeekStart); err != nil {
						state.Ctx.LogE("sp-file-seek", lesp, err, func(les LEs) string {
							return logMsg(les) + ": seeking"
						})
						return
					}
					n, err := fd.Read(buf)
					if err != nil {
						state.Ctx.LogE("sp-file-read", lesp, err, func(les LEs) string {
							return logMsg(les) + ": reading"
						})
						return
					}
					bufRead = buf[:n]
					lesp = append(
						les,
						LE{"XX", string(TTx)},
						LE{"Pkt", pktName},
						LE{"Size", int64(n)},
						LE{"FullSize", fullSize},
					)
					state.Ctx.LogD("sp-file-read", lesp, func(les LEs) string {
						return fmt.Sprintf(
							"%s: read %s",
							logMsg(les), humanize.IBytes(uint64(n)),
						)
					})
				} else {
					state.closeFd(pth)
				}
				payload = MarshalSP(SPTypeFile, SPFile{
					Hash:    freq.Hash,
					Offset:  freq.Offset,
					Payload: bufRead,
				})
				ourSize := freq.Offset + uint64(len(bufRead))
				lesp = append(
					les,
					LE{"XX", string(TTx)},
					LE{"Pkt", pktName},
					LE{"Size", int64(ourSize)},
					LE{"FullSize", fullSize},
				)
				if state.Ctx.ShowPrgrs {
					state.progressBars[pktName] = struct{}{}
					Progress("Tx", lesp)
				}
				if ourSize == uint64(fullSize) {
					state.closeFd(pth)
					state.Ctx.LogD("sp-file-finished", lesp, func(les LEs) string {
						return logMsg(les) + ": finished"
					})
					if state.Ctx.ShowPrgrs {
						delete(state.progressBars, pktName)
					}
				}
				state.Lock()
				for i, q := range state.queueTheir {
					if *q.freq.Hash != *freq.Hash {
						continue
					}
					if ourSize == uint64(fullSize) {
						state.queueTheir = append(
							state.queueTheir[:i],
							state.queueTheir[i+1:]...,
						)
					} else {
						q.freq.Offset = ourSize
					}
					break
				}
				state.Unlock()
			}
			logMsg := func(les LEs) string {
				return fmt.Sprintf(
					"SP with %s (nice %s): sending %s",
					state.Node.Name, NicenessFmt(state.Nice),
					humanize.IBytes(uint64(len(payload))),
				)
			}
			state.Ctx.LogD("sp-sending", append(les, LE{"Size", int64(len(payload))}), logMsg)
			conn.SetWriteDeadline(time.Now().Add(DefaultDeadline))
			ct, err := state.csOur.Encrypt(nil, nil, payload)
			if err != nil {
				state.Ctx.LogE("sp-encrypting", les, err, logMsg)
				return
			}
			if err := state.WriteSP(conn, ct, ping); err != nil {
				state.Ctx.LogE("sp-sending", les, err, logMsg)
				return
			}
		}
	}()

	// Receiver
	state.wg.Add(1)
	go func() {
		for {
			if state.NotAlive() {
				break
			}
			logMsg := func(les LEs) string {
				return fmt.Sprintf(
					"SP with %s (nice %s): waiting for payload",
					state.Node.Name, NicenessFmt(state.Nice),
				)
			}
			state.Ctx.LogD("sp-recv-wait", les, logMsg)
			conn.SetReadDeadline(time.Now().Add(DefaultDeadline))
			payload, err := state.ReadSP(conn)
			if err != nil {
				if err == io.EOF {
					break
				}
				unmarshalErr := err.(*xdr.UnmarshalError)
				if os.IsTimeout(unmarshalErr.Err) {
					continue
				}
				if unmarshalErr.ErrorCode == xdr.ErrIO {
					break
				}
				state.Ctx.LogE("sp-recv-wait", les, err, logMsg)
				break
			}
			logMsg = func(les LEs) string {
				return fmt.Sprintf(
					"SP with %s (nice %s): payload (%s)",
					state.Node.Name, NicenessFmt(state.Nice),
					humanize.IBytes(uint64(len(payload))),
				)
			}
			state.Ctx.LogD(
				"sp-recv-got",
				append(les, LE{"Size", int64(len(payload))}),
				func(les LEs) string { return logMsg(les) + ": got" },
			)
			payload, err = state.csTheir.Decrypt(nil, nil, payload)
			if err != nil {
				state.Ctx.LogE("sp-recv-got", les, err, func(les LEs) string {
					return logMsg(les) + ": got"
				})
				break
			}
			state.Ctx.LogD(
				"sp-recv-process",
				append(les, LE{"Size", int64(len(payload))}),
				func(les LEs) string {
					return logMsg(les) + ": processing"
				},
			)
			replies, err := state.ProcessSP(payload)
			if err != nil {
				state.Ctx.LogE("sp-recv-process", les, err, func(les LEs) string {
					return logMsg(les) + ": processing"
				})
				break
			}
			state.wg.Add(1)
			go func() {
				for _, reply := range replies {
					state.Ctx.LogD(
						"sp-recv-reply",
						append(les[:len(les)-1], LE{"Size", int64(len(reply))}),
						func(les LEs) string {
							return fmt.Sprintf(
								"SP with %s (nice %s): queuing reply (%s)",
								state.Node.Name, NicenessFmt(state.Nice),
								humanize.IBytes(uint64(len(reply))),
							)
						},
					)
					state.payloads <- reply
				}
				state.wg.Done()
			}()
			if state.rxRate > 0 {
				time.Sleep(time.Second / time.Duration(state.rxRate))
			}
		}
		state.SetDead()
		state.wg.Done()
		state.SetDead()
		conn.Close()
	}()

	return nil
}

func (state *SPState) Wait() bool {
	state.wg.Wait()
	close(state.payloads)
	close(state.pings)
	state.Duration = time.Now().Sub(state.started)
	state.dirUnlock()
	state.RxSpeed = state.RxBytes
	state.TxSpeed = state.TxBytes
	rxDuration := int64(state.RxLastSeen.Sub(state.started).Seconds())
	txDuration := int64(state.TxLastSeen.Sub(state.started).Seconds())
	if rxDuration > 0 {
		state.RxSpeed = state.RxBytes / rxDuration
	}
	if txDuration > 0 {
		state.TxSpeed = state.TxBytes / txDuration
	}
	nothingLeft := len(state.queueTheir) == 0
	for _, s := range state.fds {
		nothingLeft = false
		s.fd.Close()
	}
	for pktName := range state.progressBars {
		ProgressKill(pktName)
	}
	return nothingLeft
}

func (state *SPState) ProcessSP(payload []byte) ([][]byte, error) {
	les := LEs{{"Node", state.Node.Id}, {"Nice", int(state.Nice)}}
	r := bytes.NewReader(payload)
	var err error
	var replies [][]byte
	var infosGot bool
	for r.Len() > 0 {
		state.Ctx.LogD("sp-process-unmarshal", les, func(les LEs) string {
			return fmt.Sprintf(
				"SP with %s (nice %s): unmarshaling header",
				state.Node.Name, NicenessFmt(state.Nice),
			)
		})
		var head SPHead
		if _, err = xdr.Unmarshal(r, &head); err != nil {
			state.Ctx.LogE("sp-process-unmarshal", les, err, func(les LEs) string {
				return fmt.Sprintf(
					"SP with %s (nice %s): unmarshaling header",
					state.Node.Name, NicenessFmt(state.Nice),
				)
			})
			return nil, err
		}
		if head.Type != SPTypePing {
			state.RxLastNonPing = state.RxLastSeen
		}
		switch head.Type {
		case SPTypeHalt:
			state.Ctx.LogD(
				"sp-process-halt",
				append(les, LE{"Type", "halt"}), func(les LEs) string {
					return fmt.Sprintf(
						"SP with %s (nice %s): got HALT",
						state.Node.Name, NicenessFmt(state.Nice),
					)
				},
			)
			state.Lock()
			state.queueTheir = nil
			state.Unlock()

		case SPTypePing:
			state.Ctx.LogD(
				"sp-process-ping",
				append(les, LE{"Type", "ping"}),
				func(les LEs) string {
					return fmt.Sprintf(
						"SP with %s (nice %s): got PING",
						state.Node.Name, NicenessFmt(state.Nice),
					)
				},
			)

		case SPTypeInfo:
			infosGot = true
			lesp := append(les, LE{"Type", "info"})
			state.Ctx.LogD(
				"sp-process-info-unmarshal", lesp,
				func(les LEs) string {
					return fmt.Sprintf(
						"SP with %s (nice %s): unmarshaling INFO",
						state.Node.Name, NicenessFmt(state.Nice),
					)
				},
			)
			var info SPInfo
			if _, err = xdr.Unmarshal(r, &info); err != nil {
				state.Ctx.LogE(
					"sp-process-info-unmarshal", lesp, err,
					func(les LEs) string {
						return fmt.Sprintf(
							"SP with %s (nice %s): unmarshaling INFO",
							state.Node.Name, NicenessFmt(state.Nice),
						)
					},
				)
				return nil, err
			}
			pktName := Base32Codec.EncodeToString(info.Hash[:])
			lesp = append(
				lesp,
				LE{"Pkt", pktName},
				LE{"Size", int64(info.Size)},
				LE{"PktNice", int(info.Nice)},
			)
			logMsg := func(les LEs) string {
				return fmt.Sprintf(
					"SP with %s (nice %s): INFO %s (%s) nice %s",
					state.Node.Name, NicenessFmt(state.Nice),
					pktName,
					humanize.IBytes(info.Size),
					NicenessFmt(info.Nice),
				)
			}
			if !state.listOnly && info.Nice > state.Nice {
				state.Ctx.LogD("sp-process-info-too-nice", lesp, func(les LEs) string {
					return logMsg(les) + ": too nice"
				})
				continue
			}
			state.Ctx.LogD("sp-process-info-got", lesp, func(les LEs) string {
				return logMsg(les) + ": received"
			})
			if !state.listOnly && state.xxOnly == TTx {
				continue
			}
			state.Lock()
			state.infosTheir[*info.Hash] = &info
			state.Unlock()
			state.Ctx.LogD("sp-process-info-stat", lesp, func(les LEs) string {
				return logMsg(les) + ": stating part"
			})
			pktPath := filepath.Join(
				state.Ctx.Spool,
				state.Node.Id.String(),
				string(TRx),
				Base32Codec.EncodeToString(info.Hash[:]),
			)
			logMsg = func(les LEs) string {
				return fmt.Sprintf(
					"Packet %s (%s) (nice %s)",
					pktName,
					humanize.IBytes(info.Size),
					NicenessFmt(info.Nice),
				)
			}
			if _, err = os.Stat(pktPath); err == nil {
				state.Ctx.LogI("sp-info-done", lesp, func(les LEs) string {
					return logMsg(les) + ": already done"
				})
				if !state.listOnly {
					replies = append(replies, MarshalSP(SPTypeDone, SPDone{info.Hash}))
				}
				continue
			}
			if _, err = os.Stat(filepath.Join(
				state.Ctx.Spool, state.Node.Id.String(), string(TRx),
				SeenDir, Base32Codec.EncodeToString(info.Hash[:]),
			)); err == nil {
				state.Ctx.LogI("sp-info-seen", lesp, func(les LEs) string {
					return logMsg(les) + ": already seen"
				})
				if !state.listOnly {
					replies = append(replies, MarshalSP(SPTypeDone, SPDone{info.Hash}))
				}
				continue
			}
			if _, err = os.Stat(pktPath + NoCKSuffix); err == nil {
				state.Ctx.LogI("sp-info-nock", lesp, func(les LEs) string {
					return logMsg(les) + ": still not checksummed"
				})
				continue
			}
			fi, err := os.Stat(pktPath + PartSuffix)
			var offset int64
			if err == nil {
				offset = fi.Size()
			}
			if !state.Ctx.IsEnoughSpace(int64(info.Size) - offset) {
				state.Ctx.LogI("sp-info-no-space", lesp, func(les LEs) string {
					return logMsg(les) + ": not enough space"
				})
				continue
			}
			state.Ctx.LogI(
				"sp-info",
				append(lesp, LE{"Offset", offset}),
				func(les LEs) string {
					return fmt.Sprintf(
						"%s: %d%%", logMsg(les), 100*uint64(offset)/info.Size,
					)
				},
			)
			if !state.listOnly && (state.onlyPkts == nil || state.onlyPkts[*info.Hash]) {
				replies = append(replies, MarshalSP(
					SPTypeFreq,
					SPFreq{info.Hash, uint64(offset)},
				))
			}

		case SPTypeFile:
			lesp := append(les, LE{"Type", "file"})
			state.Ctx.LogD("sp-process-file", lesp, func(les LEs) string {
				return fmt.Sprintf(
					"SP with %s (nice %s): unmarshaling FILE",
					state.Node.Name, NicenessFmt(state.Nice),
				)
			})
			var file SPFile
			if _, err = xdr.Unmarshal(r, &file); err != nil {
				state.Ctx.LogE("sp-process-file", lesp, err, func(les LEs) string {
					return fmt.Sprintf(
						"SP with %s (nice %s): unmarshaling FILE",
						state.Node.Name, NicenessFmt(state.Nice),
					)
				})
				return nil, err
			}
			pktName := Base32Codec.EncodeToString(file.Hash[:])
			lesp = append(
				lesp,
				LE{"XX", string(TRx)},
				LE{"Pkt", pktName},
				LE{"Size", int64(len(file.Payload))},
			)
			logMsg := func(les LEs) string {
				return fmt.Sprintf(
					"Got packet %s (%s)",
					pktName, humanize.IBytes(uint64(len(file.Payload))),
				)
			}
			fullsize := int64(0)
			state.RLock()
			infoTheir := state.infosTheir[*file.Hash]
			state.RUnlock()
			if infoTheir == nil {
				state.Ctx.LogE("sp-file-open", lesp, err, func(les LEs) string {
					return logMsg(les) + ": unknown file"
				})
				continue
			}
			fullsize = int64(infoTheir.Size)
			lesp = append(lesp, LE{"FullSize", fullsize})
			dirToSync := filepath.Join(
				state.Ctx.Spool,
				state.Node.Id.String(),
				string(TRx),
			)
			filePath := filepath.Join(dirToSync, pktName)
			filePathPart := filePath + PartSuffix
			state.Ctx.LogD("sp-file-open", lesp, func(les LEs) string {
				return logMsg(les) + ": opening part"
			})
			state.fdsLock.RLock()
			fdAndFullSize, exists := state.fds[filePathPart]
			state.fdsLock.RUnlock()
			hasherAndOffset := state.fileHashers[filePath]
			var fd *os.File
			if exists {
				fd = fdAndFullSize.fd
			} else {
				fd, err = os.OpenFile(
					filePathPart,
					os.O_RDWR|os.O_CREATE,
					os.FileMode(0666),
				)
				if err != nil {
					state.Ctx.LogE("sp-file-open", lesp, err, func(les LEs) string {
						return logMsg(les) + ": opening part"
					})
					return nil, err
				}
				state.fdsLock.Lock()
				state.fds[filePathPart] = FdAndFullSize{fd: fd}
				state.fdsLock.Unlock()
				if !state.NoCK {
					hasherAndOffset = &MTHAndOffset{
						mth:    MTHNew(fullsize, int64(file.Offset)),
						offset: file.Offset,
					}
					state.fileHashers[filePath] = hasherAndOffset
				}
			}
			state.Ctx.LogD(
				"sp-file-seek",
				append(lesp, LE{"Offset", file.Offset}),
				func(les LEs) string {
					return fmt.Sprintf("%s: seeking %d", logMsg(les), file.Offset)
				})
			if _, err = fd.Seek(int64(file.Offset), io.SeekStart); err != nil {
				state.Ctx.LogE("sp-file-seek", lesp, err, func(les LEs) string {
					return logMsg(les) + ": seeking"
				})
				state.closeFd(filePathPart)
				return nil, err
			}
			state.Ctx.LogD("sp-file-write", lesp, func(les LEs) string {
				return logMsg(les) + ": writing"
			})
			if _, err = fd.Write(file.Payload); err != nil {
				state.Ctx.LogE("sp-file-write", lesp, err, func(les LEs) string {
					return logMsg(les) + ": writing"
				})
				state.closeFd(filePathPart)
				return nil, err
			}
			if hasherAndOffset != nil {
				if hasherAndOffset.offset == file.Offset {
					if _, err = hasherAndOffset.mth.Write(file.Payload); err != nil {
						panic(err)
					}
					hasherAndOffset.offset += uint64(len(file.Payload))
				} else {
					state.Ctx.LogE(
						"sp-file-offset-differs", lesp, errors.New("offset differs"),
						func(les LEs) string {
							return logMsg(les) + ": deleting hasher"
						},
					)
					delete(state.fileHashers, filePath)
					hasherAndOffset = nil
				}
			}
			ourSize := int64(file.Offset + uint64(len(file.Payload)))
			lesp[len(lesp)-2].V = ourSize
			if state.Ctx.ShowPrgrs {
				state.progressBars[pktName] = struct{}{}
				Progress("Rx", lesp)
			}
			if fullsize != ourSize {
				continue
			}
			if state.Ctx.ShowPrgrs {
				delete(state.progressBars, pktName)
			}
			logMsg = func(les LEs) string {
				return fmt.Sprintf(
					"Got packet %s %d%% (%s / %s)",
					pktName, 100*ourSize/fullsize,
					humanize.IBytes(uint64(ourSize)),
					humanize.IBytes(uint64(fullsize)),
				)
			}
			if !NoSync {
				err = fd.Sync()
				if err != nil {
					state.Ctx.LogE("sp-file-sync", lesp, err, func(les LEs) string {
						return logMsg(les) + ": syncing"
					})
					state.closeFd(filePathPart)
					continue
				}
			}
			if hasherAndOffset != nil {
				delete(state.fileHashers, filePath)
				if hasherAndOffset.mth.PreaddSize() == 0 {
					if bytes.Compare(hasherAndOffset.mth.Sum(nil), file.Hash[:]) != 0 {
						state.Ctx.LogE(
							"sp-file-bad-checksum", lesp,
							errors.New("checksum mismatch"),
							logMsg,
						)
						state.closeFd(filePathPart)
						continue
					}
					if err = os.Rename(filePathPart, filePath); err != nil {
						state.Ctx.LogE("sp-file-rename", lesp, err, func(les LEs) string {
							return logMsg(les) + ": renaming"
						})
						state.closeFd(filePathPart)
						continue
					}
					if err = DirSync(dirToSync); err != nil {
						state.Ctx.LogE("sp-file-dirsync", lesp, err, func(les LEs) string {
							return logMsg(les) + ": dirsyncing"
						})
						state.closeFd(filePathPart)
						continue
					}
					state.Ctx.LogI("sp-file-done", lesp, func(les LEs) string {
						return logMsg(les) + ": done"
					})
					state.wg.Add(1)
					go func() {
						state.payloads <- MarshalSP(SPTypeDone, SPDone{file.Hash})
						state.wg.Done()
					}()
					state.Lock()
					delete(state.infosTheir, *file.Hash)
					state.Unlock()
					if !state.Ctx.HdrUsage {
						continue
					}
					if _, err = fd.Seek(0, io.SeekStart); err != nil {
						state.Ctx.LogE("sp-file-seek", lesp, err, func(les LEs) string {
							return logMsg(les) + ": seeking"
						})
						state.closeFd(filePathPart)
						continue
					}
					_, pktEncRaw, err := state.Ctx.HdrRead(fd)
					state.closeFd(filePathPart)
					if err != nil {
						state.Ctx.LogE("sp-file-hdr-read", lesp, err, func(les LEs) string {
							return logMsg(les) + ": HdrReading"
						})
						continue
					}
					state.Ctx.HdrWrite(pktEncRaw, filePath)
					continue
				}
			}
			state.closeFd(filePathPart)
			if err = os.Rename(filePathPart, filePath+NoCKSuffix); err != nil {
				state.Ctx.LogE("sp-file-rename", lesp, err, func(les LEs) string {
					return logMsg(les) + ": renaming"
				})
				continue
			}
			if err = DirSync(dirToSync); err != nil {
				state.Ctx.LogE("sp-file-dirsync", lesp, err, func(les LEs) string {
					return logMsg(les) + ": dirsyncing"
				})
				continue
			}
			state.Ctx.LogI("sp-file-downloaded", lesp, func(les LEs) string {
				return logMsg(les) + ": downloaded"
			})
			state.Lock()
			delete(state.infosTheir, *file.Hash)
			state.Unlock()
			go func() {
				t := SPCheckerTask{
					nodeId: state.Node.Id,
					hsh:    file.Hash,
					done:   state.payloads,
				}
				if hasherAndOffset != nil {
					t.mth = hasherAndOffset.mth
				}
				spCheckerTasks <- t
			}()

		case SPTypeDone:
			lesp := append(les, LE{"Type", "done"})
			state.Ctx.LogD("sp-process-done-unmarshal", lesp, func(les LEs) string {
				return fmt.Sprintf(
					"SP with %s (nice %s): unmarshaling DONE",
					state.Node.Name, NicenessFmt(state.Nice),
				)
			})
			var done SPDone
			if _, err = xdr.Unmarshal(r, &done); err != nil {
				state.Ctx.LogE("sp-process-done-unmarshal", lesp, err, func(les LEs) string {
					return fmt.Sprintf(
						"SP with %s (nice %s): unmarshaling DONE",
						state.Node.Name, NicenessFmt(state.Nice),
					)
				})
				return nil, err
			}
			pktName := Base32Codec.EncodeToString(done.Hash[:])
			lesp = append(lesp, LE{"Pkt", pktName}, LE{"XX", string(TTx)})
			logMsg := func(les LEs) string {
				return fmt.Sprintf(
					"SP with %s (nice %s): DONE: removing %s",
					state.Node.Name, NicenessFmt(state.Nice), pktName,
				)
			}
			state.Ctx.LogD("sp-done", lesp, logMsg)
			pth := filepath.Join(
				state.Ctx.Spool,
				state.Node.Id.String(),
				string(TTx),
				pktName,
			)
			if err = os.Remove(pth); err == nil {
				state.Ctx.LogI("sp-done", lesp, func(les LEs) string {
					return fmt.Sprintf("Packet %s is sent", pktName)
				})
				if state.Ctx.HdrUsage {
					os.Remove(JobPath2Hdr(pth))
				}
			} else {
				state.Ctx.LogE("sp-done", lesp, err, logMsg)
			}

		case SPTypeFreq:
			lesp := append(les, LE{"Type", "freq"})
			state.Ctx.LogD("sp-process-freq", lesp, func(les LEs) string {
				return fmt.Sprintf(
					"SP with %s (nice %s): unmarshaling FREQ",
					state.Node.Name, NicenessFmt(state.Nice),
				)
			})
			var freq SPFreq
			if _, err = xdr.Unmarshal(r, &freq); err != nil {
				state.Ctx.LogE("sp-process-freq", lesp, err, func(les LEs) string {
					return fmt.Sprintf(
						"SP with %s (nice %s): unmarshaling FREQ",
						state.Node.Name, NicenessFmt(state.Nice),
					)
				})
				return nil, err
			}
			pktName := Base32Codec.EncodeToString(freq.Hash[:])
			lesp = append(lesp, LE{"Pkt", pktName}, LE{"Offset", freq.Offset})
			state.Ctx.LogD("sp-process-freq-queueing", lesp, func(les LEs) string {
				return fmt.Sprintf(
					"SP with %s (nice %s): FREQ %s: queuing",
					state.Node.Name, NicenessFmt(state.Nice), pktName,
				)
			})
			nice, exists := state.infosOurSeen[*freq.Hash]
			if exists {
				if state.onlyPkts == nil || !state.onlyPkts[*freq.Hash] {
					state.Lock()
					insertIdx := 0
					var freqWithNice *FreqWithNice
					for insertIdx, freqWithNice = range state.queueTheir {
						if freqWithNice.nice > nice {
							break
						}
					}
					state.queueTheir = append(state.queueTheir, nil)
					copy(state.queueTheir[insertIdx+1:], state.queueTheir[insertIdx:])
					state.queueTheir[insertIdx] = &FreqWithNice{&freq, nice}
					state.Unlock()
				} else {
					state.Ctx.LogD("sp-process-freq-skip", lesp, func(les LEs) string {
						return fmt.Sprintf(
							"SP with %s (nice %s): FREQ %s: skipping",
							state.Node.Name, NicenessFmt(state.Nice), pktName,
						)
					})
				}
			} else {
				state.Ctx.LogD("sp-process-freq-unknown", lesp, func(les LEs) string {
					return fmt.Sprintf(
						"SP with %s (nice %s): FREQ %s: unknown",
						state.Node.Name, NicenessFmt(state.Nice), pktName,
					)
				})
			}

		default:
			state.Ctx.LogE(
				"sp-process-type-unknown",
				append(les, LE{"Type", head.Type}),
				errors.New("unknown type"),
				func(les LEs) string {
					return fmt.Sprintf(
						"SP with %s (nice %s): %d",
						state.Node.Name, NicenessFmt(state.Nice), head.Type,
					)
				},
			)
			return nil, BadPktType
		}
	}

	if infosGot {
		var pkts int
		var size uint64
		state.RLock()
		for _, info := range state.infosTheir {
			pkts++
			size += info.Size
		}
		state.RUnlock()
		state.Ctx.LogI("sp-infos-rx", LEs{
			{"XX", string(TRx)},
			{"Node", state.Node.Id},
			{"Pkts", pkts},
			{"Size", int64(size)},
		}, func(les LEs) string {
			return fmt.Sprintf(
				"%s has got for us: %d packets, %s",
				state.Node.Name, pkts, humanize.IBytes(size),
			)
		})
	}
	return payloadsSplit(replies), nil
}

func SPChecker(ctx *Ctx) {
	for t := range spCheckerTasks {
		pktName := Base32Codec.EncodeToString(t.hsh[:])
		les := LEs{
			{"XX", string(TRx)},
			{"Node", t.nodeId},
			{"Pkt", pktName},
		}
		SPCheckerWg.Add(1)
		ctx.LogD("sp-checker", les, func(les LEs) string {
			return fmt.Sprintf("Checksumming %s/rx/%s", ctx.NodeName(t.nodeId), pktName)
		})
		size, err := ctx.CheckNoCK(t.nodeId, t.hsh, t.mth)
		les = append(les, LE{"Size", size})
		if err != nil {
			ctx.LogE("sp-checker", les, err, func(les LEs) string {
				return fmt.Sprintf(
					"Checksumming %s/rx/%s (%s)", ctx.NodeName(t.nodeId), pktName,
					humanize.IBytes(uint64(size)),
				)
			})
			SPCheckerWg.Done()
			continue
		}
		ctx.LogI("sp-checker-done", les, func(les LEs) string {
			return fmt.Sprintf(
				"Packet %s is retreived (%s)",
				pktName, humanize.IBytes(uint64(size)),
			)
		})
		SPCheckerWg.Done()
		go func(t SPCheckerTask) {
			defer func() { recover() }()
			t.done <- MarshalSP(SPTypeDone, SPDone{t.hsh})
		}(t)
	}
}
