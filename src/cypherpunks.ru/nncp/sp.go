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
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/davecgh/go-xdr/xdr2"
	"github.com/flynn/noise"
)

const (
	MaxSPSize       = 1<<16 - 256
	PartSuffix      = ".part"
	DefaultDeadline = 10
)

var (
	MagicNNCPLv1 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'S', 0, 0, 1}

	SPHeadOverhead    int
	SPInfoOverhead    int
	SPFreqOverhead    int
	SPFileOverhead    int
	SPHaltMarshalized []byte

	NoiseCipherSuite noise.CipherSuite = noise.NewCipherSuite(
		noise.DH25519,
		noise.CipherChaChaPoly,
		noise.HashBLAKE2b,
	)

	spWorkersGroup sync.WaitGroup
)

type SPType uint8

const (
	SPTypeInfo SPType = iota
	SPTypeFreq SPType = iota
	SPTypeFile SPType = iota
	SPTypeDone SPType = iota
	SPTypeHalt SPType = iota
)

type SPHead struct {
	Type SPType
}

type SPInfo struct {
	Nice uint8
	Size uint64
	Hash *[32]byte
}

type SPFreq struct {
	Hash   *[32]byte
	Offset uint64
}

type SPFile struct {
	Hash    *[32]byte
	Offset  uint64
	Payload []byte
}

type SPDone struct {
	Hash *[32]byte
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
	io.ReadWriter
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

func init() {
	var buf bytes.Buffer
	spHead := SPHead{Type: SPTypeHalt}
	if _, err := xdr.Marshal(&buf, spHead); err != nil {
		panic(err)
	}
	copy(SPHaltMarshalized, buf.Bytes())
	SPHeadOverhead = buf.Len()
	buf.Reset()

	spInfo := SPInfo{Nice: 123, Size: 123, Hash: new([32]byte)}
	if _, err := xdr.Marshal(&buf, spInfo); err != nil {
		panic(err)
	}
	SPInfoOverhead = buf.Len()
	buf.Reset()

	spFreq := SPFreq{Hash: new([32]byte), Offset: 123}
	if _, err := xdr.Marshal(&buf, spFreq); err != nil {
		panic(err)
	}
	SPFreqOverhead = buf.Len()
	buf.Reset()

	spFile := SPFile{Hash: new([32]byte), Offset: 123}
	if _, err := xdr.Marshal(&buf, spFile); err != nil {
		panic(err)
	}
	SPFileOverhead = buf.Len()
}

func MarshalSP(typ SPType, sp interface{}) []byte {
	var buf bytes.Buffer
	var err error
	if _, err = xdr.Marshal(&buf, SPHead{typ}); err != nil {
		panic(err)
	}
	if _, err = xdr.Marshal(&buf, sp); err != nil {
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
	onlineDeadline uint
	maxOnlineTime  uint
	hs             *noise.HandshakeState
	csOur          *noise.CipherState
	csTheir        *noise.CipherState
	payloads       chan []byte
	infosTheir     map[[32]byte]*SPInfo
	infosOurSeen   map[[32]byte]uint8
	queueTheir     []*FreqWithNice
	wg             sync.WaitGroup
	RxBytes        int64
	RxLastSeen     time.Time
	TxBytes        int64
	TxLastSeen     time.Time
	started        time.Time
	Duration       time.Duration
	RxSpeed        int64
	TxSpeed        int64
	rxLock         *os.File
	txLock         *os.File
	xxOnly         TRxTx
	rxRate         int
	txRate         int
	isDead         bool
	listOnly       bool
	onlyPkts       map[[32]byte]bool
	sync.RWMutex
}

func (state *SPState) NotAlive() bool {
	if state.isDead {
		return true
	}
	now := time.Now()
	if state.maxOnlineTime > 0 && state.started.Add(time.Duration(state.maxOnlineTime)*time.Second).Before(now) {
		return true
	}
	return uint(now.Sub(state.RxLastSeen).Seconds()) >= state.onlineDeadline &&
		uint(now.Sub(state.TxLastSeen).Seconds()) >= state.onlineDeadline
}

func (state *SPState) dirUnlock() {
	state.Ctx.UnlockDir(state.rxLock)
	state.Ctx.UnlockDir(state.txLock)
}

func (state *SPState) WriteSP(dst io.Writer, payload []byte) error {
	n, err := xdr.Marshal(dst, SPRaw{Magic: MagicNNCPLv1, Payload: payload})
	if err == nil {
		state.TxLastSeen = time.Now()
		state.TxBytes += int64(n)
	}
	return err
}

func (state *SPState) ReadSP(src io.Reader) ([]byte, error) {
	var sp SPRaw
	n, err := xdr.UnmarshalLimited(src, &sp, 1<<17)
	if err != nil {
		return nil, err
	}
	state.RxLastSeen = time.Now()
	state.RxBytes += int64(n)
	if sp.Magic != MagicNNCPLv1 {
		return nil, BadMagic
	}
	return sp.Payload, nil
}

func (ctx *Ctx) infosOur(nodeId *NodeId, nice uint8, seen *map[[32]byte]uint8) [][]byte {
	var infos []*SPInfo
	var totalSize int64
	for job := range ctx.Jobs(nodeId, TTx) {
		job.Fd.Close()
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
		ctx.LogD("sp-info-our", SDS{
			"node": nodeId,
			"name": ToBase32(info.Hash[:]),
			"size": strconv.FormatInt(int64(info.Size), 10),
		}, "")
	}
	if totalSize > 0 {
		ctx.LogI("sp-infos", SDS{
			"xx":   string(TTx),
			"node": nodeId,
			"pkts": strconv.Itoa(len(payloads)),
			"size": strconv.FormatInt(totalSize, 10),
		}, "")
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
		rxLock, err = state.Ctx.LockDir(nodeId, TRx)
		if err != nil {
			return err
		}
	}
	var txLock *os.File
	if !state.listOnly && (state.xxOnly == "" || state.xxOnly == TTx) {
		txLock, err = state.Ctx.LockDir(nodeId, TTx)
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
	state.infosTheir = make(map[[32]byte]*SPInfo)
	state.infosOurSeen = make(map[[32]byte]uint8)
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
	sds := SDS{"node": nodeId, "nice": strconv.Itoa(int(state.Nice))}
	state.Ctx.LogD("sp-start", sds, "sending first message")
	conn.SetWriteDeadline(time.Now().Add(DefaultDeadline * time.Second))
	if err = state.WriteSP(conn, buf); err != nil {
		state.Ctx.LogE("sp-start", SdsAdd(sds, SDS{"err": err}), "")
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-start", sds, "waiting for first message")
	conn.SetReadDeadline(time.Now().Add(DefaultDeadline * time.Second))
	if buf, err = state.ReadSP(conn); err != nil {
		state.Ctx.LogE("sp-start", SdsAdd(sds, SDS{"err": err}), "")
		state.dirUnlock()
		return err
	}
	payload, state.csOur, state.csTheir, err = state.hs.ReadMessage(nil, buf)
	if err != nil {
		state.Ctx.LogE("sp-start", SdsAdd(sds, SDS{"err": err}), "")
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-start", sds, "starting workers")
	err = state.StartWorkers(conn, infosPayloads, payload)
	if err != nil {
		state.Ctx.LogE("sp-start", SdsAdd(sds, SDS{"err": err}), "")
		state.dirUnlock()
		return err
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
	state.infosOurSeen = make(map[[32]byte]uint8)
	state.infosTheir = make(map[[32]byte]*SPInfo)
	state.started = started
	state.xxOnly = xxOnly
	var buf []byte
	var payload []byte
	state.Ctx.LogD(
		"sp-start",
		SDS{"nice": strconv.Itoa(int(state.Nice))},
		"waiting for first message",
	)
	conn.SetReadDeadline(time.Now().Add(DefaultDeadline * time.Second))
	if buf, err = state.ReadSP(conn); err != nil {
		state.Ctx.LogE("sp-start", SDS{"err": err}, "")
		return err
	}
	if payload, _, _, err = state.hs.ReadMessage(nil, buf); err != nil {
		state.Ctx.LogE("sp-start", SDS{"err": err}, "")
		return err
	}

	var node *Node
	for _, node = range state.Ctx.Neigh {
		if subtle.ConstantTimeCompare(state.hs.PeerStatic(), node.NoisePub[:]) == 1 {
			break
		}
	}
	if node == nil {
		peerId := ToBase32(state.hs.PeerStatic())
		state.Ctx.LogE("sp-start", SDS{"peer": peerId}, "unknown")
		return errors.New("Unknown peer: " + peerId)
	}
	state.Node = node
	state.rxRate = node.RxRate
	state.txRate = node.TxRate
	state.onlineDeadline = node.OnlineDeadline
	state.maxOnlineTime = node.MaxOnlineTime
	sds := SDS{"node": node.Id, "nice": strconv.Itoa(int(state.Nice))}

	if state.Ctx.ensureRxDir(node.Id); err != nil {
		return err
	}
	var rxLock *os.File
	if xxOnly == "" || xxOnly == TRx {
		rxLock, err = state.Ctx.LockDir(node.Id, TRx)
		if err != nil {
			return err
		}
	}
	state.rxLock = rxLock
	var txLock *os.File
	if xxOnly == "" || xxOnly == TTx {
		txLock, err = state.Ctx.LockDir(node.Id, TTx)
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

	state.Ctx.LogD("sp-start", sds, "sending first message")
	buf, state.csTheir, state.csOur, err = state.hs.WriteMessage(nil, firstPayload)
	if err != nil {
		state.dirUnlock()
		return err
	}
	conn.SetWriteDeadline(time.Now().Add(DefaultDeadline * time.Second))
	if err = state.WriteSP(conn, buf); err != nil {
		state.Ctx.LogE("sp-start", SdsAdd(sds, SDS{"err": err}), "")
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-start", sds, "starting workers")
	err = state.StartWorkers(conn, infosPayloads, payload)
	if err != nil {
		state.dirUnlock()
		return err
	}
	return err
}

func (state *SPState) StartWorkers(
	conn ConnDeadlined,
	infosPayloads [][]byte,
	payload []byte) error {
	sds := SDS{"node": state.Node.Id, "nice": strconv.Itoa(int(state.Nice))}
	if len(infosPayloads) > 1 {
		go func() {
			for _, payload := range infosPayloads[1:] {
				state.Ctx.LogD(
					"sp-work",
					SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
					"queuing remaining payload",
				)
				state.payloads <- payload
			}
		}()
	}
	state.Ctx.LogD(
		"sp-work",
		SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
		"processing first payload",
	)
	replies, err := state.ProcessSP(payload)
	if err != nil {
		state.Ctx.LogE("sp-work", SdsAdd(sds, SDS{"err": err}), "")
		return err
	}

	go func() {
		for _, reply := range replies {
			state.Ctx.LogD(
				"sp-work",
				SdsAdd(sds, SDS{"size": strconv.Itoa(len(reply))}),
				"queuing reply",
			)
			state.payloads <- reply
		}
	}()

	if !state.listOnly && (state.xxOnly == "" || state.xxOnly == TTx) {
		go func() {
			for range time.Tick(time.Second) {
				if state.NotAlive() {
					return
				}
				for _, payload := range state.Ctx.infosOur(
					state.Node.Id,
					state.Nice,
					&state.infosOurSeen,
				) {
					state.Ctx.LogD(
						"sp-work",
						SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
						"queuing new info",
					)
					state.payloads <- payload
				}
			}
		}()
	}

	state.wg.Add(1)
	go func() {
		defer func() {
			state.isDead = true
			state.wg.Done()
		}()
		for {
			if state.NotAlive() {
				return
			}
			var payload []byte
			select {
			case payload = <-state.payloads:
				state.Ctx.LogD(
					"sp-xmit",
					SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
					"got payload",
				)
			default:
			}
			if payload == nil {
				state.RLock()
				if len(state.queueTheir) == 0 {
					state.Ctx.LogD("sp-xmit", sds, "file queue is empty")
					state.RUnlock()
					time.Sleep(100 * time.Millisecond)
					continue
				}
				freq := state.queueTheir[0].freq
				state.RUnlock()

				if state.txRate > 0 {
					time.Sleep(time.Second / time.Duration(state.txRate))
				}

				sdsp := SdsAdd(sds, SDS{
					"xx":   string(TTx),
					"hash": ToBase32(freq.Hash[:]),
					"size": strconv.FormatInt(int64(freq.Offset), 10),
				})
				state.Ctx.LogD("sp-file", sdsp, "queueing")
				fd, err := os.Open(filepath.Join(
					state.Ctx.Spool,
					state.Node.Id.String(),
					string(TTx),
					ToBase32(freq.Hash[:]),
				))
				if err != nil {
					state.Ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
					break
				}
				fi, err := fd.Stat()
				if err != nil {
					state.Ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
					break
				}
				fullSize := uint64(fi.Size())
				var buf []byte
				if freq.Offset < fullSize {
					state.Ctx.LogD("sp-file", sdsp, "seeking")
					if _, err = fd.Seek(int64(freq.Offset), io.SeekStart); err != nil {
						state.Ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
						break
					}
					buf = make([]byte, MaxSPSize-SPHeadOverhead-SPFileOverhead)
					n, err := fd.Read(buf)
					if err != nil {
						state.Ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
						break
					}
					buf = buf[:n]
					state.Ctx.LogD(
						"sp-file",
						SdsAdd(sdsp, SDS{"size": strconv.Itoa(n)}),
						"read",
					)
				}
				fd.Close()
				payload = MarshalSP(SPTypeFile, SPFile{
					Hash:    freq.Hash,
					Offset:  freq.Offset,
					Payload: buf,
				})
				ourSize := freq.Offset + uint64(len(buf))
				sdsp["size"] = strconv.FormatInt(int64(ourSize), 10)
				sdsp["fullsize"] = strconv.FormatInt(int64(fullSize), 10)
				state.Ctx.LogP("sp-file", sdsp, "")
				state.Lock()
				if len(state.queueTheir) > 0 && *state.queueTheir[0].freq.Hash == *freq.Hash {
					if ourSize == fullSize {
						state.Ctx.LogD("sp-file", sdsp, "finished")
						if len(state.queueTheir) > 1 {
							state.queueTheir = state.queueTheir[1:]
						} else {
							state.queueTheir = state.queueTheir[:0]
						}
					} else {
						state.queueTheir[0].freq.Offset += uint64(len(buf))
					}
				} else {
					state.Ctx.LogD("sp-file", sdsp, "queue disappeared")
				}
				state.Unlock()
			}
			state.Ctx.LogD(
				"sp-xmit",
				SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
				"sending",
			)
			conn.SetWriteDeadline(time.Now().Add(DefaultDeadline * time.Second))
			if err := state.WriteSP(conn, state.csOur.Encrypt(nil, nil, payload)); err != nil {
				state.Ctx.LogE("sp-xmit", SdsAdd(sds, SDS{"err": err}), "")
				break
			}
		}
	}()

	state.wg.Add(1)
	go func() {
		defer func() {
			state.isDead = true
			state.wg.Done()
		}()
		for {
			if state.NotAlive() {
				return
			}
			state.Ctx.LogD("sp-recv", sds, "waiting for payload")
			conn.SetReadDeadline(time.Now().Add(DefaultDeadline * time.Second))
			payload, err := state.ReadSP(conn)
			if err != nil {
				unmarshalErr := err.(*xdr.UnmarshalError)
				netErr, ok := unmarshalErr.Err.(net.Error)
				if ok && netErr.Timeout() {
					continue
				}
				if unmarshalErr.ErrorCode == xdr.ErrIO {
					break
				}
				state.Ctx.LogE("sp-recv", SdsAdd(sds, SDS{"err": err}), "")
				break
			}
			state.Ctx.LogD(
				"sp-recv",
				SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
				"got payload",
			)
			payload, err = state.csTheir.Decrypt(nil, nil, payload)
			if err != nil {
				state.Ctx.LogE("sp-recv", SdsAdd(sds, SDS{"err": err}), "")
				break
			}
			state.Ctx.LogD(
				"sp-recv",
				SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
				"processing",
			)
			replies, err := state.ProcessSP(payload)
			if err != nil {
				state.Ctx.LogE("sp-recv", SdsAdd(sds, SDS{"err": err}), "")
				break
			}
			go func() {
				for _, reply := range replies {
					state.Ctx.LogD(
						"sp-recv",
						SdsAdd(sds, SDS{"size": strconv.Itoa(len(reply))}),
						"queuing reply",
					)
					state.payloads <- reply
				}
			}()
			if state.rxRate > 0 {
				time.Sleep(time.Second / time.Duration(state.rxRate))
			}
		}
	}()

	return nil
}

func (state *SPState) Wait() {
	state.wg.Wait()
	state.dirUnlock()
	state.Duration = time.Now().Sub(state.started)
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
}

func (state *SPState) ProcessSP(payload []byte) ([][]byte, error) {
	sds := SDS{"node": state.Node.Id, "nice": strconv.Itoa(int(state.Nice))}
	r := bytes.NewReader(payload)
	var err error
	var replies [][]byte
	var infosGot bool
	for r.Len() > 0 {
		state.Ctx.LogD("sp-process", sds, "unmarshaling header")
		var head SPHead
		if _, err = xdr.Unmarshal(r, &head); err != nil {
			state.Ctx.LogE("sp-process", SdsAdd(sds, SDS{"err": err}), "")
			return nil, err
		}
		switch head.Type {
		case SPTypeInfo:
			infosGot = true
			sdsp := SdsAdd(sds, SDS{"type": "info"})
			state.Ctx.LogD("sp-process", sdsp, "unmarshaling packet")
			var info SPInfo
			if _, err = xdr.Unmarshal(r, &info); err != nil {
				state.Ctx.LogE("sp-process", SdsAdd(sdsp, SDS{"err": err}), "")
				return nil, err
			}
			sdsp = SdsAdd(sds, SDS{
				"hash": ToBase32(info.Hash[:]),
				"size": strconv.FormatInt(int64(info.Size), 10),
				"nice": strconv.Itoa(int(info.Nice)),
			})
			if !state.listOnly && info.Nice > state.Nice {
				state.Ctx.LogD("sp-process", sdsp, "too nice")
				continue
			}
			state.Ctx.LogD("sp-process", sdsp, "received")
			if !state.listOnly && state.xxOnly == TTx {
				continue
			}
			state.Lock()
			state.infosTheir[*info.Hash] = &info
			state.Unlock()
			state.Ctx.LogD("sp-process", sdsp, "stating part")
			pktPath := filepath.Join(
				state.Ctx.Spool,
				state.Node.Id.String(),
				string(TRx),
				ToBase32(info.Hash[:]),
			)
			if _, err = os.Stat(pktPath); err == nil {
				state.Ctx.LogI("sp-info", sdsp, "already done")
				if !state.listOnly {
					replies = append(replies, MarshalSP(SPTypeDone, SPDone{info.Hash}))
				}
				continue
			}
			if _, err = os.Stat(pktPath + SeenSuffix); err == nil {
				state.Ctx.LogI("sp-info", sdsp, "already seen")
				if !state.listOnly {
					replies = append(replies, MarshalSP(SPTypeDone, SPDone{info.Hash}))
				}
				continue
			}
			fi, err := os.Stat(pktPath + PartSuffix)
			var offset int64
			if err == nil {
				offset = fi.Size()
			}
			if !state.Ctx.IsEnoughSpace(int64(info.Size) - offset) {
				state.Ctx.LogI("sp-info", sdsp, "not enough space")
				continue
			}
			state.Ctx.LogI(
				"sp-info",
				SdsAdd(sdsp, SDS{"offset": strconv.FormatInt(offset, 10)}),
				"",
			)
			if !state.listOnly && (state.onlyPkts == nil || state.onlyPkts[*info.Hash]) {
				replies = append(replies, MarshalSP(
					SPTypeFreq,
					SPFreq{info.Hash, uint64(offset)},
				))
			}
		case SPTypeFile:
			sdsp := SdsAdd(sds, SDS{"type": "file"})
			state.Ctx.LogD("sp-process", sdsp, "unmarshaling packet")
			var file SPFile
			if _, err = xdr.Unmarshal(r, &file); err != nil {
				state.Ctx.LogE("sp-process", SdsAdd(sds, SDS{
					"err":  err,
					"type": "file",
				}), "")
				return nil, err
			}
			sdsp["xx"] = string(TRx)
			sdsp["hash"] = ToBase32(file.Hash[:])
			sdsp["size"] = strconv.Itoa(len(file.Payload))
			filePath := filepath.Join(
				state.Ctx.Spool,
				state.Node.Id.String(),
				string(TRx),
				ToBase32(file.Hash[:]),
			)
			state.Ctx.LogD("sp-file", sdsp, "opening part")
			fd, err := os.OpenFile(
				filePath+PartSuffix,
				os.O_RDWR|os.O_CREATE,
				os.FileMode(0600),
			)
			if err != nil {
				state.Ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
				return nil, err
			}
			state.Ctx.LogD(
				"sp-file",
				SdsAdd(sdsp, SDS{"offset": strconv.FormatInt(int64(file.Offset), 10)}),
				"seeking",
			)
			if _, err = fd.Seek(int64(file.Offset), io.SeekStart); err != nil {
				state.Ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
				fd.Close()
				return nil, err
			}
			state.Ctx.LogD("sp-file", sdsp, "writing")
			_, err = fd.Write(file.Payload)
			if err != nil {
				state.Ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
				fd.Close()
				return nil, err
			}
			ourSize := uint64(file.Offset) + uint64(len(file.Payload))
			state.RLock()
			sdsp["fullsize"] = strconv.FormatInt(int64(state.infosTheir[*file.Hash].Size), 10)
			sdsp["size"] = strconv.FormatInt(int64(ourSize), 10)
			state.Ctx.LogP("sp-file", sdsp, "")
			if state.infosTheir[*file.Hash].Size != ourSize {
				state.RUnlock()
				fd.Close()
				continue
			}
			state.RUnlock()
			spWorkersGroup.Wait()
			spWorkersGroup.Add(1)
			go func() {
				if err := fd.Sync(); err != nil {
					state.Ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "sync")
					fd.Close()
					return
				}
				state.wg.Add(1)
				defer state.wg.Done()
				fd.Seek(0, io.SeekStart)
				state.Ctx.LogD("sp-file", sdsp, "checking")
				gut, err := Check(fd, file.Hash[:])
				fd.Close()
				if err != nil || !gut {
					state.Ctx.LogE("sp-file", sdsp, "checksum mismatch")
					return
				}
				state.Ctx.LogI("sp-done", SdsAdd(sdsp, SDS{"xx": string(TRx)}), "")
				os.Rename(filePath+PartSuffix, filePath)
				state.Lock()
				delete(state.infosTheir, *file.Hash)
				state.Unlock()
				spWorkersGroup.Done()
				go func() {
					state.payloads <- MarshalSP(SPTypeDone, SPDone{file.Hash})
				}()
			}()
		case SPTypeDone:
			sdsp := SdsAdd(sds, SDS{"type": "done"})
			state.Ctx.LogD("sp-process", sdsp, "unmarshaling packet")
			var done SPDone
			if _, err = xdr.Unmarshal(r, &done); err != nil {
				state.Ctx.LogE("sp-process", SdsAdd(sds, SDS{
					"type": "done",
					"err":  err,
				}), "")
				return nil, err
			}
			sdsp["hash"] = ToBase32(done.Hash[:])
			state.Ctx.LogD("sp-done", sdsp, "removing")
			err := os.Remove(filepath.Join(
				state.Ctx.Spool,
				state.Node.Id.String(),
				string(TTx),
				ToBase32(done.Hash[:]),
			))
			sdsp["xx"] = string(TTx)
			if err == nil {
				state.Ctx.LogI("sp-done", sdsp, "")
			} else {
				state.Ctx.LogE("sp-done", sdsp, "")
			}
		case SPTypeFreq:
			sdsp := SdsAdd(sds, SDS{"type": "freq"})
			state.Ctx.LogD("sp-process", sdsp, "unmarshaling packet")
			var freq SPFreq
			if _, err = xdr.Unmarshal(r, &freq); err != nil {
				state.Ctx.LogE("sp-process", SdsAdd(sdsp, SDS{"err": err}), "")
				return nil, err
			}
			sdsp["hash"] = ToBase32(freq.Hash[:])
			sdsp["offset"] = strconv.FormatInt(int64(freq.Offset), 10)
			state.Ctx.LogD("sp-process", sdsp, "queueing")
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
					state.Ctx.LogD("sp-process", sdsp, "skipping")
				}
			} else {
				state.Ctx.LogD("sp-process", sdsp, "unknown")
			}
		case SPTypeHalt:
			state.Ctx.LogD("sp-process", SdsAdd(sds, SDS{"type": "halt"}), "")
			state.Lock()
			state.queueTheir = nil
			state.Unlock()
		default:
			state.Ctx.LogE(
				"sp-process",
				SdsAdd(sds, SDS{"type": head.Type}),
				"unknown",
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
		state.Ctx.LogI("sp-infos", SDS{
			"xx":   string(TRx),
			"node": state.Node.Id,
			"pkts": strconv.Itoa(pkts),
			"size": strconv.FormatInt(int64(size), 10),
		}, "")
	}
	return payloadsSplit(replies), nil
}
