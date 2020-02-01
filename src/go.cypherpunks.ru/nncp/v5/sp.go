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

package nncp

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/flynn/noise"
)

const (
	MaxSPSize      = 1<<16 - 256
	PartSuffix     = ".part"
	SPHeadOverhead = 4
)

var (
	MagicNNCPLv1 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'S', 0, 0, 1}

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

	spWorkersGroup sync.WaitGroup
)

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
	io.ReadWriteCloser
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

func init() {
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
	onlineDeadline time.Duration
	maxOnlineTime  time.Duration
	hs             *noise.HandshakeState
	csOur          *noise.CipherState
	csTheir        *noise.CipherState
	payloads       chan []byte
	pings          chan struct{}
	infosTheir     map[[32]byte]*SPInfo
	infosOurSeen   map[[32]byte]uint8
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
	onlyPkts       map[[32]byte]bool
	writeSPBuf     bytes.Buffer
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
		for _ = range state.payloads {
		}
	}()
	go func() {
		for _ = range state.pings {
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
		Magic:   MagicNNCPLv1,
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
	if sp.Magic != MagicNNCPLv1 {
		return nil, BadMagic
	}
	return sp.Payload, nil
}

func (ctx *Ctx) infosOur(nodeId *NodeId, nice uint8, seen *map[[32]byte]uint8) [][]byte {
	var infos []*SPInfo
	var totalSize int64
	for job := range ctx.Jobs(nodeId, TTx) {
		job.Fd.Close() // #nosec G104
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
			"name": Base32Codec.EncodeToString(info.Hash[:]),
			"size": info.Size,
		}, "")
	}
	if totalSize > 0 {
		ctx.LogI("sp-infos", SDS{
			"xx":   string(TTx),
			"node": nodeId,
			"pkts": len(payloads),
			"size": totalSize,
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
	sds := SDS{"node": nodeId, "nice": int(state.Nice)}
	state.Ctx.LogD("sp-start", sds, "sending first message")
	conn.SetWriteDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
	if err = state.WriteSP(conn, buf, false); err != nil {
		state.Ctx.LogE("sp-start", sds, err, "")
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-start", sds, "waiting for first message")
	conn.SetReadDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
	if buf, err = state.ReadSP(conn); err != nil {
		state.Ctx.LogE("sp-start", sds, err, "")
		state.dirUnlock()
		return err
	}
	payload, state.csOur, state.csTheir, err = state.hs.ReadMessage(nil, buf)
	if err != nil {
		state.Ctx.LogE("sp-start", sds, err, "")
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-start", sds, "starting workers")
	err = state.StartWorkers(conn, infosPayloads, payload)
	if err != nil {
		state.Ctx.LogE("sp-start", sds, err, "")
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
	state.infosOurSeen = make(map[[32]byte]uint8)
	state.infosTheir = make(map[[32]byte]*SPInfo)
	state.started = started
	state.xxOnly = xxOnly
	var buf []byte
	var payload []byte
	state.Ctx.LogD("sp-start", SDS{"nice": int(state.Nice)}, "waiting for first message")
	conn.SetReadDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
	if buf, err = state.ReadSP(conn); err != nil {
		state.Ctx.LogE("sp-start", SDS{}, err, "")
		return err
	}
	if payload, _, _, err = state.hs.ReadMessage(nil, buf); err != nil {
		state.Ctx.LogE("sp-start", SDS{}, err, "")
		return err
	}

	var node *Node
	for _, n := range state.Ctx.Neigh {
		if subtle.ConstantTimeCompare(state.hs.PeerStatic(), n.NoisePub[:]) == 1 {
			node = n
			break
		}
	}
	if node == nil {
		peerId := Base32Codec.EncodeToString(state.hs.PeerStatic())
		state.Ctx.LogE("sp-start", SDS{"peer": peerId}, errors.New("unknown"), "")
		return errors.New("Unknown peer: " + peerId)
	}
	state.Node = node
	state.rxRate = node.RxRate
	state.txRate = node.TxRate
	state.onlineDeadline = node.OnlineDeadline
	state.maxOnlineTime = node.MaxOnlineTime
	sds := SDS{"node": node.Id, "nice": int(state.Nice)}

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

	state.Ctx.LogD("sp-start", sds, "sending first message")
	buf, state.csTheir, state.csOur, err = state.hs.WriteMessage(nil, firstPayload)
	if err != nil {
		state.dirUnlock()
		return err
	}
	conn.SetWriteDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
	if err = state.WriteSP(conn, buf, false); err != nil {
		state.Ctx.LogE("sp-start", sds, err, "")
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-start", sds, "starting workers")
	err = state.StartWorkers(conn, infosPayloads, payload)
	if err != nil {
		state.dirUnlock()
	}
	return err
}

func (state *SPState) StartWorkers(
	conn ConnDeadlined,
	infosPayloads [][]byte,
	payload []byte,
) error {
	sds := SDS{"node": state.Node.Id, "nice": int(state.Nice)}
	state.isDead = make(chan struct{})
	if state.maxOnlineTime > 0 {
		state.mustFinishAt = state.started.Add(state.maxOnlineTime)
	}

	// Remaining handshake payload sending
	if len(infosPayloads) > 1 {
		state.wg.Add(1)
		go func() {
			for _, payload := range infosPayloads[1:] {
				state.Ctx.LogD(
					"sp-work",
					SdsAdd(sds, SDS{"size": len(payload)}),
					"queuing remaining payload",
				)
				state.payloads <- payload
			}
			state.wg.Done()
		}()
	}

	// Processing of first payload and queueing its responses
	state.Ctx.LogD(
		"sp-work",
		SdsAdd(sds, SDS{"size": len(payload)}),
		"processing first payload",
	)
	replies, err := state.ProcessSP(payload)
	if err != nil {
		state.Ctx.LogE("sp-work", sds, err, "")
		return err
	}
	state.wg.Add(1)
	go func() {
		for _, reply := range replies {
			state.Ctx.LogD(
				"sp-work",
				SdsAdd(sds, SDS{"size": len(reply)}),
				"queuing reply",
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
				if (now.Sub(state.RxLastNonPing) >= state.onlineDeadline &&
					now.Sub(state.TxLastNonPing) >= state.onlineDeadline) ||
					(state.maxOnlineTime > 0 && state.mustFinishAt.Before(now)) ||
					(now.Sub(state.RxLastSeen) >= 2*PingTimeout) {
					state.SetDead()
					conn.Close() // #nosec G104
				}
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
			ticker := time.NewTicker(time.Second)
			for {
				select {
				case <-state.isDead:
					state.wg.Done()
					ticker.Stop()
					return
				case <-ticker.C:
					for _, payload := range state.Ctx.infosOur(
						state.Node.Id,
						state.Nice,
						&state.infosOurSeen,
					) {
						state.Ctx.LogD(
							"sp-work",
							SdsAdd(sds, SDS{"size": len(payload)}),
							"queuing new info",
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
		for {
			if state.NotAlive() {
				return
			}
			var payload []byte
			var ping bool
			select {
			case <-state.pings:
				state.Ctx.LogD("sp-xmit", sds, "got ping")
				payload = SPPingMarshalized
				ping = true
			case payload = <-state.payloads:
				state.Ctx.LogD(
					"sp-xmit",
					SdsAdd(sds, SDS{"size": len(payload)}),
					"got payload",
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
				sdsp := SdsAdd(sds, SDS{
					"xx":   string(TTx),
					"pkt":  Base32Codec.EncodeToString(freq.Hash[:]),
					"size": int64(freq.Offset),
				})
				state.Ctx.LogD("sp-file", sdsp, "queueing")
				fd, err := os.Open(filepath.Join(
					state.Ctx.Spool,
					state.Node.Id.String(),
					string(TTx),
					Base32Codec.EncodeToString(freq.Hash[:]),
				))
				if err != nil {
					state.Ctx.LogE("sp-file", sdsp, err, "")
					return
				}
				fi, err := fd.Stat()
				if err != nil {
					state.Ctx.LogE("sp-file", sdsp, err, "")
					return
				}
				fullSize := fi.Size()
				var buf []byte
				if freq.Offset < uint64(fullSize) {
					state.Ctx.LogD("sp-file", sdsp, "seeking")
					if _, err = fd.Seek(int64(freq.Offset), io.SeekStart); err != nil {
						state.Ctx.LogE("sp-file", sdsp, err, "")
						return
					}
					buf = make([]byte, MaxSPSize-SPHeadOverhead-SPFileOverhead)
					n, err := fd.Read(buf)
					if err != nil {
						state.Ctx.LogE("sp-file", sdsp, err, "")
						return
					}
					buf = buf[:n]
					state.Ctx.LogD("sp-file", SdsAdd(sdsp, SDS{"size": n}), "read")
				}
				fd.Close() // #nosec G104
				payload = MarshalSP(SPTypeFile, SPFile{
					Hash:    freq.Hash,
					Offset:  freq.Offset,
					Payload: buf,
				})
				ourSize := freq.Offset + uint64(len(buf))
				sdsp["size"] = int64(ourSize)
				sdsp["fullsize"] = fullSize
				if state.Ctx.ShowPrgrs {
					Progress("Tx", sdsp)
				}
				state.Lock()
				if len(state.queueTheir) > 0 && *state.queueTheir[0].freq.Hash == *freq.Hash {
					if ourSize == uint64(fullSize) {
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
			state.Ctx.LogD("sp-xmit", SdsAdd(sds, SDS{"size": len(payload)}), "sending")
			conn.SetWriteDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
			if err := state.WriteSP(conn, state.csOur.Encrypt(nil, nil, payload), ping); err != nil {
				state.Ctx.LogE("sp-xmit", sds, err, "")
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
			state.Ctx.LogD("sp-recv", sds, "waiting for payload")
			conn.SetReadDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
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
				state.Ctx.LogE("sp-recv", sds, err, "")
				break
			}
			state.Ctx.LogD(
				"sp-recv",
				SdsAdd(sds, SDS{"size": len(payload)}),
				"got payload",
			)
			payload, err = state.csTheir.Decrypt(nil, nil, payload)
			if err != nil {
				state.Ctx.LogE("sp-recv", sds, err, "")
				break
			}
			state.Ctx.LogD(
				"sp-recv",
				SdsAdd(sds, SDS{"size": len(payload)}),
				"processing",
			)
			replies, err := state.ProcessSP(payload)
			if err != nil {
				state.Ctx.LogE("sp-recv", sds, err, "")
				break
			}
			state.wg.Add(1)
			go func() {
				for _, reply := range replies {
					state.Ctx.LogD(
						"sp-recv",
						SdsAdd(sds, SDS{"size": len(reply)}),
						"queuing reply",
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
		conn.Close() // #nosec G104
	}()

	return nil
}

func (state *SPState) Wait() {
	state.wg.Wait()
	close(state.payloads)
	close(state.pings)
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
	sds := SDS{"node": state.Node.Id, "nice": int(state.Nice)}
	r := bytes.NewReader(payload)
	var err error
	var replies [][]byte
	var infosGot bool
	for r.Len() > 0 {
		state.Ctx.LogD("sp-process", sds, "unmarshaling header")
		var head SPHead
		if _, err = xdr.Unmarshal(r, &head); err != nil {
			state.Ctx.LogE("sp-process", sds, err, "")
			return nil, err
		}
		if head.Type != SPTypePing {
			state.RxLastNonPing = state.RxLastSeen
		}
		switch head.Type {
		case SPTypeHalt:
			state.Ctx.LogD("sp-process", SdsAdd(sds, SDS{"type": "halt"}), "")
			state.Lock()
			state.queueTheir = nil
			state.Unlock()
		case SPTypePing:
			state.Ctx.LogD("sp-process", SdsAdd(sds, SDS{"type": "ping"}), "")
		case SPTypeInfo:
			infosGot = true
			sdsp := SdsAdd(sds, SDS{"type": "info"})
			state.Ctx.LogD("sp-process", sdsp, "unmarshaling packet")
			var info SPInfo
			if _, err = xdr.Unmarshal(r, &info); err != nil {
				state.Ctx.LogE("sp-process", sdsp, err, "")
				return nil, err
			}
			sdsp = SdsAdd(sds, SDS{
				"pkt":  Base32Codec.EncodeToString(info.Hash[:]),
				"size": int64(info.Size),
				"nice": int(info.Nice),
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
				Base32Codec.EncodeToString(info.Hash[:]),
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
				SdsAdd(sdsp, SDS{"offset": offset}),
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
				state.Ctx.LogE("sp-process", SdsAdd(sds, SDS{"type": "file"}), err, "")
				return nil, err
			}
			sdsp["xx"] = string(TRx)
			sdsp["pkt"] = Base32Codec.EncodeToString(file.Hash[:])
			sdsp["size"] = len(file.Payload)
			dirToSync := filepath.Join(
				state.Ctx.Spool,
				state.Node.Id.String(),
				string(TRx),
			)
			filePath := filepath.Join(dirToSync, Base32Codec.EncodeToString(file.Hash[:]))
			state.Ctx.LogD("sp-file", sdsp, "opening part")
			fd, err := os.OpenFile(
				filePath+PartSuffix,
				os.O_RDWR|os.O_CREATE,
				os.FileMode(0666),
			)
			if err != nil {
				state.Ctx.LogE("sp-file", sdsp, err, "")
				return nil, err
			}
			state.Ctx.LogD(
				"sp-file",
				SdsAdd(sdsp, SDS{"offset": file.Offset}),
				"seeking",
			)
			if _, err = fd.Seek(int64(file.Offset), io.SeekStart); err != nil {
				state.Ctx.LogE("sp-file", sdsp, err, "")
				fd.Close() // #nosec G104
				return nil, err
			}
			state.Ctx.LogD("sp-file", sdsp, "writing")
			_, err = fd.Write(file.Payload)
			if err != nil {
				state.Ctx.LogE("sp-file", sdsp, err, "")
				fd.Close() // #nosec G104
				return nil, err
			}
			ourSize := int64(file.Offset + uint64(len(file.Payload)))
			sdsp["size"] = ourSize
			fullsize := int64(0)
			state.RLock()
			infoTheir, ok := state.infosTheir[*file.Hash]
			state.RUnlock()
			if ok {
				fullsize = int64(infoTheir.Size)
			}
			sdsp["fullsize"] = fullsize
			if state.Ctx.ShowPrgrs {
				Progress("Rx", sdsp)
			}
			if fullsize != ourSize {
				fd.Close() // #nosec G104
				continue
			}
			spWorkersGroup.Wait()
			spWorkersGroup.Add(1)
			go func() {
				if err := fd.Sync(); err != nil {
					state.Ctx.LogE("sp-file", sdsp, err, "sync")
					fd.Close() // #nosec G104
					return
				}
				state.wg.Add(1)
				defer state.wg.Done()
				if _, err = fd.Seek(0, io.SeekStart); err != nil {
					fd.Close() // #nosec G104
					state.Ctx.LogE("sp-file", sdsp, err, "")
					return
				}
				state.Ctx.LogD("sp-file", sdsp, "checking")
				gut, err := Check(fd, file.Hash[:], sdsp, state.Ctx.ShowPrgrs)
				fd.Close() // #nosec G104
				if err != nil || !gut {
					state.Ctx.LogE("sp-file", sdsp, errors.New("checksum mismatch"), "")
					return
				}
				state.Ctx.LogI("sp-done", SdsAdd(sdsp, SDS{"xx": string(TRx)}), "")
				if err = os.Rename(filePath+PartSuffix, filePath); err != nil {
					state.Ctx.LogE("sp-file", sdsp, err, "rename")
					return
				}
				if err = DirSync(dirToSync); err != nil {
					state.Ctx.LogE("sp-file", sdsp, err, "sync")
					return
				}
				state.Lock()
				delete(state.infosTheir, *file.Hash)
				state.Unlock()
				spWorkersGroup.Done()
				state.wg.Add(1)
				go func() {
					state.payloads <- MarshalSP(SPTypeDone, SPDone{file.Hash})
					state.wg.Done()
				}()
			}()
		case SPTypeDone:
			sdsp := SdsAdd(sds, SDS{"type": "done"})
			state.Ctx.LogD("sp-process", sdsp, "unmarshaling packet")
			var done SPDone
			if _, err = xdr.Unmarshal(r, &done); err != nil {
				state.Ctx.LogE("sp-process", SdsAdd(sds, SDS{"type": "done"}), err, "")
				return nil, err
			}
			sdsp["pkt"] = Base32Codec.EncodeToString(done.Hash[:])
			state.Ctx.LogD("sp-done", sdsp, "removing")
			err := os.Remove(filepath.Join(
				state.Ctx.Spool,
				state.Node.Id.String(),
				string(TTx),
				Base32Codec.EncodeToString(done.Hash[:]),
			))
			sdsp["xx"] = string(TTx)
			if err == nil {
				state.Ctx.LogI("sp-done", sdsp, "")
			} else {
				state.Ctx.LogE("sp-done", sdsp, err, "")
			}
		case SPTypeFreq:
			sdsp := SdsAdd(sds, SDS{"type": "freq"})
			state.Ctx.LogD("sp-process", sdsp, "unmarshaling packet")
			var freq SPFreq
			if _, err = xdr.Unmarshal(r, &freq); err != nil {
				state.Ctx.LogE("sp-process", sdsp, err, "")
				return nil, err
			}
			sdsp["pkt"] = Base32Codec.EncodeToString(freq.Hash[:])
			sdsp["offset"] = freq.Offset
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
		default:
			state.Ctx.LogE(
				"sp-process",
				SdsAdd(sds, SDS{"type": head.Type}),
				errors.New("unknown type"),
				"",
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
			"pkts": pkts,
			"size": int64(size),
		}, "")
	}
	return payloadsSplit(replies), nil
}
