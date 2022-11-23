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
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/poly1305"
	"lukechampine.com/blake3"
)

type PktType uint8

const (
	EncBlkSize = 128 * (1 << 10)

	PktTypeFile    PktType = iota
	PktTypeFreq    PktType = iota
	PktTypeExec    PktType = iota
	PktTypeTrns    PktType = iota
	PktTypeExecFat PktType = iota
	PktTypeArea    PktType = iota
	PktTypeACK     PktType = iota

	MaxPathSize = 1<<8 - 1

	NNCPBundlePrefix = "NNCP"
)

var (
	BadPktType error = errors.New("Unknown packet type")

	DeriveKeyFullCtx = string(MagicNNCPEv6.B[:]) + " FULL"
	DeriveKeySizeCtx = string(MagicNNCPEv6.B[:]) + " SIZE"
	DeriveKeyPadCtx  = string(MagicNNCPEv6.B[:]) + " PAD"

	PktOverhead     int64
	PktEncOverhead  int64
	PktSizeOverhead int64

	TooBig = errors.New("Too big than allowed")
)

type Pkt struct {
	Magic   [8]byte
	Type    PktType
	Nice    uint8
	PathLen uint8
	Path    [MaxPathSize]byte
}

type PktTbs struct {
	Magic     [8]byte
	Nice      uint8
	Sender    *NodeId
	Recipient *NodeId
	ExchPub   [32]byte
}

type PktEnc struct {
	Magic     [8]byte
	Nice      uint8
	Sender    *NodeId
	Recipient *NodeId
	ExchPub   [32]byte
	Sign      [ed25519.SignatureSize]byte
}

type PktSize struct {
	Payload uint64
	Pad     uint64
}

func NewPkt(typ PktType, nice uint8, path []byte) (*Pkt, error) {
	if len(path) > MaxPathSize {
		return nil, errors.New("Too long path")
	}
	pkt := Pkt{
		Magic:   MagicNNCPPv3.B,
		Type:    typ,
		Nice:    nice,
		PathLen: uint8(len(path)),
	}
	copy(pkt.Path[:], path)
	return &pkt, nil
}

func init() {
	var buf bytes.Buffer
	pkt := Pkt{Type: PktTypeFile}
	n, err := xdr.Marshal(&buf, pkt)
	if err != nil {
		panic(err)
	}
	PktOverhead = int64(n)
	buf.Reset()

	dummyId, err := NodeIdFromString(DummyB32Id)
	if err != nil {
		panic(err)
	}
	pktEnc := PktEnc{
		Magic:     MagicNNCPEv6.B,
		Sender:    dummyId,
		Recipient: dummyId,
	}
	n, err = xdr.Marshal(&buf, pktEnc)
	if err != nil {
		panic(err)
	}
	PktEncOverhead = int64(n)
	buf.Reset()

	size := PktSize{}
	n, err = xdr.Marshal(&buf, size)
	if err != nil {
		panic(err)
	}
	PktSizeOverhead = int64(n)
}

func ctrIncr(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
	panic("counter overflow")
}

func TbsPrepare(our *NodeOur, their *Node, pktEnc *PktEnc) []byte {
	tbs := PktTbs{
		Magic:     MagicNNCPEv6.B,
		Nice:      pktEnc.Nice,
		Sender:    their.Id,
		Recipient: our.Id,
		ExchPub:   pktEnc.ExchPub,
	}
	var tbsBuf bytes.Buffer
	if _, err := xdr.Marshal(&tbsBuf, &tbs); err != nil {
		panic(err)
	}
	return tbsBuf.Bytes()
}

func TbsVerify(our *NodeOur, their *Node, pktEnc *PktEnc) ([]byte, bool, error) {
	tbs := TbsPrepare(our, their, pktEnc)
	return tbs, ed25519.Verify(their.SignPub, tbs, pktEnc.Sign[:]), nil
}

func sizeWithTags(size int64) (fullSize int64) {
	size += PktSizeOverhead
	fullSize = size + (size/EncBlkSize)*poly1305.TagSize
	if size%EncBlkSize != 0 {
		fullSize += poly1305.TagSize
	}
	return
}

func sizePadCalc(sizePayload, minSize int64, wrappers int) (sizePad int64) {
	expectedSize := sizePayload - PktOverhead
	for i := 0; i < wrappers; i++ {
		expectedSize = PktEncOverhead + sizeWithTags(PktOverhead+expectedSize)
	}
	sizePad = minSize - expectedSize
	if sizePad < 0 {
		sizePad = 0
	}
	return
}

func PktEncWrite(
	our *NodeOur, their *Node,
	pkt *Pkt, nice uint8,
	minSize, maxSize int64, wrappers int,
	r io.Reader, w io.Writer,
) (pktEncRaw []byte, size int64, err error) {
	pub, prv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, 0, err
	}

	var buf bytes.Buffer
	_, err = xdr.Marshal(&buf, pkt)
	if err != nil {
		return
	}
	pktRaw := make([]byte, buf.Len())
	copy(pktRaw, buf.Bytes())
	buf.Reset()

	tbs := PktTbs{
		Magic:     MagicNNCPEv6.B,
		Nice:      nice,
		Sender:    our.Id,
		Recipient: their.Id,
		ExchPub:   *pub,
	}
	_, err = xdr.Marshal(&buf, &tbs)
	if err != nil {
		return
	}
	signature := new([ed25519.SignatureSize]byte)
	copy(signature[:], ed25519.Sign(our.SignPrv, buf.Bytes()))
	ad := blake3.Sum256(buf.Bytes())
	buf.Reset()

	pktEnc := PktEnc{
		Magic:     MagicNNCPEv6.B,
		Nice:      nice,
		Sender:    our.Id,
		Recipient: their.Id,
		ExchPub:   *pub,
		Sign:      *signature,
	}
	_, err = xdr.Marshal(&buf, &pktEnc)
	if err != nil {
		return
	}
	pktEncRaw = make([]byte, buf.Len())
	copy(pktEncRaw, buf.Bytes())
	buf.Reset()
	_, err = w.Write(pktEncRaw)
	if err != nil {
		return
	}

	sharedKey := new([32]byte)
	curve25519.ScalarMult(sharedKey, prv, their.ExchPub)
	keyFull := make([]byte, chacha20poly1305.KeySize)
	keySize := make([]byte, chacha20poly1305.KeySize)
	blake3.DeriveKey(keyFull, DeriveKeyFullCtx, sharedKey[:])
	blake3.DeriveKey(keySize, DeriveKeySizeCtx, sharedKey[:])
	aeadFull, err := chacha20poly1305.New(keyFull)
	if err != nil {
		return
	}
	aeadSize, err := chacha20poly1305.New(keySize)
	if err != nil {
		return
	}
	nonce := make([]byte, aeadFull.NonceSize())

	data := make([]byte, EncBlkSize, EncBlkSize+aeadFull.Overhead())
	mr := io.MultiReader(bytes.NewReader(pktRaw), r)
	var sizePayload int64
	var n int
	var ct []byte
	for {
		n, err = io.ReadFull(mr, data)
		sizePayload += int64(n)
		if sizePayload > maxSize {
			err = TooBig
			return
		}
		if err == nil {
			ct = aeadFull.Seal(data[:0], nonce, data[:n], ad[:])
			_, err = w.Write(ct)
			if err != nil {
				return
			}
			ctrIncr(nonce)
			continue
		}
		if !(err == io.EOF || err == io.ErrUnexpectedEOF) {
			return
		}
		break
	}

	sizePad := sizePadCalc(sizePayload, minSize, wrappers)
	_, err = xdr.Marshal(&buf, &PktSize{uint64(sizePayload), uint64(sizePad)})
	if err != nil {
		return
	}

	var aeadLast cipher.AEAD
	if n+int(PktSizeOverhead) > EncBlkSize {
		left := make([]byte, (n+int(PktSizeOverhead))-EncBlkSize)
		copy(left, data[n-len(left):])
		copy(data[PktSizeOverhead:], data[:n-len(left)])
		copy(data[:PktSizeOverhead], buf.Bytes())
		ct = aeadSize.Seal(data[:0], nonce, data[:EncBlkSize], ad[:])
		_, err = w.Write(ct)
		if err != nil {
			return
		}
		ctrIncr(nonce)
		copy(data, left)
		n = len(left)
		aeadLast = aeadFull
	} else {
		copy(data[PktSizeOverhead:], data[:n])
		copy(data[:PktSizeOverhead], buf.Bytes())
		n += int(PktSizeOverhead)
		aeadLast = aeadSize
	}

	var sizeBlockPadded int
	var sizePadLeft int64
	if sizePad > EncBlkSize-int64(n) {
		sizeBlockPadded = EncBlkSize
		sizePadLeft = sizePad - (EncBlkSize - int64(n))
	} else {
		sizeBlockPadded = n + int(sizePad)
		sizePadLeft = 0
	}
	for i := n; i < sizeBlockPadded; i++ {
		data[i] = 0
	}
	ct = aeadLast.Seal(data[:0], nonce, data[:sizeBlockPadded], ad[:])
	_, err = w.Write(ct)
	if err != nil {
		return
	}

	size = sizePayload
	if sizePadLeft > 0 {
		keyPad := make([]byte, chacha20poly1305.KeySize)
		blake3.DeriveKey(keyPad, DeriveKeyPadCtx, sharedKey[:])
		_, err = io.CopyN(w, blake3.New(32, keyPad).XOF(), sizePadLeft)
	}
	return
}

func PktEncRead(
	our *NodeOur, nodes map[NodeId]*Node,
	r io.Reader, w io.Writer,
	signatureVerify bool,
	sharedKeyCached []byte,
) (sharedKey []byte, their *Node, size int64, err error) {
	var pktEnc PktEnc
	_, err = xdr.Unmarshal(r, &pktEnc)
	if err != nil {
		return
	}
	switch pktEnc.Magic {
	case MagicNNCPEv1.B:
		err = MagicNNCPEv1.TooOld()
	case MagicNNCPEv2.B:
		err = MagicNNCPEv2.TooOld()
	case MagicNNCPEv3.B:
		err = MagicNNCPEv3.TooOld()
	case MagicNNCPEv4.B:
		err = MagicNNCPEv4.TooOld()
	case MagicNNCPEv5.B:
		err = MagicNNCPEv5.TooOld()
	case MagicNNCPEv6.B:
	default:
		err = BadMagic
	}
	if err != nil {
		return
	}
	if *pktEnc.Recipient != *our.Id {
		err = errors.New("Invalid recipient")
		return
	}

	var tbsRaw []byte
	if signatureVerify {
		their = nodes[*pktEnc.Sender]
		if their == nil {
			err = errors.New("Unknown sender")
			return
		}
		var verified bool
		tbsRaw, verified, err = TbsVerify(our, their, &pktEnc)
		if err != nil {
			return
		}
		if !verified {
			err = errors.New("Invalid signature")
			return
		}
	} else {
		tbsRaw = TbsPrepare(our, &Node{Id: pktEnc.Sender}, &pktEnc)
	}
	ad := blake3.Sum256(tbsRaw)
	if sharedKeyCached == nil {
		key := new([32]byte)
		curve25519.ScalarMult(key, our.ExchPrv, &pktEnc.ExchPub)
		sharedKey = key[:]
	} else {
		sharedKey = sharedKeyCached
	}

	keyFull := make([]byte, chacha20poly1305.KeySize)
	keySize := make([]byte, chacha20poly1305.KeySize)
	blake3.DeriveKey(keyFull, DeriveKeyFullCtx, sharedKey[:])
	blake3.DeriveKey(keySize, DeriveKeySizeCtx, sharedKey[:])
	aeadFull, err := chacha20poly1305.New(keyFull)
	if err != nil {
		return
	}
	aeadSize, err := chacha20poly1305.New(keySize)
	if err != nil {
		return
	}
	nonce := make([]byte, aeadFull.NonceSize())

	ct := make([]byte, EncBlkSize+aeadFull.Overhead())
	pt := make([]byte, EncBlkSize)
	var n int
FullRead:
	for {
		n, err = io.ReadFull(r, ct)
		switch err {
		case nil:
			pt, err = aeadFull.Open(pt[:0], nonce, ct, ad[:])
			if err != nil {
				break FullRead
			}
			size += EncBlkSize
			_, err = w.Write(pt)
			if err != nil {
				return
			}
			ctrIncr(nonce)
			continue
		case io.ErrUnexpectedEOF:
			break FullRead
		default:
			return
		}
	}

	pt, err = aeadSize.Open(pt[:0], nonce, ct[:n], ad[:])
	if err != nil {
		return
	}
	var pktSize PktSize
	_, err = xdr.Unmarshal(bytes.NewReader(pt), &pktSize)
	if err != nil {
		return
	}
	pt = pt[PktSizeOverhead:]

	left := int64(pktSize.Payload) - size
	for left > int64(len(pt)) {
		size += int64(len(pt))
		left -= int64(len(pt))
		_, err = w.Write(pt)
		if err != nil {
			return
		}
		n, err = io.ReadFull(r, ct)
		if err != nil && err != io.ErrUnexpectedEOF {
			return
		}
		ctrIncr(nonce)
		pt, err = aeadFull.Open(pt[:0], nonce, ct[:n], ad[:])
		if err != nil {
			return
		}
	}
	size += left
	_, err = w.Write(pt[:left])
	if err != nil {
		return
	}
	pt = pt[left:]

	if pktSize.Pad < uint64(len(pt)) {
		err = errors.New("unexpected pad")
		return
	}
	for i := 0; i < len(pt); i++ {
		if pt[i] != 0 {
			err = errors.New("non-zero pad byte")
			return
		}
	}
	sizePad := int64(pktSize.Pad) - int64(len(pt))
	if sizePad == 0 {
		return
	}

	keyPad := make([]byte, chacha20poly1305.KeySize)
	blake3.DeriveKey(keyPad, DeriveKeyPadCtx, sharedKey[:])
	xof := blake3.New(32, keyPad).XOF()
	pt = make([]byte, len(ct))
	for sizePad > 0 {
		n, err = io.ReadFull(r, ct)
		if err != nil && err != io.ErrUnexpectedEOF {
			return
		}
		_, err = io.ReadFull(xof, pt[:n])
		if err != nil {
			panic(err)
		}
		if bytes.Compare(ct[:n], pt[:n]) != 0 {
			err = errors.New("wrong pad value")
			return
		}
		sizePad -= int64(n)
	}
	if sizePad < 0 {
		err = errors.New("excess pad")
	}
	return
}
