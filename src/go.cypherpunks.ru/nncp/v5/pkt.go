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
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/poly1305"
)

type PktType uint8

const (
	EncBlkSize = 128 * (1 << 10)
	KDFXOFSize = chacha20poly1305.KeySize * 2

	PktTypeFile PktType = iota
	PktTypeFreq PktType = iota
	PktTypeExec PktType = iota
	PktTypeTrns PktType = iota

	MaxPathSize = 1<<8 - 1

	NNCPBundlePrefix = "NNCP"
)

var (
	MagicNNCPPv3 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'P', 0, 0, 3}
	MagicNNCPEv4 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'E', 0, 0, 4}
	BadMagic     error   = errors.New("Unknown magic number")
	BadPktType   error   = errors.New("Unknown packet type")

	PktOverhead     int64
	PktEncOverhead  int64
	PktSizeOverhead int64 = 8 + poly1305.TagSize
)

type Pkt struct {
	Magic   [8]byte
	Type    PktType
	Nice    uint8
	PathLen uint8
	Path    *[MaxPathSize]byte
}

type PktTbs struct {
	Magic     [8]byte
	Nice      uint8
	Sender    *NodeId
	Recipient *NodeId
	ExchPub   *[32]byte
}

type PktEnc struct {
	Magic     [8]byte
	Nice      uint8
	Sender    *NodeId
	Recipient *NodeId
	ExchPub   *[32]byte
	Sign      *[ed25519.SignatureSize]byte
}

func init() {
	pkt := Pkt{
		Type: PktTypeFile,
		Path: new([MaxPathSize]byte),
	}
	var buf bytes.Buffer
	n, err := xdr.Marshal(&buf, pkt)
	if err != nil {
		panic(err)
	}
	PktOverhead = int64(n)
	buf.Reset()

	dummyId, err := NodeIdFromString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		panic(err)
	}
	pktEnc := PktEnc{
		Magic:     MagicNNCPEv4,
		Nice:      123,
		Sender:    dummyId,
		Recipient: dummyId,
		ExchPub:   new([32]byte),
		Sign:      new([ed25519.SignatureSize]byte),
	}
	n, err = xdr.Marshal(&buf, pktEnc)
	if err != nil {
		panic(err)
	}
	PktEncOverhead = int64(n)
}

func NewPkt(typ PktType, nice uint8, path []byte) (*Pkt, error) {
	if len(path) > MaxPathSize {
		return nil, errors.New("Too long path")
	}
	pkt := Pkt{
		Magic:   MagicNNCPPv3,
		Type:    typ,
		Nice:    nice,
		PathLen: uint8(len(path)),
		Path:    new([MaxPathSize]byte),
	}
	copy(pkt.Path[:], path)
	return &pkt, nil
}

func aeadProcess(
	aead cipher.AEAD,
	nonce []byte,
	doEncrypt bool,
	r io.Reader,
	w io.Writer,
) (int, error) {
	var blkCtr uint64
	ciphCtr := nonce[len(nonce)-8:]
	buf := make([]byte, EncBlkSize+aead.Overhead())
	var toRead []byte
	var toWrite []byte
	var n int
	var readBytes int
	var err error
	if doEncrypt {
		toRead = buf[:EncBlkSize]
	} else {
		toRead = buf
	}
	for {
		n, err = io.ReadFull(r, toRead)
		if err != nil {
			if err == io.EOF {
				break
			}
			if err != io.ErrUnexpectedEOF {
				return readBytes + n, err
			}
		}
		readBytes += n
		blkCtr++
		binary.BigEndian.PutUint64(ciphCtr, blkCtr)
		if doEncrypt {
			toWrite = aead.Seal(buf[:0], nonce, buf[:n], nil)
		} else {
			toWrite, err = aead.Open(buf[:0], nonce, buf[:n], nil)
			if err != nil {
				return readBytes, err
			}
		}
		if _, err = w.Write(toWrite); err != nil {
			return readBytes, err
		}
	}
	return readBytes, nil
}

func sizeWithTags(size int64) (fullSize int64) {
	fullSize = size + (size/EncBlkSize)*poly1305.TagSize
	if size%EncBlkSize != 0 {
		fullSize += poly1305.TagSize
	}
	return
}

func PktEncWrite(
	our *NodeOur,
	their *Node,
	pkt *Pkt,
	nice uint8,
	size, padSize int64,
	data io.Reader,
	out io.Writer,
) error {
	pubEph, prvEph, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var pktBuf bytes.Buffer
	if _, err := xdr.Marshal(&pktBuf, pkt); err != nil {
		return err
	}
	tbs := PktTbs{
		Magic:     MagicNNCPEv4,
		Nice:      nice,
		Sender:    our.Id,
		Recipient: their.Id,
		ExchPub:   pubEph,
	}
	var tbsBuf bytes.Buffer
	if _, err = xdr.Marshal(&tbsBuf, &tbs); err != nil {
		return err
	}
	signature := new([ed25519.SignatureSize]byte)
	copy(signature[:], ed25519.Sign(our.SignPrv, tbsBuf.Bytes()))
	pktEnc := PktEnc{
		Magic:     MagicNNCPEv4,
		Nice:      nice,
		Sender:    our.Id,
		Recipient: their.Id,
		ExchPub:   pubEph,
		Sign:      signature,
	}
	if _, err = xdr.Marshal(out, &pktEnc); err != nil {
		return err
	}
	sharedKey := new([32]byte)
	curve25519.ScalarMult(sharedKey, prvEph, their.ExchPub)
	kdf, err := blake2b.NewXOF(KDFXOFSize, sharedKey[:])
	if err != nil {
		return err
	}
	if _, err = kdf.Write(MagicNNCPEv4[:]); err != nil {
		return err
	}

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err = io.ReadFull(kdf, key); err != nil {
		return err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())

	fullSize := pktBuf.Len() + int(size)
	sizeBuf := make([]byte, 8+aead.Overhead())
	binary.BigEndian.PutUint64(sizeBuf, uint64(sizeWithTags(int64(fullSize))))
	if _, err = out.Write(aead.Seal(sizeBuf[:0], nonce, sizeBuf[:8], nil)); err != nil {
		return err
	}

	lr := io.LimitedReader{R: data, N: size}
	mr := io.MultiReader(&pktBuf, &lr)
	written, err := aeadProcess(aead, nonce, true, mr, out)
	if err != nil {
		return err
	}
	if written != fullSize {
		return io.ErrUnexpectedEOF
	}
	if padSize > 0 {
		if _, err = io.ReadFull(kdf, key); err != nil {
			return err
		}
		kdf, err = blake2b.NewXOF(blake2b.OutputLengthUnknown, key)
		if err != nil {
			return err
		}
		if _, err = io.CopyN(out, kdf, padSize); err != nil {
			return err
		}
	}
	return nil
}

func TbsVerify(our *NodeOur, their *Node, pktEnc *PktEnc) (bool, error) {
	tbs := PktTbs{
		Magic:     MagicNNCPEv4,
		Nice:      pktEnc.Nice,
		Sender:    their.Id,
		Recipient: our.Id,
		ExchPub:   pktEnc.ExchPub,
	}
	var tbsBuf bytes.Buffer
	if _, err := xdr.Marshal(&tbsBuf, &tbs); err != nil {
		return false, err
	}
	return ed25519.Verify(their.SignPub, tbsBuf.Bytes(), pktEnc.Sign[:]), nil
}

func PktEncRead(
	our *NodeOur,
	nodes map[NodeId]*Node,
	data io.Reader,
	out io.Writer,
) (*Node, int64, error) {
	var pktEnc PktEnc
	_, err := xdr.Unmarshal(data, &pktEnc)
	if err != nil {
		return nil, 0, err
	}
	if pktEnc.Magic != MagicNNCPEv4 {
		return nil, 0, BadMagic
	}
	their, known := nodes[*pktEnc.Sender]
	if !known {
		return nil, 0, errors.New("Unknown sender")
	}
	if *pktEnc.Recipient != *our.Id {
		return nil, 0, errors.New("Invalid recipient")
	}
	verified, err := TbsVerify(our, their, &pktEnc)
	if err != nil {
		return nil, 0, err
	}
	if !verified {
		return their, 0, errors.New("Invalid signature")
	}
	sharedKey := new([32]byte)
	curve25519.ScalarMult(sharedKey, our.ExchPrv, pktEnc.ExchPub)
	kdf, err := blake2b.NewXOF(KDFXOFSize, sharedKey[:])
	if err != nil {
		return their, 0, err
	}
	if _, err = kdf.Write(MagicNNCPEv4[:]); err != nil {
		return their, 0, err
	}

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err = io.ReadFull(kdf, key); err != nil {
		return their, 0, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return their, 0, err
	}
	nonce := make([]byte, aead.NonceSize())

	sizeBuf := make([]byte, 8+aead.Overhead())
	if _, err = io.ReadFull(data, sizeBuf); err != nil {
		return their, 0, err
	}
	sizeBuf, err = aead.Open(sizeBuf[:0], nonce, sizeBuf, nil)
	if err != nil {
		return their, 0, err
	}
	size := int64(binary.BigEndian.Uint64(sizeBuf))

	lr := io.LimitedReader{R: data, N: size}
	written, err := aeadProcess(aead, nonce, false, &lr, out)
	if err != nil {
		return their, int64(written), err
	}
	if written != int(size) {
		return their, int64(written), io.ErrUnexpectedEOF
	}
	return their, size, nil
}
