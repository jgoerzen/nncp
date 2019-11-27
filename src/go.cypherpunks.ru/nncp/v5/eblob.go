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
	"crypto/rand"
	"hash"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"go.cypherpunks.ru/balloon"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	DefaultS = 1 << 20 / 32
	DefaultT = 1 << 4
	DefaultP = 2
)

var (
	MagicNNCPBv3 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'B', 0, 0, 3}
)

type EBlob struct {
	Magic [8]byte
	SCost uint32
	TCost uint32
	PCost uint32
	Salt  *[32]byte
	Blob  []byte
}

func blake256() hash.Hash {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

// Create an encrypted blob. sCost -- memory space requirements, number
// of hash-output sized (32 bytes) blocks. tCost -- time requirements,
// number of rounds. pCost -- number of parallel jobs.
func NewEBlob(sCost, tCost, pCost int, password, data []byte) ([]byte, error) {
	salt := new([32]byte)
	var err error
	if _, err = rand.Read(salt[:]); err != nil {
		return nil, err
	}
	eblob := EBlob{
		Magic: MagicNNCPBv3,
		SCost: uint32(sCost),
		TCost: uint32(tCost),
		PCost: uint32(pCost),
		Salt:  salt,
		Blob:  nil,
	}
	var eblobBuf bytes.Buffer
	if _, err = xdr.Marshal(&eblobBuf, &eblob); err != nil {
		return nil, err
	}
	key := balloon.H(blake256, password, salt[:], sCost, tCost, pCost)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(data)+aead.Overhead())
	buf = aead.Seal(buf, make([]byte, aead.NonceSize()), data, eblobBuf.Bytes())
	eblob.Blob = buf
	eblobBuf.Reset()
	if _, err = xdr.Marshal(&eblobBuf, &eblob); err != nil {
		return nil, err
	}
	return eblobBuf.Bytes(), nil
}

func DeEBlob(eblobRaw, password []byte) ([]byte, error) {
	var eblob EBlob
	var err error
	if _, err = xdr.Unmarshal(bytes.NewReader(eblobRaw), &eblob); err != nil {
		return nil, err
	}
	if eblob.Magic != MagicNNCPBv3 {
		return nil, BadMagic
	}
	key := balloon.H(
		blake256,
		password,
		eblob.Salt[:],
		int(eblob.SCost),
		int(eblob.TCost),
		int(eblob.PCost),
	)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	ciphertext := eblob.Blob
	eblob.Blob = nil
	var eblobBuf bytes.Buffer
	if _, err = xdr.Marshal(&eblobBuf, &eblob); err != nil {
		return nil, err
	}
	data, err := aead.Open(
		ciphertext[:0],
		make([]byte, aead.NonceSize()),
		ciphertext,
		eblobBuf.Bytes(),
	)
	if err != nil {
		return nil, err
	}
	return data, nil
}
