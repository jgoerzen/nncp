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
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

type NodeId [blake2b.Size256]byte

func (id NodeId) String() string {
	return Base32Codec.EncodeToString(id[:])
}

type Node struct {
	Name           string
	Id             *NodeId
	ExchPub        *[32]byte
	SignPub        ed25519.PublicKey
	NoisePub       *[32]byte
	Exec           map[string][]string
	Incoming       *string
	FreqPath       *string
	FreqChunked    int64
	FreqMinSize    int64
	FreqMaxSize    int64
	Via            []*NodeId
	Addrs          map[string]string
	RxRate         int
	TxRate         int
	OnlineDeadline time.Duration
	MaxOnlineTime  time.Duration
	Calls          []*Call

	Busy bool
	sync.Mutex
}

type NodeOur struct {
	Id       *NodeId
	ExchPub  *[32]byte
	ExchPrv  *[32]byte
	SignPub  ed25519.PublicKey
	SignPrv  ed25519.PrivateKey
	NoisePub *[32]byte
	NoisePrv *[32]byte
}

func NewNodeGenerate() (*NodeOur, error) {
	exchPub, exchPrv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signPub, signPrv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	noiseKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	noisePub := new([32]byte)
	noisePrv := new([32]byte)
	copy(noisePrv[:], noiseKey.Private)
	copy(noisePub[:], noiseKey.Public)

	id := NodeId(blake2b.Sum256([]byte(signPub)))
	node := NodeOur{
		Id:       &id,
		ExchPub:  exchPub,
		ExchPrv:  exchPrv,
		SignPub:  signPub,
		SignPrv:  signPrv,
		NoisePub: noisePub,
		NoisePrv: noisePrv,
	}
	return &node, nil
}

func (nodeOur *NodeOur) Their() *Node {
	return &Node{
		Name:        "self",
		Id:          nodeOur.Id,
		ExchPub:     nodeOur.ExchPub,
		SignPub:     nodeOur.SignPub,
		FreqChunked: MaxFileSize,
		FreqMaxSize: MaxFileSize,
	}
}

func NodeIdFromString(raw string) (*NodeId, error) {
	decoded, err := Base32Codec.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(decoded) != blake2b.Size256 {
		return nil, errors.New("Invalid node id size")
	}
	buf := new([blake2b.Size256]byte)
	copy(buf[:], decoded)
	nodeId := NodeId(*buf)
	return &nodeId, nil
}
