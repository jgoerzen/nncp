package nncp

import (
	"encoding/base32"
	"strings"
)

func ToBase32(data []byte) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(data), "=")
}

func FromBase32(data string) ([]byte, error) {
	padSize := len(data) % 8
	if padSize != 0 {
		padSize = 8 - padSize
		pad := make([]byte, 0, padSize)
		for i := 0; i < padSize; i++ {
			pad = append(pad, '=')
		}
		data += string(pad)
	}
	return base32.StdEncoding.DecodeString(data)
}
