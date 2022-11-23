package nncp

import (
	"strings"
	"testing"
)

func TestNiceSymmetric(t *testing.T) {
	var nice uint8
	for nice = 1; nice > 0; nice++ {
		s := NicenessFmt(nice)
		parsed, err := NicenessParse(s)
		if err != nil || parsed != nice {
			t.Error(err)
		}
		parsed, err = NicenessParse(strings.ToLower(s))
		if err != nil || parsed != nice {
			t.Error(err)
		}
	}
}
