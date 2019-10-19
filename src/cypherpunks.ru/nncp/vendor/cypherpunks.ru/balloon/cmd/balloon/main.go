package main

import (
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"

	"cypherpunks.ru/balloon"
)

var (
	s       = flag.Int("s", 1<<18, "Space cost, number of hash-sized blocks")
	t       = flag.Int("t", 2, "Time cost, rounds")
	p       = flag.Int("p", 4, "Number of threads")
	saltHex = flag.String("salt", "deadbabe", "Salt, hexadecimal")
	passwd  = flag.String("passwd", "", "Password")
)

func main() {
	flag.Parse()
	salt, err := hex.DecodeString(*saltHex)
	if err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(balloon.H(sha512.New, []byte(*passwd), salt, *s, *t, *p)))
}
