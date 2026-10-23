package sa

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNewKey(t *testing.T) {
	for _, bits := range []int{128, 160, 192, 224, 256} {
		k, err := NewKey(bits)
		if err != nil {
			t.Fatal(err)
		}
		if k.Bits() != bits {
			t.Fatalf("%d-bit key uses %d bits: %v", bits, k.Bits(), k)
		}
		if len(k.Hex()) != 2+64 || !strings.HasPrefix(k.Hex(), "0x") {
			t.Fatalf("hex %s", k.Hex())
		}
	}
	a, _ := NewKey(256)
	b, _ := NewKey(256)
	if a == b || a.ID() == b.ID() {
		t.Fatal("two random keys are equal")
	}
	for _, bits := range []int{0, 96, 100, 288} {
		if _, err := NewKey(bits); err == nil {
			t.Fatalf("accepted %d bits", bits)
		}
	}
}

func TestZeroWords(t *testing.T) {
	b := make([]byte, 32)
	b[3] = 5
	k, err := fromBytes(b, 192)
	if err != nil {
		t.Fatal(err)
	}
	if k != (Key{5, 1, 1, 1, 1, 1, 0, 0}) {
		t.Fatalf("key %v", k)
	}
}

func TestBytes(t *testing.T) {
	k := Key{0x01020304, 0x05060708, 9, 10, 0, 0, 0, 0}
	if !bytes.Equal(k.Bytes()[:9], []byte{1, 2, 3, 4, 5, 6, 7, 8, 0}) || len(k.Bytes()) != 32 {
		t.Fatalf("bytes %x", k.Bytes())
	}
	if k.Hex() != "0x0102030405060708000000090000000a"+strings.Repeat("0", 32) {
		t.Fatalf("hex %s", k.Hex())
	}
}

func TestEpoch(t *testing.T) {
	if Epoch(time.Date(2020, 1, 1, 0, 0, 1, 0, time.UTC)) != 1e9 {
		t.Fatal("epoch base")
	}
	if e := Epoch(time.Now()); e < 2e17 || e >= 1<<63 {
		t.Fatalf("epoch %d", e)
	}
}

func TestExchange(t *testing.T) {
	a, _ := NewExchange()
	b, _ := NewExchange()
	ka, err := a.Key(b.Public(), 7, 1, a.Public(), b.Public(), 256)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := b.Key(a.Public(), 7, 1, a.Public(), b.Public(), 256)
	if err != nil {
		t.Fatal(err)
	}
	if ka != kb || ka.Bits() != 256 {
		t.Fatalf("keys differ: %v %v", ka, kb)
	}
	// bound to the rotation, the phase and the key size
	if k, _ := a.Key(b.Public(), 8, 1, a.Public(), b.Public(), 256); k == ka {
		t.Fatal("same key for another rotation")
	}
	if k, _ := a.Key(b.Public(), 7, 0, a.Public(), b.Public(), 256); k == ka {
		t.Fatal("same key for another phase")
	}
	if k, _ := a.Key(b.Public(), 7, 1, a.Public(), b.Public(), 128); k.Bits() != 128 {
		t.Fatalf("128-bit key: %v", k)
	}
	if _, err := a.Key([]byte{1, 2, 3}, 7, 1, nil, nil, 256); err == nil {
		t.Fatal("accepted a bad public value")
	}
}
