// Package sa holds the P4ICS security-association values the controller
// installs: keys (see docs/WIRE_FORMAT.md, "Keys"), key phases and counter
// epochs, and the Diffie-Hellman exchange between two controllers.
package sa

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// Words is the number of 32-bit words of a key (p4ics_keys set_key: bit<256>).
const Words = 8

// epochBase: counters start from the nanoseconds since 2020-01-01.
var epochBase = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// Key is the key of one key phase. The switch uses the words before the
// first zero word (4..8: AES-128 to AES-256 and the HMAC key derived from them).
type Key [Words]uint32

// ValidBits reports whether bits is a key size the switch supports.
func ValidBits(bits int) bool {
	return bits >= 128 && bits <= 256 && bits%32 == 0
}

// NewKey returns a random key of bits bits.
func NewKey(bits int) (Key, error) {
	var buf [4 * Words]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return Key{}, err
	}
	return fromBytes(buf[:], bits)
}

// fromBytes takes the first bits/32 words of b. A zero word would end the
// key early, so it becomes 1 (probability 2^-32 per word).
func fromBytes(b []byte, bits int) (Key, error) {
	if !ValidBits(bits) {
		return Key{}, fmt.Errorf("key size %d: must be 128, 160, 192, 224 or 256", bits)
	}
	var k Key
	for i := 0; i < bits/32; i++ {
		k[i] = binary.BigEndian.Uint32(b[4*i:])
		if k[i] == 0 {
			k[i] = 1
		}
	}
	return k, nil
}

// Bytes is the 32-byte big-endian value of set_key.
func (k Key) Bytes() []byte {
	b := make([]byte, 4*Words)
	for i, w := range k {
		binary.BigEndian.PutUint32(b[4*i:], w)
	}
	return b
}

// Hex is the set_key parameter in simple_switch_CLI syntax.
func (k Key) Hex() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

// Bits is the key size the switch uses.
func (k Key) Bits() int {
	n := 0
	for n < Words && k[n] != 0 {
		n++
	}
	return 32 * n
}

// ID identifies a key in logs and in the API without revealing it.
func (k Key) ID() string {
	h := sha256.Sum256(append([]byte("P4ICS key id "), k.Bytes()...))
	return hex.EncodeToString(h[:6])
}

// Epoch is the counter base of a security association configured at t:
// nanoseconds since 2020-01-01. Counters are epoch + packets sent, so they
// never go back across reconfigurations and restarts.
func Epoch(t time.Time) uint64 {
	return uint64(t.Sub(epochBase).Nanoseconds())
}

// Exchange is one side of an X25519 exchange for one key rotation.
type Exchange struct {
	priv *ecdh.PrivateKey
}

func NewExchange() (*Exchange, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Exchange{priv: priv}, nil
}

// Public is the value sent to the other controller.
func (x *Exchange) Public() []byte {
	return x.priv.PublicKey().Bytes()
}

// Key derives the key of a rotation from the other controller's public
// value. Both sides get the same key: initiator and responder are the
// public values of the controller that started the rotation and of the
// one that answered.
//
//	key = HKDF-SHA256(X25519 secret, salt "P4ICS-ctl-v1",
//	                  info "P4ICS-ctl-v1 key" ‖ rotation ‖ phase ‖ initiator ‖ responder)
func (x *Exchange) Key(peer []byte, rotation uint64, phase uint8, initiator, responder []byte, bits int) (Key, error) {
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return Key{}, fmt.Errorf("peer public value: %w", err)
	}
	secret, err := x.priv.ECDH(pub)
	if err != nil {
		return Key{}, err
	}
	info := []byte("P4ICS-ctl-v1 key")
	info = binary.BigEndian.AppendUint64(info, rotation)
	info = append(info, phase)
	info = append(append(info, initiator...), responder...)
	okm, err := hkdf.Key(sha256.New, secret, []byte("P4ICS-ctl-v1"), string(info), 4*Words)
	if err != nil {
		return Key{}, err
	}
	return fromBytes(okm, bits)
}
