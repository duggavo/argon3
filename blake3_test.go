package argon3

import (
	"encoding/hex"
	"testing"
)

func TestBlake3(t *testing.T) {
	out := make([]byte, 45)

	blake3Hash(out, []byte("test"))

	expected, _ := hex.DecodeString("4878ca0425c739fa427f7eda20fe845f6b2e46ba5fe2a14df5b1e32f50603215c82f77a5bd07f7048a95a699e0")

	if [45]byte(out) != [45]byte(expected) {
		t.Errorf("blake3 hash is invalid, expected %x, got %x", expected, out)
	}
}
