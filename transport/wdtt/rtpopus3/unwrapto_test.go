package rtpopus3

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func newKey3(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// TestUnwrapToRoundTripAndNoMutation locks the local UnwrapTo addition and the
// IsRTPOpus3 detector (ext length = 3 words) for the rtpopus3 profile.
func TestUnwrapToRoundTripAndNoMutation(t *testing.T) {
	t.Parallel()
	key := newKey3(t)
	cli, _ := NewConn(key, false)
	srv, _ := NewConn(key, true)

	payload := []byte("rtpopus3 no-mutation round-trip payload")
	wire := make([]byte, MaxWire(len(payload)))
	n, err := cli.WrapInto(wire, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !IsRTPOpus3(wire[:n]) {
		t.Fatal("IsRTPOpus3 did not recognise a freshly wrapped packet")
	}
	wireCopy := append([]byte(nil), wire[:n]...)

	dst := make([]byte, len(payload))
	m, err := srv.UnwrapTo(wire[:n], dst)
	if err != nil {
		t.Fatalf("UnwrapTo: %v", err)
	}
	if !bytes.Equal(dst[:m], payload) {
		t.Fatalf("plaintext mismatch: %q", dst[:m])
	}
	if !bytes.Equal(wire[:n], wireCopy) {
		t.Fatal("UnwrapTo mutated the wire buffer")
	}

	other, _ := NewConn(newKey3(t), true)
	if _, err := other.UnwrapTo(wire[:n], dst); err == nil {
		t.Fatal("expected failure with wrong key")
	}
	if !bytes.Equal(wire[:n], wireCopy) {
		t.Fatal("failed UnwrapTo mutated the wire buffer")
	}
}
