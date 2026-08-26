package rtpopus2

import (
	"bytes"
	"testing"
)

// TestUnwrapToRoundTripAndNoMutation locks the local UnwrapTo addition: it
// decrypts into a separate dst and must leave the wire buffer untouched (so the
// server can retry other keys / re-key on failure without corrupting the packet).
func TestUnwrapToRoundTripAndNoMutation(t *testing.T) {
	t.Parallel()
	key := newKey(t)
	cli, _ := NewConn(key, false)
	srv, _ := NewConn(key, true)

	payload := []byte("no-mutation round-trip payload")
	wire := make([]byte, MaxWire(len(payload)))
	n, err := cli.WrapInto(wire, payload)
	if err != nil {
		t.Fatal(err)
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

	// Wrong key must fail without mutating wire either.
	other, _ := NewConn(newKey(t), true)
	if _, err := other.UnwrapTo(wire[:n], dst); err == nil {
		t.Fatal("expected failure with wrong key")
	}
	if !bytes.Equal(wire[:n], wireCopy) {
		t.Fatal("failed UnwrapTo mutated the wire buffer")
	}
}
