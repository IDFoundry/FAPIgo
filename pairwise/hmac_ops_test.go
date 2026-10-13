package pairwise_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/idfoundry/fapigo/pairwise"
)

// hsmHMAC stands in for an HSM or KMS MAC key: HMAC-SHA-256 under a key
// the deriver never sees, with an optional fault.
type hsmHMAC struct {
	key  []byte
	err  error
	size int // when non-zero, the length of the MAC it returns
}

func (h hsmHMAC) MAC(_ context.Context, data []byte) ([]byte, error) {
	if h.err != nil {
		return nil, h.err
	}
	m := hmac.New(sha256.New, h.key)
	m.Write(data)
	sum := m.Sum(nil)
	if h.size != 0 {
		sum = append(sum, make([]byte, sha256.Size)...)[:h.size]
	}
	return sum, nil
}

// TestNewHMACWithReproducesTheVectors: over an HSM-held key,
// NewHMACWith derives exactly the published bodies, so it matches
// NewHMAC for the same key.
func TestNewHMACWithReproducesTheVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/hmac_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct{ Key, Issuer, Sector, Subject, Body string }
	}
	if err := json.Unmarshal(raw, &file); err != nil || len(file.Vectors) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	for _, v := range file.Vectors {
		key, err := hex.DecodeString(v.Key)
		if err != nil {
			t.Fatal(err)
		}
		d, err := pairwise.NewHMACWith(hsmHMAC{key: key})
		if err != nil {
			t.Fatal(err)
		}
		in, err := pairwise.NewInput(v.Issuer, v.Sector, v.Subject)
		if err != nil {
			t.Fatal(err)
		}
		if body, err := d.DerivePairwiseSubject(context.Background(), in); err != nil || body != v.Body {
			t.Errorf("(%s, %q, %q, %.20q) = %q, %v; want %q", v.Key[:8], v.Issuer, v.Sector, v.Subject, body, err, v.Body)
		}
	}
}

func TestHMACWithDeriverContract(t *testing.T) {
	pairwise.TestDeriverContract(t, func(t *testing.T) pairwise.Deriver {
		d, err := pairwise.NewHMACWith(hsmHMAC{key: testKey})
		if err != nil {
			t.Fatal(err)
		}
		return d
	})
}

// TestNewHMACWithFailsClosed: a failing key operation, or a MAC of the
// wrong length, fails the derivation instead of producing a body.
func TestNewHMACWithFailsClosed(t *testing.T) {
	if _, err := pairwise.NewHMACWith(nil); err == nil {
		t.Error("NewHMACWith(nil) succeeded")
	}
	in, err := pairwise.NewInput("https://op.example", "rp.example", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	for name, ops := range map[string]hsmHMAC{
		"error":     {key: testKey, err: errors.New("kms down")},
		"too long":  {key: testKey, size: 33},
		"too short": {key: testKey, size: 31},
	} {
		t.Run(name, func(t *testing.T) {
			d, err := pairwise.NewHMACWith(ops)
			if err != nil {
				t.Fatal(err)
			}
			if body, err := d.DerivePairwiseSubject(context.Background(), in); err == nil {
				t.Errorf("DerivePairwiseSubject = %q, want an error", body)
			}
		})
	}
}
