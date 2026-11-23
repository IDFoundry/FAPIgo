package jwe

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/strictjson"
)

// ecdhHeaderPrefix opens an ECDH-ES+A256KW, A256GCM protected header.
const ecdhHeaderPrefix = `{"alg":"ECDH-ES+A256KW","enc":"A256GCM",`

// sealWithHeader is a JWE to recipient whose protected header is what
// header builds from its ephemeral key's base64url coordinates, for a
// header Encrypt wouldn't write. Its AAD is that header as written, so
// Decrypt opens it unless it refuses the header.
func sealWithHeader(t *testing.T, recipient *ecdh.PublicKey, header func(x, y string) string) string {
	t.Helper()
	cek, iv := make([]byte, 32), make([]byte, 12)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	encryptedKey, epk, err := wrapCEKECDHESA256KW(Header{Algorithm: fapi.ECDHESA256KW}, recipient, cek, rand.Reader)
	if err != nil {
		t.Fatalf("wrap cek: %v", err)
	}
	coordinates := marshalEPK(epk)
	protected := base64.RawURLEncoding.EncodeToString([]byte(header(coordinates.X, coordinates.Y)))
	ciphertext, tag, err := seal(cek, iv, []byte("plaintext"), []byte(protected))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return strings.Join([]string{protected, enc(encryptedKey), enc(iv), enc(ciphertext), enc(tag)}, ".")
}

// epkMember is an "epk" member holding members after kty and crv.
func epkMember(members string) string {
	return `"epk":{"kty":"EC","crv":"P-256",` + members + `}`
}

// TestParseHeaderRefusesDuplicateMembers covers RFC 7516 §4: Header
// Parameter names are unique. encoding/json merged two copies of epk
// into one key, completing the first, assembling one from halves, or
// keeping case variants the case check never saw, since it read only
// the empty last copy; a reader keeping one copy reads another key or
// none. Any repeated name, or two differing only in case, is refused.
func TestParseHeaderRefusesDuplicateMembers(t *testing.T) {
	pub := generateECDHKey(t).PublicKey()
	xy := marshalEPK(pub)
	x, y := fmt.Sprintf(`"x":%q`, xy.X), fmt.Sprintf(`"y":%q`, xy.Y)
	for name, header := range map[string]string{
		"epk then kty alone":              ecdhHeaderPrefix + epkMember(x+","+y) + `,"epk":{"kty":"EC"}}`,
		"epk split across copies":         ecdhHeaderPrefix + epkMember(x) + `,"epk":{` + y + `}}`,
		"case variants then empty":        ecdhHeaderPrefix + epkMember(strings.ToUpper(x[:2])+x[2:]+","+strings.ToUpper(y[:2])+y[2:]) + `,"epk":{}}`,
		"member repeated inside epk":      ecdhHeaderPrefix + epkMember(x+","+y+","+x) + `}`,
		"alg twice":                       `{"alg":"RSA-OAEP-256","alg":"RSA-OAEP-256","enc":"A256GCM"}`,
		"enc twice":                       `{"alg":"RSA-OAEP-256","enc":"A256GCM","enc":"A256GCM"}`,
		"case variant before enc":         `{"alg":"RSA-OAEP-256","ENC":"A128GCM","enc":"A256GCM"}`,
		"private names differing in case": `{"alg":"RSA-OAEP-256","enc":"A256GCM","ext":1,"EXT":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseHeader([]byte(header)); !errors.Is(err, strictjson.ErrDuplicateMember) {
				t.Fatalf("parseHeader(%s) = %v, want ErrDuplicateMember", header, err)
			}
		})
	}
	if _, err := parseHeader([]byte(ecdhHeaderPrefix + epkMember(x+","+y) + `}`)); err != nil {
		t.Fatalf("parseHeader(one epk) = %v", err)
	}
}

// TestDecryptRefusesDuplicateEPK: a JWE whose protected header repeats
// epk is refused before any key agreement, though the header, as the
// AAD, authenticates. Before, both opened, with the merged key.
func TestDecryptRefusesDuplicateEPK(t *testing.T) {
	priv := generateECDHKey(t)
	decrypt := func(compact string) error {
		_, err := Decrypt(context.Background(), DecryptRequest{
			Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: priv, Compact: compact,
		})
		return err
	}
	once := sealWithHeader(t, priv.PublicKey(), func(x, y string) string {
		return ecdhHeaderPrefix + epkMember(fmt.Sprintf(`"x":%q,"y":%q`, x, y)) + `}`
	})
	if err := decrypt(once); err != nil {
		t.Fatalf("Decrypt(one epk) = %v, want nil", err)
	}
	for name, header := range map[string]func(x, y string) string{
		"epk then kty alone": func(x, y string) string {
			return ecdhHeaderPrefix + epkMember(fmt.Sprintf(`"x":%q,"y":%q`, x, y)) + `,"epk":{"kty":"EC"}}`
		},
		"case variants then empty": func(x, y string) string {
			return ecdhHeaderPrefix + epkMember(fmt.Sprintf(`"X":%q,"Y":%q`, x, y)) + `,"epk":{}}`
		},
	} {
		err := decrypt(sealWithHeader(t, priv.PublicKey(), header))
		if !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "duplicate member") {
			t.Errorf("%s: Decrypt = %v, want ErrMalformed for a duplicate member", name, err)
		}
	}
}
