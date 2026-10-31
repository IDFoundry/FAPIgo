package client

import (
	"bytes"
	"context"
	"encoding/json"
	"mime"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzDecodeUserInfoResponse checks how FetchUserInfo reads a UserInfo
// response (OIDC Core §5.3.2), whose Content-Type and body the
// endpoint chooses, short of verifying a signature (which
// FuzzParseCompact and the JWS targets cover). Beyond never panicking:
//
//   - a refusal is always an ErrorInvalidResponse *Error;
//   - a plain JSON response is refused whenever the client requires a
//     signed or an encrypted one, and a JWT of the wrong shape for what
//     it requires is refused before any key is used (no downgrade);
//   - an accepted plain response is exactly a JSON object (or null);
//   - checkUserInfoSubject accepts it only when its sub is the ID
//     token's, and then keeps every other claim, never a second sub.
func FuzzDecodeUserInfoResponse(f *testing.F) {
	f.Add(uint8(0), "application/json", []byte(`{"sub":"end-user-1","name":"A"}`), "end-user-1")
	f.Add(uint8(0), "Application/JSON; charset=utf-8", []byte(`{"sub":"x","sub":"end-user-1"}`), "end-user-1")
	f.Add(uint8(1), "application/json", []byte(`{"sub":"end-user-1"}`), "end-user-1")
	f.Add(uint8(2), "application/jwt", []byte(`a.b.c`), "end-user-1")
	f.Add(uint8(0), "application/jwt", []byte(`a.b.c.d.e`), "end-user-1")
	f.Add(uint8(0), "text/plain", []byte(`{"sub":"end-user-1"}`), "end-user-1")
	f.Add(uint8(0), "application/json", []byte(`null`), "")
	f.Add(uint8(0), "application/json", []byte(`{"sub":7}`), "7")
	f.Fuzz(func(t *testing.T, mode uint8, contentType string, body []byte, subject string) {
		c := userInfoFuzzClient(mode)
		mediaType, _, mtErr := mime.ParseMediaType(contentType)
		if mtErr == nil && strings.EqualFold(mediaType, "application/jwt") && reachesUserInfoKeys(c, body) {
			return // verifying or decrypting needs the issuer's keys.
		}
		claims, decErr := c.decodeUserInfoResponse(context.Background(), contentType, body)
		if decErr != nil {
			if decErr.Code() != ErrorInvalidResponse {
				t.Fatalf("decodeUserInfoResponse refused with %v, want ErrorInvalidResponse", decErr)
			}
			return
		}
		if mtErr != nil || !strings.EqualFold(mediaType, "application/json") || mode%3 != 0 {
			t.Fatalf("mode %d accepted a %q response", mode%3, contentType)
		}
		if !isJSONObjectOrNull(body) {
			t.Fatalf("accepted %q, which isn't a JSON object", body)
		}
		checkUserInfoSubjectProperties(t, c, claims, subject)
	})
}

// userInfoFuzzClient is a client accepting any UserInfo response (mode
// 0), only a signed one (1), or only an encrypted one (2).
func userInfoFuzzClient(mode uint8) *Client {
	c := &Client{}
	switch mode % 3 {
	case 1:
		c.cfg.RequireSignedUserInfo = true
	case 2:
		c.cfg.Algorithms.UserInfoKeyManagement = fapi.ECDHESA256KW
		c.cfg.Algorithms.UserInfoContentEncryption = fapi.A256GCM
	}
	return c
}

// reachesUserInfoKeys reports whether an application/jwt body has the
// shape c would go on to verify or decrypt: a JWS when c expects no
// encryption, a JWE when it does.
func reachesUserInfoKeys(c *Client, body []byte) bool {
	segments := bytes.Count(body, []byte(".")) + 1
	encrypted := c.cfg.Algorithms.UserInfoKeyManagement != 0
	return (segments == 3 && !encrypted) || (segments == 5 && encrypted)
}

// isJSONObjectOrNull reports whether body is one JSON value that is an
// object or null.
func isJSONObjectOrNull(body []byte) bool {
	if !json.Valid(body) {
		return false
	}
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	return bytes.HasPrefix(trimmed, []byte("{")) || bytes.HasPrefix(trimmed, []byte("null"))
}

// checkUserInfoSubjectProperties checks checkUserInfoSubject accepts
// claims for subject only when their sub is subject, and then returns
// the claims less sub.
func checkUserInfoSubjectProperties(t *testing.T, c *Client, claims map[string]json.RawMessage, subject string) {
	t.Helper()
	info, err := c.checkUserInfoSubject(claims, TokenSet{HasIDToken: true, Subject: subject, IDTokenClaims: IDTokenClaims{Subject: subject}})
	var sub string
	subMatches := claims["sub"] != nil && json.Unmarshal(claims["sub"], &sub) == nil && sub == subject
	if (err == nil) != subMatches {
		t.Fatalf("checkUserInfoSubject(sub %s, ID token sub %q) = %v", claims["sub"], subject, err)
	}
	if err != nil {
		return
	}
	if _, ok := info.Parameters["sub"]; ok || info.Subject != subject || len(info.Parameters) != len(claims)-1 {
		t.Fatalf("checkUserInfoSubject kept %d of %d claims, subject %q (want %q)", len(info.Parameters), len(claims), info.Subject, subject)
	}
	if m := info.AsMap(); m["sub"] != subject || len(m) != len(claims) {
		t.Fatalf("AsMap() = %v, want the response's claims with sub %q", m, subject)
	}
}
