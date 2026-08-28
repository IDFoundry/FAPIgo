package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
)

// dpopResourceClient bundles the fixed DPoP-signing configuration a
// protected-resource call needs — everything but the request's own
// target and access token — so callProtectedResource's and
// doProtectedResourceRequest's own parameter lists aren't several
// same-shaped values passed positionally (go:S107).
type dpopResourceClient struct {
	HTTP   *http.Client
	Signer *ecdsa.PrivateKey
	Alg    fapi.SignatureAlgorithm
	Random io.Reader
	Now    func() time.Time
}

// callProtectedResource presents accessToken to resourceURL with a DPoP
// proof bound to it (RFC 9449 §7), retrying once with a fresh proof if
// the resource server challenges for a nonce (RFC 9449 §8) — a resource
// server's nonce is a separate value from the authorization server's
// own, even though both use the same challenge/retry shape.
func (c dpopResourceClient) callProtectedResource(ctx context.Context, resourceURL, accessToken string) ([]byte, int, error) {
	body, status, header, err := c.doProtectedResourceRequest(ctx, resourceURL, accessToken, "")
	if err != nil {
		return nil, 0, err
	}
	if status == http.StatusUnauthorized {
		if nonce := header.Get("DPoP-Nonce"); nonce != "" {
			body, status, _, err = c.doProtectedResourceRequest(ctx, resourceURL, accessToken, nonce)
			if err != nil {
				return nil, 0, err
			}
		}
	}
	return body, status, nil
}

// callProtectedResourceBearer presents accessToken to resourceURL as a
// plain Bearer credential (RFC 8705 §3.4: an mTLS-bound token needs no
// proof-of-possession header of its own — the connection's own client
// certificate, already configured on httpClient's transport, is the
// sender-constraint) — the mTLS counterpart to
// dpopResourceClient.callProtectedResource.
func callProtectedResourceBearer(ctx context.Context, httpClient *http.Client, resourceURL, accessToken string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read response body: %w", err)
	}
	return body, res.StatusCode, nil
}

func (c dpopResourceClient) doProtectedResourceRequest(ctx context.Context, resourceURL, accessToken, nonce string) ([]byte, int, http.Header, error) {
	target, err := url.Parse(resourceURL)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("parse resource URL: %w", err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: c.Signer, Algorithm: c.Alg,
		Method: http.MethodGet, URL: target, AccessToken: accessToken,
		Nonce: nonce, Now: c.Now(), Random: c.Random,
	})
	if err != nil {
		return nil, 0, nil, fmt.Errorf("build DPoP proof: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURL, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", proof)

	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("read response body: %w", err)
	}
	return body, res.StatusCode, res.Header, nil
}
