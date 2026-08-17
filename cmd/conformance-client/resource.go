package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/internal/dpop"
)

// callProtectedResource presents accessToken to resourceURL with a DPoP
// proof bound to it (RFC 9449 §7), retrying once with a fresh proof if
// the resource server challenges for a nonce (RFC 9449 §8) — a resource
// server's nonce is a separate value from the authorization server's
// own, even though both use the same challenge/retry shape.
func callProtectedResource(ctx context.Context, httpClient *http.Client, dpopSigner *ecdsa.PrivateKey, alg fapi.SignatureAlgorithm, random io.Reader, now func() time.Time, resourceURL, accessToken string) ([]byte, int, error) {
	body, status, header, err := doProtectedResourceRequest(ctx, httpClient, dpopSigner, alg, random, now, resourceURL, accessToken, "")
	if err != nil {
		return nil, 0, err
	}
	if status == http.StatusUnauthorized {
		if nonce := header.Get("DPoP-Nonce"); nonce != "" {
			body, status, _, err = doProtectedResourceRequest(ctx, httpClient, dpopSigner, alg, random, now, resourceURL, accessToken, nonce)
			if err != nil {
				return nil, 0, err
			}
		}
	}
	return body, status, nil
}

func doProtectedResourceRequest(ctx context.Context, httpClient *http.Client, dpopSigner *ecdsa.PrivateKey, alg fapi.SignatureAlgorithm, random io.Reader, now func() time.Time, resourceURL, accessToken, nonce string) ([]byte, int, http.Header, error) {
	target, err := url.Parse(resourceURL)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("parse resource URL: %w", err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopSigner, Algorithm: alg,
		Method: http.MethodGet, URL: target, AccessToken: accessToken,
		Nonce: nonce, Now: now(), Random: random,
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

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("read response body: %w", err)
	}
	return body, res.StatusCode, res.Header, nil
}
