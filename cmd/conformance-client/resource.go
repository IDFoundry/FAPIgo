package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/idfoundry/fapigo/client"
)

// callAccountsEndpoint fetches moduleID's exported "accounts_endpoint"
// value (the same mechanism a human operator reads from the suite's own
// web frontend — this profile's resource endpoint URL isn't part of
// OIDC discovery at all) and, when present, presents tokens' access
// token to it via cl.ProtectedResource(tokens).Do — which picks a DPoP
// proof plus RFC 9449 §9 nonce-challenge retry, or a plain Bearer
// credential under mTLS sender-constraining (RFC 8705 §3.4), entirely
// on its own from cl's own Config.SenderConstrain, the same binding
// this module's token exchange already used.
func callAccountsEndpoint(ctx context.Context, cl *client.Client, rawHTTP *http.Client, apiBase, moduleID string, tokens client.TokenSet) error {
	exposed, err := fetchExposedValues(rawHTTP, apiBase, moduleID)
	if err != nil {
		return fmt.Errorf("fetch exposed values: %w", err)
	}
	accountsEndpoint := exposed["accounts_endpoint"]
	if accountsEndpoint == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, accountsEndpoint, nil)
	if err != nil {
		return fmt.Errorf("build accounts endpoint request: %w", err)
	}
	res, err := cl.ProtectedResource(tokens).Do(ctx, req)
	if err != nil {
		return err
	}
	return res.Body.Close()
}
