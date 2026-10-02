package checkout

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// bankClient is one app's connection to Alder Bank: a FAPIgo client
// built from the bank's published metadata the first time it's needed
// (the bank isn't listening yet when the demo starts).
type bankClient struct {
	w        *World
	host     string
	clientID fapi.ClientID
	keys     clientKeys
	mode     storage.BackchannelTokenDeliveryMode

	mu     sync.Mutex
	client *client.Client
}

func (b *bankClient) get(ctx context.Context) (*client.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.client != nil {
		return b.client, nil
	}
	fetcher, err := b.w.fetcher(b.host)
	if err != nil {
		return nil, err
	}
	issuer, err := fapi.ParseIssuerURL(b.w.URL(bankHost, ""))
	if err != nil {
		return nil, err
	}
	discovered, err := client.Discover(ctx, fetcher, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover Alder Bank: %w", err)
	}
	issuerKeys, err := discovered.IssuerKeySource(fetcher, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	limits := client.RecommendedLimits()
	limits.BackchannelAuthenticationRequestLifetime = time.Minute
	// An ID token comes with the tokens; Alder Bank's live for 10
	// minutes (server.RecommendedLimits).
	limits.MaxIDTokenLifetime = 10 * time.Minute
	c, err := client.NewFromDiscovery(discovered, client.Config{
		// No RedirectURI: a CIBA client is never redirected, so
		// NewFromDiscovery leaves out the authorization endpoints.
		Issuer: issuer, ClientID: b.clientID,
		Profile:   client.ProfileFAPISecurity,
		Assurance: client.AssuranceDevelopment,
		Algorithms: client.Algorithms{
			ClientAuthentication: fapi.ES256, DPoP: fapi.ES256, IDToken: fapi.ES256,
			BackchannelAuthenticationRequest: fapi.ES256,
		},
		Limits:                       limits,
		SenderConstrain:              storage.SenderConstrainDPoP,
		ClientAuthMethod:             storage.ClientAuthMethodPrivateKeyJWT,
		BackchannelTokenDeliveryMode: b.mode,
	}, client.Dependencies{
		Sessions:   memstore.NewSessionStore(),
		Keys:       b.keys.manager,
		IssuerKeys: issuerKeys,
		HTTP:       b.w.net.Client(b.host),
		Clock:      client.SystemClock{},
		Random:     rand.Reader,
	})
	if err != nil {
		return nil, err
	}
	b.client = c
	return c, nil
}

// apiResponse is what one call to Alder Bank's API returned.
type apiResponse struct {
	Status int
	Body   string
}

func (r apiResponse) OK() bool { return r.Status/100 == 2 }

// callAPI makes a DPoP-bound request to Alder Bank's API with tokens.
func (b *bankClient) callAPI(ctx context.Context, tokens client.TokenSet, method, path string, body any) (apiResponse, error) {
	c, err := b.get(ctx)
	if err != nil {
		return apiResponse{}, err
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return apiResponse{}, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.w.URL(apiHost, path), reader)
	if err != nil {
		return apiResponse{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.ProtectedResource(tokens).Do(ctx, req)
	if err != nil {
		return apiResponse{}, err
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	return apiResponse{Status: res.StatusCode, Body: prettyJSON(raw)}, nil
}

// describeError is err as a page shows it: the bank's OAuth error, when
// there is one.
func describeError(err error) string {
	var ce *client.Error
	if errors.As(err, &ce) {
		if resp, ok := ce.ServerResponse(); ok {
			return fmt.Sprintf("%s: %s", resp.Code, resp.Description)
		}
	}
	return err.Error()
}

func prettyJSON(raw []byte) string {
	var buf bytes.Buffer
	if json.Indent(&buf, raw, "", "  ") != nil {
		return string(raw)
	}
	return buf.String()
}
