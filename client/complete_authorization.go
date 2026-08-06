package client

import "context"

// CompletionResult is a closed sum type returned by CompleteAuthorization.
type CompletionResult interface {
	completionResult()
}

// CompletionSuccess means the flow completed and Tokens were issued.
type CompletionSuccess struct {
	Tokens TokenSet
}

func (CompletionSuccess) completionResult() {}

// CompletionDenied means the authorization server (or the resource
// owner, via the authorization server) declined the request.
type CompletionDenied struct {
	Code        string
	Description string
}

func (CompletionDenied) completionResult() {}

// CompleteAuthorization validates cb via HandleAuthorizationResponse and,
// on success, immediately exchanges the resulting code via ExchangeCode
// — so a caller cannot skip callback validation before exchanging a
// code (see ARCHITECTURE.md design rule 3).
func (c *Client) CompleteAuthorization(ctx context.Context, cb AuthorizationCallback) (CompletionResult, error) {
	result, err := c.HandleAuthorizationResponse(ctx, cb)
	if err != nil {
		return nil, err
	}
	switch r := result.(type) {
	case CallbackDenied:
		return CompletionDenied{Code: r.Code, Description: r.Description}, nil
	case CallbackSuccess:
		tokens, err := c.ExchangeCode(ctx, r.Response)
		if err != nil {
			return nil, err
		}
		return CompletionSuccess{Tokens: tokens}, nil
	default:
		return nil, newError(ErrorInternal, "unrecognized callback result", nil)
	}
}
