package client

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/idfoundry/fapigo/internal/resourceindicator"
)

// resourceParameter is RFC 8707's "resource" parameter: the resource
// server, or servers, an access token is requested for.
const resourceParameter = "resource"

// resourceSeparator joins a request's resources into the one string
// this package's single-valued parameter maps hold under
// resourceParameter, for encodeForm and resourceObjectParameter to split
// again. checkResources refuses a resource containing it.
const resourceSeparator = "\n"

// checkResources refuses resources the server would: more than
// resourceindicator.MaxPerRequest of them, an empty or repeated one, or
// one resourceindicator.Check refuses, which the server applies too: an
// absolute URI (RFC 8707 §2) without a fragment, valid UTF-8, at most
// resourceindicator.MaxLength bytes, and without whitespace or control
// characters (resourceSeparator among them). Invalid UTF-8 in particular
// wouldn't survive the request object's JSON, which replaces it with
// U+FFFD, so the server would read a different resource.
func checkResources(resources []string) *Error {
	if len(resources) > resourceindicator.MaxPerRequest {
		return newError(ErrorInvalidRequest, fmt.Sprintf("at most %d resource indicators may be sent", resourceindicator.MaxPerRequest), nil)
	}
	for i, r := range resources {
		if r == "" {
			return newError(ErrorInvalidRequest, "a resource indicator is empty", nil)
		}
		if err := resourceindicator.Check(r); err != nil {
			return newError(ErrorInvalidRequest, "a resource indicator isn't one RFC 8707 §2 allows", err)
		}
		if slices.Contains(resources[:i], r) {
			return newError(ErrorInvalidRequest, "a resource indicator is repeated", nil)
		}
	}
	return nil
}

// checkResourceSubset refuses narrowed unless every one of its
// resources is among granted: a refresh can ask for an access token for
// fewer resources than the grant's, never for others (RFC 8707 §2.2).
func checkResourceSubset(narrowed, granted []string) *Error {
	if checkErr := checkResources(narrowed); checkErr != nil {
		return checkErr
	}
	for _, r := range narrowed {
		if !slices.Contains(granted, r) {
			return newError(ErrorInvalidRequest, "a resource indicator isn't one the token set was obtained for (TokenSet.Resource)", nil)
		}
	}
	return nil
}

// setResources records resources in params under resourceParameter,
// when there are any. Callers have already checked them.
func setResources(params map[string]string, resources []string) {
	if len(resources) > 0 {
		params[resourceParameter] = strings.Join(resources, resourceSeparator)
	}
}

// encodeForm encodes form as an application/x-www-form-urlencoded
// body, sending each resource setResources recorded as its own
// "resource" parameter (RFC 8707 §2).
func encodeForm(form map[string]string) []byte {
	values := make(url.Values, len(form))
	for k, v := range form {
		if k == resourceParameter {
			for _, r := range strings.Split(v, resourceSeparator) {
				values.Add(k, r)
			}
			continue
		}
		values.Set(k, v)
	}
	return []byte(values.Encode())
}

// resourceObjectParameter is a request object's "resource" member for
// the resources setResources recorded as joined: a string for one, an
// array of strings for several.
func resourceObjectParameter(joined string) json.RawMessage {
	resources := strings.Split(joined, resourceSeparator)
	var encoded []byte
	if len(resources) == 1 {
		encoded, _ = json.Marshal(resources[0]) // marshaling a string cannot fail
	} else {
		encoded, _ = json.Marshal(resources) // nor a []string
	}
	return encoded
}

// addResourceObjectParameter sets a request object's "resource" member
// for resources (see resourceObjectParameter), when there are any.
func addResourceObjectParameter(objectParams map[string]json.RawMessage, resources []string) {
	if len(resources) > 0 {
		objectParams[resourceParameter] = resourceObjectParameter(strings.Join(resources, resourceSeparator))
	}
}
