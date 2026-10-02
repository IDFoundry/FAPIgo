package extension

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// AuthorizationDetailsClaim is the access token claim, and token
// introspection member, that carries the authorization details a token
// was granted (RFC 9396 §9.1, §9.2).
const AuthorizationDetailsClaim = "authorization_details"

// ParseGrantedRAR reads the authorization details an access token was
// granted — its AuthorizationDetailsClaim, as a resource server finds it
// in resource.AuthorizationContext.Claims — for reading each type with
// RARGet:
//
//	granted, err := extension.ParseGrantedRAR(authz.Claims[extension.AuthorizationDetailsClaim])
//	payments, err := extension.RARGet(granted, paymentInitiation)
//
// A token without the claim was granted none: the result is empty. A
// claim that isn't an array of objects each with a string "type" is an
// error, never an empty grant read as "nothing to check". Every object
// in it, at any depth, is checked as RARRegistry.Parse checks a
// request's: no member twice, compared as encoding/json compares names,
// and "type" spelled exactly. RARGet then refuses a member spelled other
// than its field's json tag. So the claim reads as any case-sensitive
// reader of the same token would read it. It doesn't otherwise validate
// the details: the
// authorization server did that when it granted them, and RARGet decodes
// only the types asked for, so a type this resource server doesn't know
// is left alone.
func ParseGrantedRAR(claim json.RawMessage) (RARValues, error) {
	if len(bytes.TrimSpace(claim)) == 0 || bytes.Equal(bytes.TrimSpace(claim), []byte("null")) {
		return RARValues{}, nil
	}
	var objects []json.RawMessage
	if err := json.Unmarshal(claim, &objects); err != nil {
		return RARValues{}, fmt.Errorf("extension: granted authorization_details is not an array: %w", err)
	}
	byType := make(map[string][]json.RawMessage, len(objects))
	for i, obj := range objects {
		if err := checkMembers(obj); err != nil {
			return RARValues{}, fmt.Errorf("extension: granted authorization_details object %d: %w", i, err)
		}
		var head rarObjectHead
		if err := json.Unmarshal(obj, &head); err != nil || head.Type == "" {
			return RARValues{}, fmt.Errorf("extension: granted authorization_details object %d has no type", i)
		}
		byType[head.Type] = append(byType[head.Type], obj)
	}
	if len(byType) == 0 {
		return RARValues{}, nil
	}
	return RARValues{byType: byType}, nil
}
