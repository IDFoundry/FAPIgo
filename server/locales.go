package server

import (
	"encoding/json"
	"strings"
)

// Display is the client's "display" (OIDC Core §3.1.2.1): how it would
// like the authentication and consent pages shown. It is a preference,
// not a requirement: render whatever suits the user agent.
type Display string

// The display values OIDC Core §3.1.2.1 defines. A request naming any
// other value arrives as no Display at all: OIDC Core §15.1 requires
// only that the parameter never cause an error.
const (
	DisplayPage  Display = "page"  // a full user-agent page (the default)
	DisplayPopup Display = "popup" // a popup user-agent window
	DisplayTouch Display = "touch" // a touch-interface device
	DisplayWAP   Display = "wap"   // a "feature phone" display
)

// Bounds on ui_locales and claims_locales, so a long list costs
// nothing: more tags than any user agent sends, each as long as
// RFC 5646 §4.4.1 says a tag needs to be supported.
const (
	maxLocaleTags      = 16
	maxLocaleTagLength = 35
)

// requestedDisplay returns the request's "display", or "" when it sent
// none or a value OIDC Core doesn't define.
func requestedDisplay(params map[string]json.RawMessage) Display {
	raw, ok := params["display"]
	if !ok {
		return ""
	}
	v, err := jsonStringValue(raw)
	if err != nil {
		return ""
	}
	switch d := Display(v); d {
	case DisplayPage, DisplayPopup, DisplayTouch, DisplayWAP:
		return d
	}
	return ""
}

// requestedLocales returns the language tags in the request's name
// parameter ("ui_locales" or "claims_locales", OIDC Core §3.1.2.1 and
// §5.2): a space-separated list, most preferred first. They are
// preferences, so a malformed list never fails the request: a tag that
// isn't BCP 47 shaped is dropped, as are repeats and anything past
// maxLocaleTags. Nil when none is left.
func requestedLocales(params map[string]json.RawMessage, name string) []string {
	raw, ok := params[name]
	if !ok {
		return nil
	}
	v, err := jsonStringValue(raw)
	if err != nil {
		return nil
	}
	var tags []string
	for field := range strings.FieldsSeq(v) {
		if len(tags) == maxLocaleTags {
			break
		}
		if !isLanguageTagShaped(field) || containsFold(tags, field) {
			continue
		}
		tags = append(tags, field)
	}
	return tags
}

// isLanguageTagShaped reports whether tag has the shape of an RFC 5646
// language tag: alphanumeric subtags of 1 to 8 characters joined by
// hyphens, the first alphabetic, at most maxLocaleTagLength in all. It
// doesn't check the registry: the application matches tags against the
// languages it has.
func isLanguageTagShaped(tag string) bool {
	if tag == "" || len(tag) > maxLocaleTagLength {
		return false
	}
	for i, subtag := range strings.Split(tag, "-") {
		if subtag == "" || len(subtag) > 8 {
			return false
		}
		for j := range len(subtag) {
			c := subtag[j]
			alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
			if !alpha && (i == 0 || c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

// containsFold reports whether tags holds tag, ignoring case: language
// tags are case-insensitive (RFC 5646 §2.1.1).
func containsFold(tags []string, tag string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}
