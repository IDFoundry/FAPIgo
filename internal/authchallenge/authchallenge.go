// Package authchallenge parses WWW-Authenticate header values (RFC 9110
// §11.6.1) into their challenges, so a client can read a protected
// resource's error parameters (RFC 6750 §3, RFC 9449 §7.1) from the
// challenge for the scheme it actually used, rather than
// substring-matching a header that may carry several.
package authchallenge

import (
	"errors"
	"strings"
)

// ErrMalformed is returned for a header value that doesn't follow the
// RFC 9110 §11 challenge grammar.
var ErrMalformed = errors.New("authchallenge: malformed WWW-Authenticate value")

// maxValueBytes bounds how much header text Parse will look at.
const maxValueBytes = 8 << 10

// Challenge is one parsed challenge. Scheme and parameter names are
// lower-cased, since both are case-insensitive (RFC 9110 §11.1, §11.2);
// parameter values are unquoted and otherwise exactly as sent.
type Challenge struct {
	Scheme  string
	Token68 string // set instead of Params when the challenge carries a token68
	Params  map[string]string
}

// Find returns the first challenge in values (the header's field
// values, e.g. http.Header.Values("WWW-Authenticate")) whose scheme
// matches scheme case-insensitively.
func Find(values []string, scheme string) (Challenge, bool, error) {
	challenges, err := Parse(values)
	if err != nil {
		return Challenge{}, false, err
	}
	for _, c := range challenges {
		if c.Scheme == strings.ToLower(scheme) {
			return c, true, nil
		}
	}
	return Challenge{}, false, nil
}

// Parse parses every challenge in values. A parameter repeated within
// one challenge is malformed (RFC 9110 §11.2: "each parameter name MUST
// only occur once per challenge").
func Parse(values []string) ([]Challenge, error) {
	var out []Challenge
	total := 0
	for _, v := range values {
		total += len(v)
		if total > maxValueBytes {
			return nil, ErrMalformed
		}
		challenges, err := parseValue(v)
		if err != nil {
			return nil, err
		}
		out = append(out, challenges...)
	}
	return out, nil
}

type parser struct {
	s   string
	pos int
}

func parseValue(v string) ([]Challenge, error) {
	p := &parser{s: v}
	var out []Challenge
	for {
		p.skipListSeparators()
		if p.done() {
			return out, nil
		}
		c, err := p.challenge()
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
}

// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
func (p *parser) challenge() (Challenge, error) {
	scheme := p.token()
	if scheme == "" {
		return Challenge{}, ErrMalformed
	}
	c := Challenge{Scheme: strings.ToLower(scheme)}
	if p.done() || p.peek() == ',' {
		return c, nil
	}
	if p.peek() != ' ' {
		return Challenge{}, ErrMalformed
	}
	p.skipSpaces()
	if p.done() || p.peek() == ',' {
		return c, nil
	}
	if t68, ok := p.token68(); ok {
		c.Token68 = t68
		return c, nil
	}
	params, err := p.authParams()
	if err != nil {
		return Challenge{}, err
	}
	c.Params = params
	return c, nil
}

// token68 is accepted only when it is the whole remainder of this
// challenge — followed by the end, or by a list comma — and isn't the
// start of an auth-param.
func (p *parser) token68() (string, bool) {
	start := p.pos
	i := start
	for i < len(p.s) && isToken68Char(p.s[i]) {
		i++
	}
	if i == start {
		return "", false
	}
	for i < len(p.s) && p.s[i] == '=' {
		i++
	}
	j := i
	for j < len(p.s) && (p.s[j] == ' ' || p.s[j] == '\t') {
		j++
	}
	if j < len(p.s) && p.s[j] != ',' {
		return "", false
	}
	p.pos = j
	return p.s[start:i], true
}

// authParams parses "#auth-param" up to the start of the next challenge
// (a token not followed by "=") or the end.
func (p *parser) authParams() (map[string]string, error) {
	params := map[string]string{}
	for {
		name, value, err := p.authParam()
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(name)
		if _, dup := params[key]; dup {
			return nil, ErrMalformed
		}
		params[key] = value
		more, err := p.afterParam()
		if err != nil {
			return nil, err
		}
		if !more {
			return params, nil
		}
	}
}

// authParam parses one "auth-param": token BWS "=" BWS ( token /
// quoted-string ).
func (p *parser) authParam() (name, value string, err error) {
	p.skipSpaces()
	name = p.token()
	if name == "" {
		return "", "", ErrMalformed
	}
	p.skipSpaces()
	if p.done() || p.peek() != '=' {
		return "", "", ErrMalformed
	}
	p.pos++
	p.skipSpaces()
	value, err = p.paramValue()
	if err != nil {
		return "", "", err
	}
	return name, value, nil
}

// afterParam consumes what follows a parameter, reporting whether
// another parameter of the same challenge follows.
func (p *parser) afterParam() (more bool, err error) {
	p.skipSpaces()
	if p.done() {
		return false, nil
	}
	if p.peek() != ',' {
		return false, ErrMalformed
	}
	// A comma ends this parameter; it also ends the challenge if
	// what follows is a new scheme rather than another parameter.
	save := p.pos
	p.skipListSeparators()
	if p.done() {
		return false, nil
	}
	if !p.nextIsParam() {
		p.pos = save
		return false, nil
	}
	return true, nil
}

// nextIsParam reports whether the text at pos is "token BWS =".
func (p *parser) nextIsParam() bool {
	t := p.tokenAt(p.pos)
	if t == "" {
		return false
	}
	i := p.pos + len(t)
	for i < len(p.s) && (p.s[i] == ' ' || p.s[i] == '\t') {
		i++
	}
	return i < len(p.s) && p.s[i] == '='
}

func (p *parser) paramValue() (string, error) {
	if !p.done() && p.peek() == '"' {
		return p.quotedString()
	}
	v := p.token()
	if v == "" {
		return "", ErrMalformed
	}
	return v, nil
}

// quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
func (p *parser) quotedString() (string, error) {
	p.pos++ // opening quote
	var b strings.Builder
	for p.pos < len(p.s) {
		ch := p.s[p.pos]
		switch {
		case ch == '"':
			p.pos++
			return b.String(), nil
		case ch == '\\':
			if p.pos+1 >= len(p.s) || !isQuotedPairChar(p.s[p.pos+1]) {
				return "", ErrMalformed
			}
			b.WriteByte(p.s[p.pos+1])
			p.pos += 2
		case isQDText(ch):
			b.WriteByte(ch)
			p.pos++
		default:
			return "", ErrMalformed
		}
	}
	return "", ErrMalformed
}

func (p *parser) token() string {
	t := p.tokenAt(p.pos)
	p.pos += len(t)
	return t
}

func (p *parser) tokenAt(i int) string {
	start := i
	for i < len(p.s) && isTChar(p.s[i]) {
		i++
	}
	return p.s[start:i]
}

func (p *parser) skipSpaces() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}

// skipListSeparators skips OWS and empty list elements (RFC 9110 §5.6.1).
func (p *parser) skipListSeparators() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t' || p.s[p.pos] == ',') {
		p.pos++
	}
}

func (p *parser) done() bool { return p.pos >= len(p.s) }
func (p *parser) peek() byte { return p.s[p.pos] }

// tchar (RFC 9110 §5.6.2).
func isTChar(c byte) bool {
	if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func isToken68Char(c byte) bool {
	if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
		return true
	}
	return strings.IndexByte("-._~+/", c) >= 0
}

// qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text. obs-text is
// not accepted: nothing this package's callers read is meant to carry it.
func isQDText(c byte) bool {
	return c == '\t' || c == ' ' || c == 0x21 || c >= 0x23 && c <= 0x5B || c >= 0x5D && c <= 0x7E
}

// quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text ), again without obs-text.
func isQuotedPairChar(c byte) bool {
	return c == '\t' || c >= 0x20 && c <= 0x7E
}
