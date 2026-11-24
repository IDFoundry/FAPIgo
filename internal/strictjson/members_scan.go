package strictjson

import (
	"bytes"
	"encoding/json"
)

// scanMembers reports whether CheckDuplicateMembers' walker would
// accept data: its first JSON value is well formed, nests at most
// MaxNestingDepth objects and arrays, and has no object that repeats a
// member name, exactly or under FoldKey. It reads data once, byte by
// byte, and allocates only for an object of more than
// smallObjectMembers members or a name holding an escape or a non-ASCII
// byte, where json.Decoder.Token allocates for every token.
//
// It answers only "accepted": false means the walker decides, which
// keeps every error, and which of several faults is reported first,
// exactly what the walker reports. So scanMembers may refuse more than
// the walker does, at the walker's cost, but must never accept what the
// walker refuses; FuzzScanMembersMatchesWalker checks both directions.
func scanMembers(data []byte) bool {
	s := memberScanner{data: data}
	return s.value(0)
}

// smallObjectMembers is how many members an object may have before
// scanMembers indexes its names in a map rather than comparing each new
// name with every earlier one.
const smallObjectMembers = 16

type memberScanner struct {
	data []byte
	pos  int
	// folded holds the FoldKey form of the names of every object the
	// scan is inside, one after another; names holds each name's span
	// in it. An object's names are the spans from where it began.
	folded []byte
	names  []nameSpan
}

type nameSpan struct{ start, end int }

func (s *memberScanner) skipSpace() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

// next is the byte at pos after any whitespace, or 0 at the end.
func (s *memberScanner) next() byte {
	s.skipSpace()
	if s.pos == len(s.data) {
		return 0
	}
	return s.data[s.pos]
}

// value scans the value at pos, which depth objects and arrays enclose.
func (s *memberScanner) value(depth int) bool {
	switch c := s.next(); {
	case c == '{' || c == '[':
		if depth >= MaxNestingDepth {
			return false
		}
		s.pos++
		if c == '{' {
			return s.object(depth)
		}
		return s.array(depth)
	case c == '"':
		_, _, ok := s.str()
		return ok
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	case c == '-' || isDigit(c):
		return s.number()
	default:
		return false
	}
}

// object scans an object's members, after its "{", through its "}".
func (s *memberScanner) object(depth int) bool {
	mark, foldedMark := len(s.names), len(s.folded)
	defer func() { s.names, s.folded = s.names[:mark], s.folded[:foldedMark] }()
	var index map[string]struct{} // past smallObjectMembers names
	if s.next() == '}' {
		s.pos++
		return true
	}
	for {
		if s.next() != '"' {
			return false
		}
		span, ok := s.name()
		if !ok || s.repeats(mark, span, &index) {
			return false
		}
		if s.next() != ':' {
			return false
		}
		s.pos++
		if !s.value(depth + 1) {
			return false
		}
		switch s.next() {
		case ',':
			s.pos++
		case '}':
			s.pos++
			return true
		default:
			return false
		}
	}
}

// repeats reports whether span's name repeats one of the current
// object's earlier names (those from mark on), and records it.
func (s *memberScanner) repeats(mark int, span nameSpan, index *map[string]struct{}) bool {
	name := s.folded[span.start:span.end]
	earlier := s.names[mark:]
	if *index == nil && len(earlier) < smallObjectMembers {
		for _, e := range earlier {
			if bytes.Equal(s.folded[e.start:e.end], name) {
				return true
			}
		}
		s.names = append(s.names, span)
		return false
	}
	if *index == nil {
		*index = make(map[string]struct{}, 2*smallObjectMembers)
		for _, e := range earlier {
			(*index)[string(s.folded[e.start:e.end])] = struct{}{}
		}
	}
	if _, ok := (*index)[string(name)]; ok {
		return true
	}
	(*index)[string(name)] = struct{}{}
	s.names = append(s.names, span)
	return false
}

// array scans an array's elements, after its "[", through its "]".
func (s *memberScanner) array(depth int) bool {
	if s.next() == ']' {
		s.pos++
		return true
	}
	for {
		if !s.value(depth + 1) {
			return false
		}
		switch s.next() {
		case ',':
			s.pos++
		case ']':
			s.pos++
			return true
		default:
			return false
		}
	}
}

// name scans the member name at pos and appends its FoldKey form to
// folded. A name of ASCII bytes alone, without escapes, is folded in
// place (FoldKey maps ASCII to upper case); any other is unquoted as
// json.Decoder unquotes it, invalid UTF-8 becoming U+FFFD, and then
// folded with FoldKey, so two names the walker reads as one fold alike
// here too.
func (s *memberScanner) name() (nameSpan, bool) {
	start, plain, ok := s.str()
	if !ok {
		return nameSpan{}, false
	}
	span := nameSpan{start: len(s.folded)}
	if plain {
		for _, c := range s.data[start+1 : s.pos-1] {
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			s.folded = append(s.folded, c)
		}
	} else {
		var unquoted string
		if json.Unmarshal(s.data[start:s.pos], &unquoted) != nil {
			return nameSpan{}, false
		}
		s.folded = append(s.folded, FoldKey(unquoted)...)
	}
	span.end = len(s.folded)
	return span, true
}

// str scans the string at pos (its opening quote) through its closing
// quote, as RFC 8259 §7 has it: no unescaped control character, and
// only the escapes it defines. plain reports a string of ASCII bytes
// without escapes. Any other byte at or above 0x80 is accepted, as
// json.Decoder accepts invalid UTF-8.
func (s *memberScanner) str() (start int, plain, ok bool) {
	start = s.pos
	plain = true
	s.pos++
	for s.pos < len(s.data) {
		c := s.data[s.pos]
		switch {
		case c == '"':
			s.pos++
			return start, plain, true
		case c < 0x20:
			return start, false, false
		case c == '\\':
			plain = false
			if !s.escape() {
				return start, false, false
			}
			continue
		case c >= 0x80:
			plain = false
		}
		s.pos++
	}
	return start, false, false
}

// escape scans the escape at pos, its backslash, through its end.
func (s *memberScanner) escape() bool {
	if s.pos+1 >= len(s.data) {
		return false
	}
	switch s.data[s.pos+1] {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		s.pos += 2
		return true
	case 'u':
		if s.pos+6 > len(s.data) {
			return false
		}
		for _, h := range s.data[s.pos+2 : s.pos+6] {
			if !isHex(h) {
				return false
			}
		}
		s.pos += 6
		return true
	default:
		return false
	}
}

func (s *memberScanner) literal(word string) bool {
	if !bytes.HasPrefix(s.data[s.pos:], []byte(word)) {
		return false
	}
	s.pos += len(word)
	return true
}

// number scans the number at pos, as RFC 8259 §6 has it: an optional
// minus, an integer without leading zeros, then an optional fraction
// and exponent.
func (s *memberScanner) number() bool {
	s.skipByte('-')
	if !s.skipByte('0') && !s.digits() {
		return false
	}
	if s.skipByte('.') && !s.digits() {
		return false
	}
	if s.skipByte('e') || s.skipByte('E') {
		if !s.skipByte('+') {
			s.skipByte('-')
		}
		return s.digits()
	}
	return true
}

// skipByte advances past c if it is the byte at pos, reporting whether
// it was.
func (s *memberScanner) skipByte(c byte) bool {
	if s.pos < len(s.data) && s.data[s.pos] == c {
		s.pos++
		return true
	}
	return false
}

// digits scans one or more digits, reporting whether there was one.
func (s *memberScanner) digits() bool {
	start := s.pos
	for s.pos < len(s.data) && isDigit(s.data[s.pos]) {
		s.pos++
	}
	return s.pos > start
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}
