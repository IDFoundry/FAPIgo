package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
)

// CheckConflictingMembers is CheckDuplicateMembers, except that it
// accepts an object that repeats a member name exactly (the same once
// unescaped) when every copy's value is the same JSON text as the first
// copy's once json.Compact has removed its insignificant whitespace. A
// reader keeping the first copy and one keeping the last then take the
// same value, so the repeat leaves the document only one reading. It
// still refuses, wrapping ErrDuplicateMember, a repeat whose copies
// differ, and two names that differ only in case (FoldKey maps them
// together), however alike their values: encoding/json reads those as
// one member, where a case-sensitive reader reads two. It checks every
// copy's own value, too, so a repeated member whose copies are the
// same text but each repeat a member of their own with differing
// values is refused. Nesting deeper than MaxNestingDepth and malformed
// JSON are refused as CheckDuplicateMembers refuses them, and anything
// after the first value is likewise left to the caller.
//
// Two copies are compared as text, not as values: "a" and "a", or
// 1 and 1.0, are refused as differing, though some readers would take
// them as equal. Refusing them is conservative; it never accepts copies
// two readers could read differently.
//
// A document that repeats nothing costs what CheckDuplicateMembers
// costs: the same byte scanner (scanMembers) accepts it. Otherwise a
// json.Decoder walks it once, keeping each member's value as a span of
// data, and compacts a value only when a later copy repeats its name:
// the first copy once, each later copy once. A value is compacted once
// for each repeated member it is nested in, so the walk takes time and
// memory at most proportional to len(data) times MaxNestingDepth, and
// linear in len(data) when no repeated member nests in another.
func CheckConflictingMembers(data []byte) error {
	if scanMembers(data) {
		return nil
	}
	return walkConflictingMembers(data)
}

// CheckConflictingObject is CheckConflictingMembers for the JSON object
// whose members are members, each value already encoded, without
// encoding it: an issuer building a JWT's claims set, or another
// object, from values a caller supplied refuses what a reader running
// CheckConflictingMembers on the result would refuse. It refuses a
// value that isn't valid JSON, or that CheckConflictingMembers refuses
// as a member of the object (one level deeper than on its own), and a
// name FoldKey maps together with another's. It returns the name at
// fault, the first in sorted order, so a caller can say which member it
// refuses. Every member is the object's own (a Go map can't repeat a
// name exactly), so only case variants can repeat a name at the top.
func CheckConflictingObject(members map[string]json.RawMessage) (string, error) {
	seen := make(map[string]string, len(members)) // by FoldKey, the name as spelled
	for _, name := range slices.Sorted(maps.Keys(members)) {
		key := FoldKey(name)
		if first, ok := seen[key]; ok {
			return name, duplicateMemberError(first, name)
		}
		seen[key] = name
		value := members[name]
		if !json.Valid(value) {
			return name, fmt.Errorf("strictjson: member %q is not valid JSON", name)
		}
		// Inside "[...]" the value nests as deeply as inside the object.
		nested := slices.Concat([]byte("["), value, []byte("]"))
		if err := CheckConflictingMembers(nested); err != nil {
			return name, err
		}
	}
	return "", nil
}

// UnmarshalNoConflicts is Unmarshal, after CheckConflictingMembers: it
// refuses a member name repeated in one object with differing copies,
// or as a case variant, and accepts one repeated with identical copies,
// which encoding/json, keeping the last, reads as every other reader
// does.
func UnmarshalNoConflicts(data []byte, v any) error {
	if err := CheckConflictingMembers(data); err != nil {
		return err
	}
	return Unmarshal(data, v)
}

// conflictWalker is CheckConflictingMembers' walk of data by
// json.Decoder tokens.
type conflictWalker struct {
	dec  *json.Decoder
	data []byte
}

// firstCopy is a member as its object first holds it: its name as
// spelled there, and its value's span in data, compacted once a later
// copy needs comparing with it.
type firstCopy struct {
	name       string
	start, end int
	compact    []byte
}

func walkConflictingMembers(data []byte) error {
	w := conflictWalker{dec: json.NewDecoder(bytes.NewReader(data)), data: data}
	w.dec.UseNumber() // numbers are skipped, never converted, so none overflows
	err := w.value(0)
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF // a whole value never ends early
	}
	return err
}

// value checks the next value the decoder reads, which depth objects
// and arrays enclose.
func (w *conflictWalker) value(depth int) error {
	tok, err := w.dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= MaxNestingDepth {
		return errNestedTooDeep
	}
	if delim == '{' {
		return w.object(depth)
	}
	for w.dec.More() {
		if err := w.value(depth + 1); err != nil {
			return err
		}
	}
	_, err = w.dec.Token() // "]"
	return err
}

// object checks the members of the object whose "{" the decoder has
// just read, and their values, through its "}".
func (w *conflictWalker) object(depth int) error {
	seen := make(map[string]*firstCopy) // by FoldKey
	for w.dec.More() {
		tok, err := w.dec.Token()
		if err != nil {
			return err
		}
		name, _ := tok.(string) // a json.Decoder only reads a string here
		key := FoldKey(name)
		first := seen[key]
		if first != nil && first.name != name {
			return duplicateMemberError(first.name, name)
		}
		start := int(w.dec.InputOffset()) // just after the name
		if err := w.value(depth + 1); err != nil {
			return err
		}
		end := int(w.dec.InputOffset()) // just after the value
		if first == nil {
			seen[key] = &firstCopy{name: name, start: start, end: end}
			continue
		}
		if err := w.sameAsFirst(first, start, end); err != nil {
			return err
		}
	}
	_, err := w.dec.Token() // "}"
	return err
}

// sameAsFirst reports an error wrapping ErrDuplicateMember unless the
// value spanning data[start:end] is the same text as first's once both
// are compacted.
func (w *conflictWalker) sameAsFirst(first *firstCopy, start, end int) error {
	if first.compact == nil {
		c, err := compactValue(w.data[first.start:first.end])
		if err != nil {
			return err
		}
		first.compact = c
	}
	c, err := compactValue(w.data[start:end])
	if err != nil {
		return err
	}
	if !bytes.Equal(first.compact, c) {
		return fmt.Errorf("%w %q, whose copies differ", ErrDuplicateMember, first.name)
	}
	return nil
}

// compactValue is span, a member's value with the whitespace and colon
// that may precede it, compacted. A value never begins with either, so
// trimming them leaves just the value.
func compactValue(span []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, bytes.TrimLeft(span, " \t\r\n:")); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
