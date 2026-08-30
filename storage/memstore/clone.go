package memstore

import "encoding/json"

// cloneRawMessageMap returns a deep copy of m: a fresh map holding a
// fresh, independently-owned byte slice for every value. A Go map or
// slice field copies its header by value but shares its backing data,
// so simply assigning a stored/returned struct is not enough to keep
// this store's records independent of whatever the caller does with
// its own copy afterward — every value that crosses this package's
// store/retrieve boundary must be cloned, in both directions, or a
// caller's later mutation could silently corrupt another caller's
// already-returned value or this store's own internal record.
func cloneRawMessageMap(m map[string]json.RawMessage) map[string]json.RawMessage {
	if m == nil {
		return nil
	}
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		out[k] = append(json.RawMessage(nil), v...)
	}
	return out
}

// cloneStrings returns a deep copy of s, for the same reason as
// cloneRawMessageMap.
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s...)
}
