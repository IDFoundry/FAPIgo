package fapitest

// EmbedderUIWithKey is h.EmbedderUI sealing its interactions with key,
// for the key-material matrix to render one whose key it knows.
func EmbedderUIWithKey(h *Harness, opts EmbedderUIOptions, key []byte) *EmbedderUI {
	return h.embedderUI(opts, key)
}
