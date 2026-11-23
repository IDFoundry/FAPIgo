package checkout

// AuthReqIDOf is the auth_req_id of Pocketwise's link linkID, for a test
// that forges a ping for it: the demo keeps it out of the link's URL.
func (w *World) AuthReqIDOf(linkID string) string {
	w.pocketwise.mu.Lock()
	defer w.pocketwise.mu.Unlock()
	if l, ok := w.pocketwise.links[linkID]; ok {
		return l.session.AuthReqID()
	}
	return ""
}
