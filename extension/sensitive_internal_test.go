package extension

import (
	"errors"
	"testing"
)

// TestWithheldCauseGivesNoText checks the holder of a Sensitive
// refusal's cause gives none of the cause's text, should anything call
// its Error, while errors.Is still reaches the cause through it.
func TestWithheldCauseGivesNoText(t *testing.T) {
	cause := errors.New("quotes the value 10.20.30.400.secret")
	held := &withheldCause{&cause}
	if held.Error() != withheldDetail || !errors.Is(held, cause) {
		t.Errorf("withheldCause = %q, errors.Is finds the cause: %t", held.Error(), errors.Is(held, cause))
	}
}
