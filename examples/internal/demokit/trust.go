package demokit

import (
	"fmt"
	"runtime"
)

// TrustCommand is the command adding the demo CA at caPath, named
// caName, to the current user's trust store on this OS.
func TrustCommand(caPath, caName string) string {
	switch runtime.GOOS {
	case "darwin":
		return fmt.Sprintf("security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db %q", caPath)
	case "windows":
		return fmt.Sprintf("certutil -user -addstore Root %q", caPath)
	default:
		return fmt.Sprintf("certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n %q -i %q", caName, caPath)
	}
}
