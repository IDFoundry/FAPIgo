package demonet

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var testHosts = []string{"console.localhost", "id.eastmark.localhost"}

func TestLoadOrIssueKeepsCertificatesAcrossRuns(t *testing.T) {
	dir, now := t.TempDir(), time.Now()
	first, err := loadOrIssue(dir, testHosts, now)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	second, err := loadOrIssue(dir, []string{"id.eastmark.localhost", "console.localhost"}, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if !first.ca.Equal(second.ca) {
		t.Error("second run issued a new CA, want the saved one")
	}
	if !bytes.Equal(first.serving.Certificate[0], second.serving.Certificate[0]) {
		t.Error("second run issued a new serving certificate, want the saved one")
	}
	for _, name := range []string{caKeyFile, leafKeyFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s permissions = %v, want 0600", name, perm)
		}
	}
}

func TestLoadOrIssueReissuesServingCertificateForNewHosts(t *testing.T) {
	dir, now := t.TempDir(), time.Now()
	first, err := loadOrIssue(dir, testHosts, now)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	hosts := append([]string{"union.localhost"}, testHosts...)
	second, err := loadOrIssue(dir, hosts, now)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if !first.ca.Equal(second.ca) {
		t.Error("new hosts replaced the CA, want only the serving certificate replaced")
	}
	if err := second.serving.Leaf.VerifyHostname("union.localhost"); err != nil {
		t.Errorf("serving certificate doesn't cover the added host: %v", err)
	}
}

func TestLoadOrIssueRenewsBeforeExpiry(t *testing.T) {
	dir, now := t.TempDir(), time.Now()
	first, err := loadOrIssue(dir, testHosts, now)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	// Within renewBefore of the serving certificate's expiry, but not
	// the CA's.
	later := first.serving.Leaf.NotAfter.Add(-renewBefore / 2)
	second, err := loadOrIssue(dir, testHosts, later)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if !first.ca.Equal(second.ca) {
		t.Error("CA replaced early")
	}
	if bytes.Equal(first.serving.Certificate[0], second.serving.Certificate[0]) {
		t.Error("serving certificate close to expiry was kept, want it renewed")
	}
	third, err := loadOrIssue(dir, testHosts, first.ca.NotAfter.Add(-renewBefore/2))
	if err != nil {
		t.Fatalf("third run: %v", err)
	}
	if first.ca.Equal(third.ca) {
		t.Error("CA close to expiry was kept, want it renewed")
	}
}

func TestCAOnlyVouchesForLocalhost(t *testing.T) {
	now := time.Now()
	ca, caKey, err := issueCA(now)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, host := range []string{"example.com", "localhost.example.com"} {
		leaf, err := issueLeaf(ca, caKey, []string{host}, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err == nil {
			t.Errorf("a certificate for %s from the demo CA verified, want the name constraint to reject it", host)
		}
	}
	leaf, err := issueLeaf(ca, caKey, testHosts, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: testHosts[1]}); err != nil {
		t.Errorf("demo serving certificate doesn't verify: %v", err)
	}
}

func TestLoadOrIssueWithoutStateDirKeepsNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if _, err := loadOrIssue("", testHosts, time.Now()); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("wrote %d files with no state directory, want none", len(entries))
	}
}
