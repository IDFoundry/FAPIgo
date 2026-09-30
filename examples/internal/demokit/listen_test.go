package demokit

import (
	"net"
	"testing"
)

func TestListenRefusesAPortInUse(t *testing.T) {
	// Another program holding the port on every address, like a
	// container publishing it.
	other, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	if listeners, err := Listen(other.Addr().(*net.TCPAddr).Port); err == nil {
		for _, l := range listeners {
			_ = l.Close()
		}
		t.Fatal("listen on a port another program holds = nil error, want error")
	}
}

func TestListenBindsBothLoopbacks(t *testing.T) {
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	_ = free.Close()

	listeners, err := Listen(port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	hosts := map[string]bool{}
	for _, l := range listeners {
		hosts[l.Addr().(*net.TCPAddr).IP.String()] = true
	}
	if !hosts["127.0.0.1"] {
		t.Errorf("listeners = %v, want 127.0.0.1 among them", hosts)
	}
	if ln6, err := net.Listen("tcp", "[::1]:0"); err == nil {
		_ = ln6.Close()
		if !hosts["::1"] {
			t.Errorf("listeners = %v, want ::1 too on a machine with IPv6 loopback", hosts)
		}
	}
}
