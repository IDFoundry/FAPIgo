package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
)

// listen binds port on both loopback addresses. Browsers resolve
// *.localhost to ::1 as well as 127.0.0.1 and usually try ::1 first, so
// listening on IPv4 alone would send them elsewhere — or nowhere.
//
// It first checks that no other program holds the port on any address:
// a wildcard listener (a container publishing the port, say) would
// otherwise quietly take the browser's ::1 connections, or be shadowed
// by the demo on 127.0.0.1.
func listen(port int) ([]net.Listener, error) {
	p := strconv.Itoa(port)
	probe, err := net.Listen("tcp", ":"+p)
	if err != nil {
		return nil, fmt.Errorf("port %d is already in use by another program (pick another with -port): %w", port, err)
	}
	_ = probe.Close()

	var listeners []net.Listener
	for _, host := range []string{"127.0.0.1", "::1"} {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, p))
		if err != nil {
			if host == "::1" && (errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT)) {
				continue // no IPv6 loopback on this machine: nothing to route there
			}
			for _, l := range listeners {
				_ = l.Close()
			}
			return nil, fmt.Errorf("listen on %s: %w", net.JoinHostPort(host, p), err)
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}
