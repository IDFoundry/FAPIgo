package fapihttp

import (
	"net"
	"testing"
)

func TestDisallowedIP(t *testing.T) {
	cases := []struct {
		name          string
		ip            string
		allowLoopback bool
		want          bool
	}{
		{"loopback v4, not allowed", "127.0.0.1", false, true},
		{"loopback v4, allowed", "127.0.0.1", true, false},
		{"loopback v6, allowed", "::1", true, false},
		{"private RFC1918", "10.0.0.5", false, true},
		{"link-local (cloud metadata)", "169.254.169.254", false, true},
		{"link-local, allowLoopback does not except it", "169.254.169.254", true, true},
		{"unspecified", "0.0.0.0", false, true},
		{"multicast", "224.0.0.1", false, true},
		{"public", "8.8.8.8", false, false},
		{"public, allowLoopback still fine", "8.8.8.8", true, false},
		{"CGNAT low", "100.64.0.1", false, true},
		{"CGNAT high", "100.127.255.254", false, true},
		{"reserved 240/4", "240.0.0.1", false, true},
		{"broadcast", "255.255.255.255", false, true},
		{"IETF protocol assignment", "192.0.0.1", false, true},
		{"benchmarking", "198.18.0.1", false, true},
		{"IPv4-mapped IPv6 CGNAT", "::ffff:100.64.0.1", false, true},
		{"IPv4-mapped IPv6 link-local", "::ffff:169.254.169.254", false, true},
		{"public, real-world address", "93.184.216.34", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) = nil", tc.ip)
			}
			if got := disallowedIP(ip, tc.allowLoopback); got != tc.want {
				t.Errorf("disallowedIP(%s, allowLoopback=%v) = %v, want %v", tc.ip, tc.allowLoopback, got, tc.want)
			}
		})
	}
}
