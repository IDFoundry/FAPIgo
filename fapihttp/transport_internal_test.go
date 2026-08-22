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
		{"loopback v6, not allowed", "::1", false, true},
		{"loopback v6, allowed", "::1", true, false},
		{"unspecified v6", "::", false, true},
		{"IPv4-mapped IPv6 loopback", "::ffff:127.0.0.1", false, true},
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

		// IPv6 transition addresses that tunnel an IPv4 destination:
		// each of these must be judged by the embedded v4 address, not
		// by the (global-unicast-looking) IPv6 form itself.
		{"NAT64 -> link-local (cloud metadata)", "64:ff9b::a9fe:a9fe", false, true},
		{"NAT64 -> loopback", "64:ff9b::7f00:1", false, true},
		{"NAT64 -> private", "64:ff9b::a00:1", false, true},
		{"NAT64 -> public, stays allowed", "64:ff9b::808:808", false, false},
		{"NAT64 -> loopback, allowLoopback exempts it", "64:ff9b::7f00:1", true, false},
		{"6to4 -> loopback", "2002:7f00:1::", false, true},
		{"6to4 -> link-local (cloud metadata)", "2002:a9fe:a9fe::", false, true},
		// Teredo (RFC 4380): client v4 lives in the low 32 bits,
		// bit-inverted. Target 169.254.169.254 = A9.FE.A9.FE; XOR each
		// byte with 0xFF -> 56.01.56.01 -> hextets 5601:5601.
		{"Teredo -> link-local (cloud metadata)", "2001:0:0:0:0:0:5601:5601", false, true},
		{"IPv4-compatible -> link-local (cloud metadata)", "::a9fe:a9fe", false, true},
		{"ordinary global-unicast IPv6, unaffected", "2606:4700:4700::1111", false, false},

		// ISATAP (RFC 5214): identified by the 0000:5efe/0200:5efe
		// interface-ID marker, not by prefix.
		{"ISATAP 0000:5efe -> private", "2001:db8::5efe:c0a8:101", false, true},
		{"ISATAP already blocked via link-local, unaffected by the marker", "fe80::5efe:c0a8:101", false, true},
		{"ISATAP 0200:5efe -> loopback", "2001:db8::200:5efe:7f00:1", false, true},
		{"5efe present but not at the ISATAP interface-ID position, unaffected", "2001:db8:aaaa:bbbb:cccc:dddd:5efe:c0a8", false, false},

		// Non-routable IPv4 ranges the plain checks don't cover.
		{"0.0.0.0/8 non-zero (\"this network\")", "0.1.2.3", false, true},
		{"TEST-NET-1 documentation", "192.0.2.1", false, true},
		{"TEST-NET-2 documentation", "198.51.100.1", false, true},
		{"TEST-NET-3 documentation", "203.0.113.1", false, true},
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

func TestEmbeddedIPv4(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want string // "" means nil (not a transition address)
	}{
		{"NAT64", "64:ff9b::808:808", "8.8.8.8"},
		{"6to4", "2002:0102:0304::", "1.2.3.4"},
		{"Teredo", "2001:0:0:0:0:0:5601:5601", "169.254.169.254"},
		{"IPv4-compatible", "::102:304", "1.2.3.4"},
		{"plain IPv4, not applicable", "8.8.8.8", ""},
		{"IPv4-mapped, not applicable", "::ffff:8.8.8.8", ""},
		// ::1 and :: technically match the IPv4-compatible ::a.b.c.d
		// pattern this helper decodes (their low 32 bits are 0.0.0.1
		// and 0.0.0.0 respectively) — disallowedIP never actually
		// reaches this helper for either, since its own
		// IsLoopback/IsUnspecified checks return first, but this
		// documents embeddedIPv4's actual behavior in isolation.
		{"loopback low bits", "::1", "0.0.0.1"},
		{"unspecified low bits", "::", "0.0.0.0"},
		{"ordinary global-unicast IPv6", "2606:4700:4700::1111", ""},
		{"ISATAP 0000:5efe", "2001:db8::5efe:c0a8:101", "192.168.1.1"},
		{"ISATAP 0200:5efe", "2001:db8::200:5efe:7f00:1", "127.0.0.1"},
		{"5efe present but not at the ISATAP interface-ID position", "2001:db8:aaaa:bbbb:cccc:dddd:5efe:c0a8", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) = nil", tc.ip)
			}
			got := embeddedIPv4(ip)
			if tc.want == "" {
				if got != nil {
					t.Errorf("embeddedIPv4(%s) = %v, want nil", tc.ip, got)
				}
				return
			}
			want := net.ParseIP(tc.want)
			if got == nil || !got.Equal(want) {
				t.Errorf("embeddedIPv4(%s) = %v, want %s", tc.ip, got, tc.want)
			}
		})
	}
}
