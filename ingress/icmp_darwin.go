//go:build darwin

package ingress

import (
	"net/netip"

	"github.com/rs/zerolog"
)

// checkICMPProxyPermission is a no-op on Darwin: the OS allows unprivileged
// datagram ICMP sockets natively, so no permission pre-check is needed.
func checkICMPProxyPermission(_ netip.Addr, _ *zerolog.Logger) error { return nil }
