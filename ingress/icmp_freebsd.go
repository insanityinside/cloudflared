//go:build freebsd

package ingress

import (
	"fmt"
	"net/netip"
	"syscall"

	"github.com/rs/zerolog"
)

// icmpUsesRawSocket is true on FreeBSD: the OS has no unprivileged datagram
// ICMP support, so a privileged raw socket (SOCK_RAW) is required (needs root).
const icmpUsesRawSocket = true

// checkICMPProxyPermission verifies that cloudflared is running as root before
// attempting to open a raw ICMP socket. Mirrors the intent of Linux's
// testPermission check for ping_group_range. Called once for the IPv4 proxy and
// once for the IPv6 proxy; the warning is only emitted for the IPv4 call to
// avoid repeating the same message.
func checkICMPProxyPermission(listenIP netip.Addr, logger *zerolog.Logger) error {
	if uid := syscall.Getuid(); uid != 0 {
		err := fmt.Errorf("ICMP proxy on FreeBSD requires root privileges to open a raw ICMP socket (current UID %d)", uid)
		if listenIP.Is4() {
			// only warn once; the IPv6 proxy calls this function too
			logger.Warn().Err(err).Msg("Cannot create ICMP proxy")
		}
		return err
	}
	return nil
}
