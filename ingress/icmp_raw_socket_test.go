//go:build freebsd || openbsd

package ingress

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cloudflare/cloudflared/packet"
)

func getFunnel(t *testing.T, proxy *icmpProxy, tuple flow3Tuple) (packet.Funnel, bool) {
	assignedEchoID, success := proxy.echoIDTracker.getOrAssign(tuple)
	require.True(t, success)
	return proxy.srcFunnelTracker.Get(echoFunnelID(assignedEchoID))
}
