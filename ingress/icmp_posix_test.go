//go:build darwin || linux || freebsd

package ingress

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/fortytw2/leaktest"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/cloudflare/cloudflared/packet"
)

func TestFunnelIdleTimeout(t *testing.T) {
	if icmpUsesRawSocket && syscall.Getuid() != 0 {
		t.Skip("raw ICMP socket requires root")
	}
	defer leaktest.Check(t)()

	const (
		idleTimeout = time.Second
		echoID      = 42573
		startSeq    = 8129
	)
	logger := zerolog.New(os.Stderr)
	proxy, err := newICMPProxy(localhostIP, &logger, idleTimeout)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	proxyDone := make(chan struct{})
	go func() {
		proxy.Serve(ctx)
		close(proxyDone)
	}()

	// Send a packet to register the flow
	pk := packet.ICMP{
		IP: &packet.IP{
			Src:      localhostIP,
			Dst:      localhostIP,
			Protocol: layers.IPProtocolICMPv4,
		},
		Message: &icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   echoID,
				Seq:  startSeq,
				Data: []byte(t.Name()),
			},
		},
	}
	muxer := newMockMuxer(0)
	responder := newPacketResponder(muxer, 0, packet.NewEncoder())
	require.NoError(t, proxy.Request(ctx, &pk, responder))
	validateEchoFlow(t, <-muxer.cfdToEdge, &pk)

	// Send second request, should reuse the funnel
	require.NoError(t, proxy.Request(ctx, &pk, responder))
	validateEchoFlow(t, <-muxer.cfdToEdge, &pk)

	// New muxer on a different connection should use a new flow
	time.Sleep(idleTimeout * 2)
	newMuxer := newMockMuxer(0)
	newResponder := newPacketResponder(newMuxer, 1, packet.NewEncoder())
	require.NoError(t, proxy.Request(ctx, &pk, newResponder))
	validateEchoFlow(t, <-newMuxer.cfdToEdge, &pk)

	time.Sleep(idleTimeout * 2)
	cancel()
	<-proxyDone
}

func TestReuseFunnel(t *testing.T) {
	if icmpUsesRawSocket && syscall.Getuid() != 0 {
		t.Skip("raw ICMP socket requires root")
	}
	defer leaktest.Check(t)()

	const (
		idleTimeout = time.Millisecond * 100
		echoID      = 42573
		startSeq    = 8129
	)
	logger := zerolog.New(os.Stderr)
	proxy, err := newICMPProxy(localhostIP, &logger, idleTimeout)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	proxyDone := make(chan struct{})
	go func() {
		proxy.Serve(ctx)
		close(proxyDone)
	}()

	// Send a packet to register the flow
	pk := packet.ICMP{
		IP: &packet.IP{
			Src:      localhostIP,
			Dst:      localhostIP,
			Protocol: layers.IPProtocolICMPv4,
		},
		Message: &icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   echoID,
				Seq:  startSeq,
				Data: []byte(t.Name()),
			},
		},
	}
	tuple := flow3Tuple{
		srcIP:          pk.Src,
		dstIP:          pk.Dst,
		originalEchoID: echoID,
	}
	muxer := newMockMuxer(0)
	responder := newPacketResponder(muxer, 0, packet.NewEncoder())
	require.NoError(t, proxy.Request(ctx, &pk, responder))
	validateEchoFlow(t, <-muxer.cfdToEdge, &pk)
	funnel1, found := getFunnel(t, proxy, tuple)
	require.True(t, found)

	// Send second request, should reuse the funnel
	require.NoError(t, proxy.Request(ctx, &pk, responder))
	validateEchoFlow(t, <-muxer.cfdToEdge, &pk)
	funnel2, found := getFunnel(t, proxy, tuple)
	require.True(t, found)
	require.Equal(t, funnel1, funnel2)

	time.Sleep(idleTimeout * 2)

	cancel()
	<-proxyDone
}

// TestNetipAddr validates that netipAddr correctly handles both *net.UDPAddr
// (datagram sockets used on Darwin/Linux) and *net.IPAddr (raw sockets used on
// FreeBSD), as well as returning false for unrecognised types.
func TestNetipAddr(t *testing.T) {
	ipv4Raw := net.IP{1, 2, 3, 4}
	ipv6Raw := net.ParseIP("2001:db8::1")

	tests := []struct {
		name    string
		addr    net.Addr
		wantOK  bool
		wantStr string
	}{
		{
			name:    "UDPAddr IPv4",
			addr:    &net.UDPAddr{IP: ipv4Raw},
			wantOK:  true,
			wantStr: "1.2.3.4",
		},
		{
			name:    "UDPAddr IPv6",
			addr:    &net.UDPAddr{IP: ipv6Raw},
			wantOK:  true,
			wantStr: "2001:db8::1",
		},
		{
			name:    "IPAddr IPv4",
			addr:    &net.IPAddr{IP: ipv4Raw},
			wantOK:  true,
			wantStr: "1.2.3.4",
		},
		{
			name:    "IPAddr IPv6",
			addr:    &net.IPAddr{IP: ipv6Raw},
			wantOK:  true,
			wantStr: "2001:db8::1",
		},
		{
			name:   "unsupported type",
			addr:   &net.TCPAddr{IP: ipv4Raw},
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := netipAddr(tt.addr)
			require.Equal(t, tt.wantOK, ok)
			if ok {
				require.Equal(t, tt.wantStr, got.String())
			}
		})
	}
}

