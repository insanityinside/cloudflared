//go:build darwin || linux || freebsd || openbsd

package ingress

// This file extracts logic shared by Darwin, Linux, FreeBSD, and OpenBSD implementations of ICMPProxy.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"golang.org/x/net/icmp"

	"github.com/cloudflare/cloudflared/packet"
)

// newICMPConn opens an ICMP socket on the given IP.
// On Darwin and Linux a non-privileged datagram socket (udp4/udp6) is used.
// On FreeBSD a privileged raw socket (ip4:icmp / ip6:ipv6-icmp) is used.
func newICMPConn(listenIP netip.Addr) (*icmp.PacketConn, error) {
	if listenIP.Is4() {
		if icmpUsesRawSocket {
			return icmp.ListenPacket("ip4:icmp", listenIP.String())
		}
		return icmp.ListenPacket("udp4", listenIP.String())
	}
	if icmpUsesRawSocket {
		return icmp.ListenPacket("ip6:ipv6-icmp", listenIP.String())
	}
	return icmp.ListenPacket("udp6", listenIP.String())
}

func netipAddr(addr net.Addr) (netip.Addr, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		// datagram socket (Darwin, Linux)
		return a.AddrPort().Addr(), true
	case *net.IPAddr:
		// raw socket (FreeBSD); IPv4 raw reads also come through handleFullPacket,
		// but IPv6 raw reads return *net.IPAddr peers and use this path.
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return netip.Addr{}, false
		}
		return ip.Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// icmpDstAddr returns the correct net.Addr type to pass to icmp.PacketConn.WriteTo.
// Raw sockets require *net.IPAddr; datagram sockets require *net.UDPAddr.
func icmpDstAddr(dst netip.Addr) net.Addr {
	if icmpUsesRawSocket {
		return &net.IPAddr{IP: dst.AsSlice()}
	}
	return &net.UDPAddr{IP: dst.AsSlice()}
}

type flow3Tuple struct {
	srcIP          netip.Addr
	dstIP          netip.Addr
	originalEchoID int
}

// icmpEchoFlow implements the packet.Funnel interface.
type icmpEchoFlow struct {
	*packet.ActivityTracker
	closeCallback  func() error
	closed         *atomic.Bool
	src            netip.Addr
	originConn     *icmp.PacketConn
	responder      ICMPResponder
	assignedEchoID int
	originalEchoID int
}

func newICMPEchoFlow(src netip.Addr, closeCallback func() error, originConn *icmp.PacketConn, responder ICMPResponder, assignedEchoID, originalEchoID int) *icmpEchoFlow {
	return &icmpEchoFlow{
		ActivityTracker: packet.NewActivityTracker(),
		closeCallback:   closeCallback,
		closed:          &atomic.Bool{},
		src:             src,
		originConn:      originConn,
		responder:       responder,
		assignedEchoID:  assignedEchoID,
		originalEchoID:  originalEchoID,
	}
}

func (ief *icmpEchoFlow) Equal(other packet.Funnel) bool {
	otherICMPFlow, ok := other.(*icmpEchoFlow)
	if !ok {
		return false
	}
	if otherICMPFlow.src != ief.src {
		return false
	}
	if otherICMPFlow.originalEchoID != ief.originalEchoID {
		return false
	}
	if otherICMPFlow.assignedEchoID != ief.assignedEchoID {
		return false
	}
	return true
}

func (ief *icmpEchoFlow) Close() error {
	ief.closed.Store(true)
	return ief.closeCallback()
}

func (ief *icmpEchoFlow) IsClosed() bool {
	return ief.closed.Load()
}

// sendToDst rewrites the echo ID to the one assigned to this flow
func (ief *icmpEchoFlow) sendToDst(dst netip.Addr, msg *icmp.Message) error {
	ief.UpdateLastActive()
	originalEcho, err := getICMPEcho(msg)
	if err != nil {
		return err
	}
	sendMsg := icmp.Message{
		Type: msg.Type,
		Code: msg.Code,
		Body: &icmp.Echo{
			ID:   ief.assignedEchoID,
			Seq:  originalEcho.Seq,
			Data: originalEcho.Data,
		},
	}
	// For IPv4, the pseudoHeader is not used because the checksum is always calculated
	var pseudoHeader []byte = nil
	serializedPacket, err := sendMsg.Marshal(pseudoHeader)
	if err != nil {
		return err
	}
	_, err = ief.originConn.WriteTo(serializedPacket, icmpDstAddr(dst))
	return err
}

// returnToSrc rewrites the echo ID to the original echo ID from the eyeball
func (ief *icmpEchoFlow) returnToSrc(reply *echoReply) error {
	ief.UpdateLastActive()
	reply.echo.ID = ief.originalEchoID
	reply.msg.Body = reply.echo
	pk := packet.ICMP{
		IP: &packet.IP{
			Src:      reply.from,
			Dst:      ief.src,
			Protocol: layers.IPProtocol(reply.msg.Type.Protocol()),
			TTL:      packet.DefaultTTL,
		},
		Message: reply.msg,
	}
	return ief.responder.ReturnPacket(&pk)
}

type echoReply struct {
	from netip.Addr
	msg  *icmp.Message
	echo *icmp.Echo
}

// errNotEchoReply is returned by parseReply when the ICMP message is valid but
// not an echo reply (e.g. NDP neighbor advertisements received on a FreeBSD raw
// IPv6 socket). Callers that want to fall back to handleFullPacket should only
// do so when this sentinel is NOT set — i.e. when icmp.ParseMessage itself failed.
var errNotEchoReply = errors.New("not an ICMP echo reply")

func parseReply(from net.Addr, rawMsg []byte) (*echoReply, error) {
	fromAddr, ok := netipAddr(from)
	if !ok {
		return nil, fmt.Errorf("cannot convert %s to netip.Addr", from)
	}
	proto := layers.IPProtocolICMPv4
	if fromAddr.Is6() {
		proto = layers.IPProtocolICMPv6
	}
	msg, err := icmp.ParseMessage(int(proto), rawMsg)
	if err != nil {
		return nil, err
	}
	echo, err := getICMPEcho(msg)
	if err != nil {
		// ICMP parsed OK but is not an echo (e.g. NDP on a raw IPv6 socket).
		return nil, fmt.Errorf("%w: %w", errNotEchoReply, err)
	}
	return &echoReply{
		from: fromAddr,
		msg:  msg,
		echo: echo,
	}, nil
}

func toICMPEchoFlow(funnel packet.Funnel) (*icmpEchoFlow, error) {
	icmpFlow, ok := funnel.(*icmpEchoFlow)
	if !ok {
		return nil, fmt.Errorf("%v is not *ICMPEchoFunnel", funnel)
	}
	return icmpFlow, nil
}

func createShouldReplaceFunnelFunc(logger *zerolog.Logger, responder ICMPResponder, pk *packet.ICMP, originalEchoID int) func(packet.Funnel) bool {
	return func(existing packet.Funnel) bool {
		existingFlow, err := toICMPEchoFlow(existing)
		if err != nil {
			logger.Err(err).
				Str("src", pk.Src.String()).
				Str("dst", pk.Dst.String()).
				Int("originalEchoID", originalEchoID).
				Msg("Funnel of wrong type found")
			return true
		}
		// Each quic connection should have a unique muxer.
		// If the existing flow has a different muxer, there's a new quic connection where return packets should be
		// routed. Otherwise, return packets will be send to the first observed incoming connection, rather than the
		// most recently observed connection.
		if existingFlow.responder.ConnectionIndex() != responder.ConnectionIndex() {
			logger.Debug().
				Str("src", pk.Src.String()).
				Str("dst", pk.Dst.String()).
				Int("originalEchoID", originalEchoID).
				Msg("Replacing funnel with new responder")
			return true
		}
		return false
	}
}
