//go:build darwin || linux

package ingress

// icmpUsesRawSocket is false on Darwin and Linux: both support unprivileged
// datagram ICMP sockets (SOCK_DGRAM) via udp4/udp6, so root is not required.
const icmpUsesRawSocket = false
