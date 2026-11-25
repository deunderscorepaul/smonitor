package scanner

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/smonitor/smonitor/internal/model"
)

const (
	protoICMPv4 = 1
	echoMagic   = "SMON"
)

// Config holds parameters for the ICMP ping and traceroute engine.
type Config struct {
	Timeout         time.Duration
	MaxHops         int
	Concurrency     int
	ForceOSFallback bool
}

// PingResult holds the outcome of a responsive host during a ping sweep.
type PingResult struct {
	IP       net.IP
	Hostname string
	RTTMs    float64
}

// Engine defines the network probing interface for ping sweeps and traceroute.
type Engine interface {
	PingSweep(ctx context.Context, targets []net.IP) ([]PingResult, error)
	Traceroute(ctx context.Context, target net.IP) ([]model.Hop, error)
}

// ResolveHostname attempts a fast reverse DNS lookup with a strict timeout.
func ResolveHostname(ctx context.Context, ip string, timeout time.Duration) string {
	resCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var r net.Resolver
	names, err := r.LookupAddr(resCtx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}

	return strings.TrimSuffix(names[0], ".")
}

// buildEchoPayload embeds target IPv4 (4 bytes), send timestamp (8 bytes), and magic marker (4 bytes).
func buildEchoPayload(target net.IP, sentAt time.Time) []byte {
	payload := make([]byte, 16)
	if ip4 := target.To4(); ip4 != nil {
		copy(payload[0:4], ip4)
	}
	binary.BigEndian.PutUint64(payload[4:12], uint64(sentAt.UnixNano()))
	copy(payload[12:16], echoMagic)
	return payload
}

// parseEchoPayload extracts target IP and send timestamp if payload matches our format.
func parseEchoPayload(data []byte) (net.IP, time.Time, bool) {
	if len(data) < 16 || string(data[12:16]) != echoMagic {
		return nil, time.Time{}, false
	}
	ip := make(net.IP, net.IPv4len)
	copy(ip, data[0:4])
	nano := int64(binary.BigEndian.Uint64(data[4:12]))
	return ip, time.Unix(0, nano), true
}

// parseEmbeddedICMPHeader extracts the original ICMP Echo ID and Seq from an ICMP TimeExceeded/DstUnreach payload.
// Per RFC 792, the payload contains the original IPv4 header + at least the first 8 bytes of the original datagram.
func parseEmbeddedICMPHeader(data []byte) (id uint16, seq uint16, ok bool) {
	if len(data) < 28 {
		return 0, 0, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl+8 {
		return 0, 0, false
	}
	// Protocol byte at offset 9 must be ICMP (1)
	if data[9] != protoICMPv4 {
		return 0, 0, false
	}
	// Original ICMP header: Type(1), Code(1), Checksum(2), ID(2), Seq(2)
	id = binary.BigEndian.Uint16(data[ihl+4 : ihl+6])
	seq = binary.BigEndian.Uint16(data[ihl+6 : ihl+8])
	return id, seq, true
}
