package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/smonitor/smonitor/internal/model"
)

// ICMPScanner implements native ICMPv4 ping sweeps and TTL-based traceroute using raw sockets
// (requires CAP_NET_RAW on Linux, with automatic fallback to OS ping/tracert when unprivileged).
type ICMPScanner struct {
	cfg          Config
	seqGen       atomic.Uint32
	fallbackOnce sync.Once
	useFallback  atomic.Bool
}

// NewICMPScanner creates a new ICMPScanner with sensible defaults.
func NewICMPScanner(cfg Config) *ICMPScanner {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 1 * time.Second
	}
	if cfg.MaxHops <= 0 {
		cfg.MaxHops = 15
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 32
	}
	s := &ICMPScanner{cfg: cfg}
	if cfg.ForceOSFallback {
		s.useFallback.Store(true)
	}
	return s
}

func (s *ICMPScanner) nextID() uint16 {
	seq := s.seqGen.Add(1)
	return uint16((uint32(os.Getpid()) ^ (seq * 2654435761)) & 0xffff)
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "access is denied") ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "socket") && strings.Contains(msg, "forbidden")
}

func (s *ICMPScanner) triggerFallback(reason error) {
	s.useFallback.Store(true)
	s.fallbackOnce.Do(func() {
		log.Printf("[WARN] Raw ICMP socket unavailable (%v). Falling back to OS ping/tracert commands. On Linux, grant CAP_NET_RAW via 'sudo setcap cap_net_raw+ep <binary>'.", reason)
	})
}

// PingSweep probes all target IPv4 addresses concurrently via ICMP Echo Request.
func (s *ICMPScanner) PingSweep(ctx context.Context, targets []net.IP) ([]PingResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if s.useFallback.Load() {
		return s.osPingSweep(ctx, targets)
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		if isPermissionError(err) {
			s.triggerFallback(err)
			return s.osPingSweep(ctx, targets)
		}
		return nil, fmt.Errorf("failed to open raw ICMP socket: %w", err)
	}
	defer conn.Close()

	icmpID := int(s.nextID())
	resultsMap := make(map[string]PingResult)
	sentAtMap := make(map[string]time.Time, len(targets))
	var mu sync.Mutex

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 1500)
		for {
			if ctx.Err() != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				return
			}

			msg, err := icmp.ParseMessage(protoICMPv4, buf[:n])
			if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
				continue
			}

			echo, ok := msg.Body.(*icmp.Echo)
			if !ok || echo.ID != icmpID {
				continue
			}

			now := time.Now()
			peerIP := peerIPString(peer)
			var targetIP net.IP
			var payloadSentAt time.Time
			var hasPayloadTime bool

			if embeddedIP, sentAt, ok := parseEchoPayload(echo.Data); ok {
				targetIP = embeddedIP
				payloadSentAt = sentAt
				hasPayloadTime = true
			} else if peerIP != "" {
				targetIP = net.ParseIP(peerIP).To4()
			}

			if targetIP == nil {
				continue
			}
			key := targetIP.String()

			mu.Lock()
			sentAt, targeted := sentAtMap[key]
			if !targeted {
				mu.Unlock()
				continue
			}

			var rttMs float64
			if !sentAt.IsZero() {
				rttMs = round2(float64(now.Sub(sentAt).Microseconds()) / 1000.0)
			} else if hasPayloadTime {
				rttMs = round2(float64(now.Sub(payloadSentAt).Microseconds()) / 1000.0)
			}

			if _, exists := resultsMap[key]; !exists {
				resultsMap[key] = PingResult{
					IP:    targetIP,
					RTTMs: rttMs,
				}
			}
			mu.Unlock()
		}
	}()

	// Pace outgoing Echo Requests gently so low-power devices (Raspberry Pi) and Wi-Fi APs do not drop packets.
	for i, targetIP := range targets {
		if ctx.Err() != nil {
			break
		}
		ip4 := targetIP.To4()
		if ip4 == nil {
			continue
		}

		now := time.Now()
		mu.Lock()
		sentAtMap[ip4.String()] = now
		mu.Unlock()

		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   icmpID,
				Seq:  (i + 1) & 0xffff,
				Data: buildEchoPayload(ip4, now),
			},
		}
		wb, err := msg.Marshal(nil)
		if err != nil {
			continue
		}
		_, _ = conn.WriteTo(wb, &net.IPAddr{IP: ip4})

		if i%4 == 3 {
			time.Sleep(1 * time.Millisecond)
		}
	}

	// Wait for replies up to Timeout after the last request was transmitted.
	select {
	case <-time.After(s.cfg.Timeout):
	case <-ctx.Done():
	}

	_ = conn.Close()
	<-readDone

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	mu.Lock()
	results := make([]PingResult, 0, len(resultsMap))
	for _, r := range resultsMap {
		results = append(results, r)
	}
	mu.Unlock()

	// Concurrent reverse DNS resolution (bounded to 300ms per host).
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i := range results {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer func() {
				<-sem
				wg.Done()
			}()
			results[idx].Hostname = ResolveHostname(ctx, results[idx].IP.String(), 300*time.Millisecond)
		}(i)
	}
	wg.Wait()

	return results, nil
}

// Traceroute performs an ICMPv4 TTL-incrementing traceroute up to cfg.MaxHops.
func (s *ICMPScanner) Traceroute(ctx context.Context, target net.IP) ([]model.Hop, error) {
	ip4 := target.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("invalid IPv4 target %v", target)
	}
	if s.useFallback.Load() {
		return s.osTraceroute(ctx, ip4)
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		if isPermissionError(err) {
			s.triggerFallback(err)
			return s.osTraceroute(ctx, ip4)
		}
		return nil, fmt.Errorf("failed to open raw ICMP socket for traceroute: %w", err)
	}
	defer conn.Close()

	p := conn.IPv4PacketConn()
	if p == nil {
		return nil, fmt.Errorf("failed to obtain IPv4PacketConn")
	}

	traceID := s.nextID()
	targetStr := ip4.String()
	hops := make([]model.Hop, 0, s.cfg.MaxHops)
	buf := make([]byte, 1500)

	for ttl := 1; ttl <= s.cfg.MaxHops; ttl++ {
		if ctx.Err() != nil {
			return hops, ctx.Err()
		}

		if err := p.SetTTL(ttl); err != nil {
			return hops, fmt.Errorf("failed to set TTL=%d: %w", ttl, err)
		}

		sentAt := time.Now()
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   int(traceID),
				Seq:  ttl,
				Data: buildEchoPayload(ip4, sentAt),
			},
		}
		wb, err := msg.Marshal(nil)
		if err != nil {
			return hops, err
		}

		if _, err := conn.WriteTo(wb, &net.IPAddr{IP: ip4}); err != nil {
			hops = append(hops, model.Hop{TTL: ttl, Timeout: true})
			continue
		}

		hop, reached, err := s.waitForHopReply(ctx, conn, buf, traceID, uint16(ttl), targetStr, sentAt)
		if err != nil {
			return hops, err
		}
		hops = append(hops, hop)
		if reached {
			break
		}
	}

	return hops, nil
}

func (s *ICMPScanner) waitForHopReply(
	ctx context.Context,
	conn *icmp.PacketConn,
	buf []byte,
	traceID uint16,
	seq uint16,
	targetStr string,
	sentAt time.Time,
) (model.Hop, bool, error) {
	deadline := sentAt.Add(s.cfg.Timeout)

	for {
		if ctx.Err() != nil {
			return model.Hop{}, false, ctx.Err()
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return model.Hop{TTL: int(seq), Timeout: true}, false, nil
		}

		_ = conn.SetReadDeadline(deadline)
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return model.Hop{TTL: int(seq), Timeout: true}, false, nil
			}
			return model.Hop{TTL: int(seq), Timeout: true}, false, nil
		}

		rttMs := round2(float64(time.Since(sentAt).Microseconds()) / 1000.0)
		peerIP := peerIPString(peer)

		parsed, err := icmp.ParseMessage(protoICMPv4, buf[:n])
		if err != nil {
			continue
		}

		switch parsed.Type {
		case ipv4.ICMPTypeEchoReply:
			echo, ok := parsed.Body.(*icmp.Echo)
			if !ok {
				continue
			}
			if uint16(echo.ID) == traceID && uint16(echo.Seq) == seq {
				return model.Hop{
					TTL:   int(seq),
					IP:    peerIP,
					RTTMs: rttMs,
				}, true, nil
			}

		case ipv4.ICMPTypeTimeExceeded:
			te, ok := parsed.Body.(*icmp.TimeExceeded)
			if !ok {
				continue
			}
			embID, embSeq, ok := parseEmbeddedICMPHeader(te.Data)
			if ok && embID == traceID && embSeq == seq {
				return model.Hop{
					TTL:   int(seq),
					IP:    peerIP,
					RTTMs: rttMs,
				}, peerIP == targetStr, nil
			}

		case ipv4.ICMPTypeDestinationUnreachable:
			du, ok := parsed.Body.(*icmp.DstUnreach)
			if !ok {
				continue
			}
			embID, embSeq, ok := parseEmbeddedICMPHeader(du.Data)
			if ok && embID == traceID && embSeq == seq {
				return model.Hop{
					TTL:   int(seq),
					IP:    peerIP,
					RTTMs: rttMs,
				}, true, nil
			}
		}
	}
}

func peerIPString(peer net.Addr) string {
	switch addr := peer.(type) {
	case *net.IPAddr:
		return addr.IP.String()
	case *net.UDPAddr:
		return addr.IP.String()
	default:
		host, _, err := net.SplitHostPort(peer.String())
		if err == nil {
			return host
		}
		return peer.String()
	}
}

func round2(v float64) float64 {
	if v < 0 {
		return 0
	}
	return math.Round(v*100) / 100
}
