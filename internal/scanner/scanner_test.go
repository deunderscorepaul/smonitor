package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestEchoPayloadRoundTrip(t *testing.T) {
	target := net.ParseIP("192.168.1.42").To4()
	now := time.Unix(1700000000, 123456000)

	payload := buildEchoPayload(target, now)
	gotIP, gotTime, ok := parseEchoPayload(payload)
	if !ok {
		t.Fatal("expected parseEchoPayload to succeed")
	}
	if !gotIP.Equal(target) {
		t.Errorf("got IP %s, want %s", gotIP, target)
	}
	if !gotTime.Equal(now) {
		t.Errorf("got time %v, want %v", gotTime, now)
	}
}

func TestParseEmbeddedICMPHeader(t *testing.T) {
	// 20-byte IPv4 header + 8-byte ICMP Echo header
	pkt := make([]byte, 28)
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	pkt[9] = protoICMPv4
	binary.BigEndian.PutUint16(pkt[24:26], 0x1234) // ID
	binary.BigEndian.PutUint16(pkt[26:28], 7)      // Seq

	id, seq, ok := parseEmbeddedICMPHeader(pkt)
	if !ok {
		t.Fatal("expected parseEmbeddedICMPHeader to succeed")
	}
	if id != 0x1234 || seq != 7 {
		t.Errorf("got id=0x%x seq=%d, want id=0x1234 seq=7", id, seq)
	}
}

func TestParseOSPingOutput(t *testing.T) {
	winDE := `
Ping wird ausgeführt für 192.168.1.1 mit 32 Bytes Daten:
Antwort von 192.168.1.1: Bytes=32 Zeit=2ms TTL=64
`
	rtt, ok := parseOSPingOutput(winDE, 10)
	if !ok || rtt != 2 {
		t.Errorf("winDE: got ok=%v rtt=%v, want ok=true rtt=2", ok, rtt)
	}

	winSubMs := `Reply from 127.0.0.1: bytes=32 time<1ms TTL=128`
	rtt, ok = parseOSPingOutput(winSubMs, 10)
	if !ok || rtt != 0.5 {
		t.Errorf("winSubMs: got ok=%v rtt=%v, want ok=true rtt=0.5", ok, rtt)
	}

	winUnreach := `Reply from 192.168.1.10: Destination host unreachable.`
	if _, ok := parseOSPingOutput(winUnreach, 10); ok {
		t.Error("expected unreachable reply to return ok=false")
	}
}

func TestParseOSTracerouteOutput(t *testing.T) {
	sample := `
Tracing route to 1.1.1.1 over a maximum of 15 hops

  1     1 ms     1 ms     1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    12 ms    14 ms    13 ms  1.1.1.1
`
	hops := parseOSTracerouteOutput(sample)
	if len(hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(hops))
	}
	if hops[0].TTL != 1 || hops[0].IP != "192.168.1.1" || hops[0].RTTMs != 1 {
		t.Errorf("unexpected hop 1: %+v", hops[0])
	}
	if hops[1].TTL != 2 || !hops[1].Timeout {
		t.Errorf("unexpected hop 2: %+v", hops[1])
	}
	if hops[2].TTL != 3 || hops[2].IP != "1.1.1.1" || hops[2].RTTMs != 13 {
		t.Errorf("unexpected hop 3: %+v", hops[2])
	}
}

func TestRound2(t *testing.T) {
	if got := round2(-1.23); got != 0 {
		t.Errorf("round2(-1.23) = %v, want 0", got)
	}
	if got := round2(1.235); got != 1.24 {
		t.Errorf("round2(1.235) = %v, want 1.24", got)
	}
	if got := round2(0); got != 0 {
		t.Errorf("round2(0) = %v, want 0", got)
	}
}

func TestOSPingSweepCanceled(t *testing.T) {
	s := NewICMPScanner(Config{
		Timeout:         100 * time.Millisecond,
		Concurrency:     2,
		ForceOSFallback: true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := s.PingSweep(ctx, []net.IP{net.ParseIP("127.0.0.1")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got err=%v, res=%v", err, res)
	}
}
