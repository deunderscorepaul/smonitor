package coordinator

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smonitor/smonitor/internal/model"
	"github.com/smonitor/smonitor/internal/scanner"
	"github.com/smonitor/smonitor/internal/storage"
)

type mockEngine struct {
	reachable map[string]float64
	routes    map[string][]model.Hop
}

func (m *mockEngine) PingSweep(_ context.Context, targets []net.IP) ([]scanner.PingResult, error) {
	var out []scanner.PingResult
	for _, ip := range targets {
		if rtt, ok := m.reachable[ip.String()]; ok {
			out = append(out, scanner.PingResult{
				IP:       ip,
				Hostname: "host-" + strings.ReplaceAll(ip.String(), ".", "-"),
				RTTMs:    rtt,
			})
		}
	}
	return out, nil
}

func (m *mockEngine) Traceroute(_ context.Context, target net.IP) ([]model.Hop, error) {
	return m.routes[target.String()], nil
}

func TestCoordinatorScanAndOfflineTransition(t *testing.T) {
	dir := t.TempDir()
	rangesPath := filepath.Join(dir, "ranges.json")
	dbPath := filepath.Join(dir, "test.db")

	if err := os.WriteFile(rangesPath, []byte(`[["10.0.0.1", "10.0.0.3"]]`), 0644); err != nil {
		t.Fatal(err)
	}

	store, err := storage.NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	engine := &mockEngine{
		reachable: map[string]float64{
			"10.0.0.1": 1.5,
			"10.0.0.2": 2.3,
		},
		routes: map[string][]model.Hop{
			"10.0.0.1": {{TTL: 1, IP: "10.0.0.1", RTTMs: 1.5}},
			"10.0.0.2": {{TTL: 1, IP: "10.0.0.1", RTTMs: 1.0}, {TTL: 2, IP: "10.0.0.2", RTTMs: 2.3}},
		},
	}

	coord := NewCoordinator(rangesPath, engine, store, time.Minute)
	ctx := context.Background()

	// First scan: 2 reachable hosts stored
	m1, err := coord.RunScan(ctx)
	if err != nil {
		t.Fatalf("first RunScan failed: %v", err)
	}
	if m1.TotalHosts != 2 || m1.OnlineHosts != 2 || m1.OfflineHosts != 0 {
		t.Fatalf("unexpected metrics after scan 1: %+v", m1)
	}

	h2Before, _ := store.GetHost(ctx, "10.0.0.2")
	lastReachable := h2Before.LastSeen

	time.Sleep(20 * time.Millisecond)

	// Second scan: 10.0.0.2 goes offline
	delete(engine.reachable, "10.0.0.2")
	m2, err := coord.RunScan(ctx)
	if err != nil {
		t.Fatalf("second RunScan failed: %v", err)
	}
	if m2.OnlineHosts != 1 || m2.OfflineHosts != 1 {
		t.Fatalf("unexpected metrics after scan 2: %+v", m2)
	}

	h2After, _ := store.GetHost(ctx, "10.0.0.2")
	if h2After.IsOnline {
		t.Fatal("expected 10.0.0.2 to be offline")
	}
	if !h2After.LastSeen.Equal(lastReachable) {
		t.Fatalf("expected last_seen to stay %v, got %v", lastReachable, h2After.LastSeen)
	}

	events, err := store.GetRecentEvents(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].EventType != model.EventOffline || !strings.Contains(events[0].Details, "last reachable:") {
		t.Fatalf("expected OFFLINE event with last reachable timestamp, got %+v", events)
	}
}

type cancelingEngine struct {
	cancel func()
}

func (c *cancelingEngine) PingSweep(_ context.Context, targets []net.IP) ([]scanner.PingResult, error) {
	// Cancel mid-scan before returning partial results
	c.cancel()
	return nil, nil
}

func (c *cancelingEngine) Traceroute(_ context.Context, _ net.IP) ([]model.Hop, error) {
	return nil, nil
}

func TestCoordinatorScanCancellationPreservesOnlineState(t *testing.T) {
	dir := t.TempDir()
	rangesPath := filepath.Join(dir, "ranges.json")
	dbPath := filepath.Join(dir, "cancel-test.db")

	if err := os.WriteFile(rangesPath, []byte(`[["10.0.0.1", "10.0.0.1"]]`), 0644); err != nil {
		t.Fatal(err)
	}

	store, err := storage.NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Seed an online host
	_, _, err = store.UpsertOnlineHost(context.Background(), &model.Host{
		IPAddress: "10.0.0.1",
		RTTMs:     1.0,
		LastRoute: []model.Hop{{TTL: 1, IP: "10.0.0.1", RTTMs: 1.0}},
	})
	if err != nil {
		t.Fatal(err)
	}

	scanCtx, cancel := context.WithCancel(context.Background())
	coord := NewCoordinator(rangesPath, &cancelingEngine{cancel: cancel}, store, time.Minute)

	_, err = coord.RunScan(scanCtx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Host must still be online because scan was canceled before reconciliation
	h, err := store.GetHost(context.Background(), "10.0.0.1")
	if err != nil || h == nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if !h.IsOnline {
		t.Fatal("expected 10.0.0.1 to remain online when scan is canceled")
	}
}
