package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/smonitor/smonitor/internal/model"
)

func TestHostLifecycleAndLastReachablePreservation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "smonitor-test.db")
	store, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// 1. Insert reachable host with traceroute hops
	h1 := &model.Host{
		IPAddress: "192.168.1.10",
		Hostname:  "pi-server",
		RTTMs:     1.42,
		LastRoute: []model.Hop{
			{TTL: 1, IP: "192.168.1.1", RTTMs: 0.8},
			{TTL: 2, IP: "192.168.1.10", RTTMs: 1.42},
		},
	}

	isNew, cameOnline, err := store.UpsertOnlineHost(ctx, h1)
	if err != nil {
		t.Fatalf("UpsertOnlineHost failed: %v", err)
	}
	if !isNew || cameOnline {
		t.Fatalf("expected isNew=true, cameOnline=false; got isNew=%v, cameOnline=%v", isNew, cameOnline)
	}
	_ = store.RecordEvent(ctx, h1.IPAddress, model.EventDiscovered, "Host discovered")

	saved, err := store.GetHost(ctx, h1.IPAddress)
	if err != nil || saved == nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if !saved.IsOnline || saved.HopCount != 2 || len(saved.LastRoute) != 2 {
		t.Fatalf("unexpected saved host: %+v", saved)
	}
	lastReachable := saved.LastSeen

	// Small pause to distinguish offline timestamp from last_seen
	time.Sleep(25 * time.Millisecond)

	// 2. Host disappears in next scan -> mark offline while preserving last_seen
	goneOffline, err := store.MarkOfflineExcept(ctx, map[string]bool{})
	if err != nil {
		t.Fatalf("MarkOfflineExcept failed: %v", err)
	}
	if len(goneOffline) != 1 || goneOffline[0].IPAddress != h1.IPAddress {
		t.Fatalf("expected 1 offline host (%s), got %+v", h1.IPAddress, goneOffline)
	}

	afterOffline, err := store.GetHost(ctx, h1.IPAddress)
	if err != nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if afterOffline.IsOnline {
		t.Fatal("expected host to be marked offline")
	}
	if !afterOffline.LastSeen.Equal(lastReachable) {
		t.Fatalf("expected last_seen to remain %v when offline, got %v", lastReachable, afterOffline.LastSeen)
	}
	if afterOffline.LastOffline == nil || !afterOffline.LastOffline.After(lastReachable) {
		t.Fatalf("expected last_offline after last_seen, got %v", afterOffline.LastOffline)
	}

	// 3. Host comes back online
	time.Sleep(15 * time.Millisecond)
	isNew, cameOnline, err = store.UpsertOnlineHost(ctx, h1)
	if err != nil {
		t.Fatalf("UpsertOnlineHost failed: %v", err)
	}
	if isNew || !cameOnline {
		t.Fatalf("expected isNew=false, cameOnline=true; got isNew=%v, cameOnline=%v", isNew, cameOnline)
	}

	// 4. Verify metrics and notes
	if err := store.SetNotes(ctx, h1.IPAddress, "DNS Server"); err != nil {
		t.Fatalf("SetNotes failed: %v", err)
	}
	m, err := store.GetMetrics(ctx)
	if err != nil {
		t.Fatalf("GetMetrics failed: %v", err)
	}
	if m.TotalHosts != 1 || m.OnlineHosts != 1 || m.OfflineHosts != 0 {
		t.Fatalf("unexpected metrics: %+v", m)
	}

	events, err := store.GetRecentEvents(ctx, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("expected 1 event, got %d (err=%v)", len(events), err)
	}

	// 5. Updating online host with empty LastRoute preserves previously stored route
	h1NoRoute := &model.Host{
		IPAddress: "192.168.1.10",
		Hostname:  "pi-server",
		RTTMs:     1.10,
		LastRoute: nil,
	}
	if _, _, err := store.UpsertOnlineHost(ctx, h1NoRoute); err != nil {
		t.Fatalf("UpsertOnlineHost with empty route failed: %v", err)
	}
	preserved, err := store.GetHost(ctx, h1.IPAddress)
	if err != nil {
		t.Fatalf("GetHost after empty route failed: %v", err)
	}
	if preserved.HopCount != 2 || len(preserved.LastRoute) != 2 {
		t.Fatalf("expected stored route (2 hops) to be preserved, got hop_count=%d route=%+v", preserved.HopCount, preserved.LastRoute)
	}
	if preserved.RTTMs != 1.10 {
		t.Fatalf("expected RTTMs to update to 1.10, got %v", preserved.RTTMs)
	}
}
