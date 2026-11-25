package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smonitor/smonitor/internal/model"
	"github.com/smonitor/smonitor/internal/storage"
)

func TestAPIServer(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "api-test.db")
	store, err := storage.NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	_, _, _ = store.UpsertOnlineHost(ctx, &model.Host{
		IPAddress: "192.168.1.100",
		Hostname:  "nas-box",
		RTTMs:     1.2,
		LastRoute: []model.Hop{{TTL: 1, IP: "192.168.1.100", RTTMs: 1.2}},
	})

	server := NewServer(Config{
		ListenAddr: ":0",
		APIToken:   "test-secret-token",
		Storage:    store,
		TriggerTrace: func(_ context.Context, ip net.IP) ([]model.Hop, error) {
			return []model.Hop{{TTL: 1, IP: ip.String(), RTTMs: 0.9}}, nil
		},
	})

	// 1. /healthz unauthenticated
	reqHealth := httptest.NewRequest("GET", "/healthz", nil)
	rrHealth := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rrHealth, reqHealth)
	if rrHealth.Code != http.StatusOK {
		t.Fatalf("expected 200 for /healthz, got %d", rrHealth.Code)
	}

	// 2. /api/v1/metrics without token -> 401
	reqNoAuth := httptest.NewRequest("GET", "/api/v1/metrics", nil)
	rrNoAuth := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rrNoAuth, reqNoAuth)
	if rrNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rrNoAuth.Code)
	}

	// 3. /api/v1/metrics with Bearer Token -> 200
	reqAuth := httptest.NewRequest("GET", "/api/v1/metrics", nil)
	reqAuth.Header.Set("Authorization", "Bearer test-secret-token")
	rrAuth := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rrAuth, reqAuth)
	if rrAuth.Code != http.StatusOK || !strings.Contains(rrAuth.Body.String(), `"online_hosts":1`) {
		t.Fatalf("unexpected metrics response: code=%d body=%s", rrAuth.Code, rrAuth.Body.String())
	}

	// 4. Update notes
	reqNotes := httptest.NewRequest("POST", "/api/v1/hosts/192.168.1.100/notes", strings.NewReader(`{"notes":"Home NAS"}`))
	reqNotes.Header.Set("Authorization", "Bearer test-secret-token")
	rrNotes := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rrNotes, reqNotes)
	if rrNotes.Code != http.StatusOK {
		t.Fatalf("expected 200 on setting notes, got %d: %s", rrNotes.Code, rrNotes.Body.String())
	}
	saved, _ := store.GetHost(ctx, "192.168.1.100")
	if saved.Notes != "Home NAS" {
		t.Fatalf("expected notes 'Home NAS', got %q", saved.Notes)
	}

	// 5. On-demand traceroute
	reqTrace := httptest.NewRequest("POST", "/api/v1/traceroute/192.168.1.100", nil)
	reqTrace.Header.Set("X-API-Key", "test-secret-token")
	rrTrace := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rrTrace, reqTrace)
	if rrTrace.Code != http.StatusOK || !strings.Contains(rrTrace.Body.String(), `"hop_count":1`) {
		t.Fatalf("unexpected traceroute response: code=%d body=%s", rrTrace.Code, rrTrace.Body.String())
	}

	// 6. Invalid JSON body on notes returns 400 and preserves existing notes
	reqBadNotes := httptest.NewRequest("POST", "/api/v1/hosts/192.168.1.100/notes", strings.NewReader(`{invalid`))
	reqBadNotes.Header.Set("Authorization", "Bearer test-secret-token")
	rrBadNotes := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rrBadNotes, reqBadNotes)
	if rrBadNotes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON notes, got %d", rrBadNotes.Code)
	}
	saved, _ = store.GetHost(ctx, "192.168.1.100")
	if saved.Notes != "Home NAS" {
		t.Fatalf("expected notes to stay 'Home NAS' after invalid JSON, got %q", saved.Notes)
	}

	// 7. IPv6 rejected with 400 on host endpoints
	reqIPv6 := httptest.NewRequest("GET", "/api/v1/hosts/::1", nil)
	reqIPv6.Header.Set("Authorization", "Bearer test-secret-token")
	rrIPv6 := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rrIPv6, reqIPv6)
	if rrIPv6.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for IPv6 host lookup, got %d", rrIPv6.Code)
	}

	// 8. Events query with large limit succeeds (capped cleanly at 1000)
	_ = store.RecordEvent(ctx, "192.168.1.100", model.EventDiscovered, "test event")
	reqEvents := httptest.NewRequest("GET", "/api/v1/events?limit=99999", nil)
	reqEvents.Header.Set("Authorization", "Bearer test-secret-token")
	rrEvents := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rrEvents, reqEvents)
	if rrEvents.Code != http.StatusOK || !strings.Contains(rrEvents.Body.String(), `"test event"`) {
		t.Fatalf("unexpected events response: code=%d body=%s", rrEvents.Code, rrEvents.Body.String())
	}
}
