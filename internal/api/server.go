package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/smonitor/smonitor/internal/model"
	"github.com/smonitor/smonitor/internal/storage"
)

// Server provides a lightweight REST API for external integrations alongside the SQLite WAL file.
type Server struct {
	store        storage.Storage
	apiToken     string
	triggerScan  func(ctx context.Context) (*model.NetworkMetrics, error)
	triggerTrace func(ctx context.Context, ip net.IP) ([]model.Hop, error)
	getMetricsFn func() *model.NetworkMetrics
	httpServer   *http.Server
}

// Config defines the configuration for the REST API server.
type Config struct {
	ListenAddr   string
	APIToken     string
	Storage      storage.Storage
	TriggerScan  func(ctx context.Context) (*model.NetworkMetrics, error)
	TriggerTrace func(ctx context.Context, ip net.IP) ([]model.Hop, error)
	GetMetricsFn func() *model.NetworkMetrics
}

// NewServer constructs an HTTP API server with CORS and optional Bearer/API-Key auth.
func NewServer(cfg Config) *Server {
	s := &Server{
		store:        cfg.Storage,
		apiToken:     strings.TrimSpace(cfg.APIToken),
		triggerScan:  cfg.TriggerScan,
		triggerTrace: cfg.TriggerTrace,
		getMetricsFn: cfg.GetMetricsFn,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/v1/metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/v1/hosts", s.handleListHosts)
	mux.HandleFunc("GET /api/v1/hosts/{ip}", s.handleGetHost)
	mux.HandleFunc("POST /api/v1/hosts/{ip}/notes", s.handleSetNotes)
	mux.HandleFunc("GET /api/v1/events", s.handleGetEvents)
	mux.HandleFunc("POST /api/v1/scan", s.handleTriggerScan)
	mux.HandleFunc("POST /api/v1/traceroute/{ip}", s.handleTraceroute)

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s.securityMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

func (s *Server) Start() error {
	log.Printf("[API] Server listening on %s (Auth enabled: %v)", s.httpServer.Addr, s.apiToken != "")
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "application/json")
			next.ServeHTTP(w, r)
			return
		}

		if s.apiToken != "" {
			authHeader := r.Header.Get("Authorization")
			apiKeyHeader := r.Header.Get("X-API-Key")

			token := ""
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			} else if apiKeyHeader != "" {
				token = apiKeyHeader
			}

			if subtle.ConstantTimeCompare([]byte(token), []byte(s.apiToken)) != 1 {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized: invalid or missing API token")
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := s.store.GetMetrics(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if s.getMetricsFn != nil {
		if latest := s.getMetricsFn(); latest != nil {
			metrics.LastScanDurationMs = latest.LastScanDurationMs
			metrics.LastScanTimestamp = latest.LastScanTimestamp
		}
	}

	writeJSON(w, http.StatusOK, metrics)
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	var onlineFilter *bool
	switch strings.ToLower(r.URL.Query().Get("online")) {
	case "true", "1":
		v := true
		onlineFilter = &v
	case "false", "0":
		v := false
		onlineFilter = &v
	}

	hosts, err := s.store.ListHosts(r.Context(), onlineFilter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hosts == nil {
		hosts = []model.Host{}
	}

	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	parsed := net.ParseIP(r.PathValue("ip"))
	if parsed == nil || parsed.To4() == nil {
		writeJSONError(w, http.StatusBadRequest, "valid IPv4 address is required")
		return
	}
	ip := parsed.To4().String()

	host, err := s.store.GetHost(r.Context(), ip)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if host == nil {
		writeJSONError(w, http.StatusNotFound, "host not found")
		return
	}

	writeJSON(w, http.StatusOK, host)
}

type setNotesRequest struct {
	Notes string `json:"notes"`
}

func (s *Server) handleSetNotes(w http.ResponseWriter, r *http.Request) {
	parsed := net.ParseIP(r.PathValue("ip"))
	if parsed == nil || parsed.To4() == nil {
		writeJSONError(w, http.StatusBadRequest, "valid IPv4 address is required")
		return
	}
	ip := parsed.To4().String()

	if r.Body == nil {
		writeJSONError(w, http.StatusBadRequest, "request body is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)

	var req setNotesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}

	if err := s.store.SetNotes(r.Context(), ip, req.Notes); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "notes updated successfully",
		"ip":      ip,
		"notes":   req.Notes,
	})
}

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			if parsed > 1000 {
				parsed = 1000
			}
			limit = parsed
		}
	}

	events, err := s.store.GetRecentEvents(r.Context(), limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []model.HostEvent{}
	}

	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	if s.triggerScan == nil {
		writeJSONError(w, http.StatusNotImplemented, "on-demand scan not configured")
		return
	}

	metrics, err := s.triggerScan(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("scan failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, metrics)
}

func (s *Server) handleTraceroute(w http.ResponseWriter, r *http.Request) {
	if s.triggerTrace == nil {
		writeJSONError(w, http.StatusNotImplemented, "on-demand traceroute not configured")
		return
	}

	ipStr := r.PathValue("ip")
	parsed := net.ParseIP(ipStr)
	if parsed == nil || parsed.To4() == nil {
		writeJSONError(w, http.StatusBadRequest, "valid IPv4 address is required")
		return
	}

	hops, err := s.triggerTrace(r.Context(), parsed.To4())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("traceroute failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ip":        parsed.To4().String(),
		"hop_count": len(hops),
		"hops":      hops,
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
