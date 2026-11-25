package model

import "time"

// Event types for the host reachability audit log.
const (
	EventDiscovered = "DISCOVERED"
	EventOnline     = "ONLINE"
	EventOffline    = "OFFLINE"
)

// Hop represents a single hop observed during an ICMP traceroute.
type Hop struct {
	TTL     int     `json:"ttl"`
	IP      string  `json:"ip,omitempty"`
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Timeout bool    `json:"timeout,omitempty"`
}

// Host represents a reachable (or previously reachable) network device and its tracking state.
type Host struct {
	IPAddress   string     `json:"ip_address"`
	Hostname    string     `json:"hostname"`
	Notes       string     `json:"notes,omitempty"`
	IsOnline    bool       `json:"is_online"`
	RTTMs       float64    `json:"rtt_ms"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	LastOffline *time.Time `json:"last_offline,omitempty"`
	HopCount    int        `json:"hop_count"`
	LastRoute   []Hop      `json:"last_route"`
}

// HostEvent represents an immutable audit log entry for reachability state changes.
type HostEvent struct {
	ID        int64     `json:"id"`
	IPAddress string    `json:"ip_address"`
	EventType string    `json:"event_type"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}

// NetworkMetrics provides aggregated statistics for CLI summaries and REST API clients.
type NetworkMetrics struct {
	TotalHosts         int       `json:"total_hosts"`
	OnlineHosts        int       `json:"online_hosts"`
	OfflineHosts       int       `json:"offline_hosts"`
	NewHosts24h        int       `json:"new_hosts_24h"`
	LastScanDurationMs int64     `json:"last_scan_duration_ms"`
	LastScanTimestamp  time.Time `json:"last_scan_timestamp"`
}
