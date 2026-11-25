package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // Pure-Go SQLite driver (CGO-free static compilation)

	"github.com/smonitor/smonitor/internal/model"
)

// Storage defines the persistence interface for monitored hosts, traceroutes, events, and metrics.
type Storage interface {
	Close() error
	UpsertOnlineHost(ctx context.Context, host *model.Host) (isNew bool, cameOnline bool, err error)
	MarkOfflineExcept(ctx context.Context, activeIPs map[string]bool) ([]model.Host, error)
	UpdateTraceroute(ctx context.Context, ip string, hops []model.Hop) error
	GetHost(ctx context.Context, ip string) (*model.Host, error)
	ListHosts(ctx context.Context, onlineFilter *bool) ([]model.Host, error)
	SetNotes(ctx context.Context, ip string, notes string) error
	RecordEvent(ctx context.Context, ip string, eventType string, details string) error
	GetRecentEvents(ctx context.Context, limit int) ([]model.HostEvent, error)
	GetMetrics(ctx context.Context) (*model.NetworkMetrics, error)
}

type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLiteStorage opens or creates the SQLite database in WAL mode for safe concurrent external reads.
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1) // Optimal writer concurrency for SQLite WAL mode

	s := &SQLiteStorage{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return s, nil
}

func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

func (s *SQLiteStorage) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS hosts (
		ip_address TEXT PRIMARY KEY,
		hostname TEXT DEFAULT '',
		notes TEXT DEFAULT '',
		is_online INTEGER NOT NULL DEFAULT 1,
		rtt_ms REAL NOT NULL DEFAULT 0,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		last_offline DATETIME,
		hop_count INTEGER NOT NULL DEFAULT 0,
		last_route TEXT NOT NULL DEFAULT '[]'
	);

	CREATE TABLE IF NOT EXISTS host_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_address TEXT NOT NULL,
		event_type TEXT NOT NULL,
		details TEXT,
		timestamp DATETIME NOT NULL,
		FOREIGN KEY(ip_address) REFERENCES hosts(ip_address) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_hosts_is_online ON hosts(is_online);
	CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen);
	CREATE INDEX IF NOT EXISTS idx_host_events_timestamp ON host_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_host_events_ip ON host_events(ip_address);
	`
	_, err := s.db.Exec(schema)
	return err
}

// UpsertOnlineHost registers a newly reachable host or refreshes last_seen, RTT, and route of an existing host.
func (s *SQLiteStorage) UpsertOnlineHost(ctx context.Context, host *model.Host) (isNew bool, cameOnline bool, err error) {
	ip := strings.TrimSpace(host.IPAddress)
	now := time.Now().UTC()

	routeJSON := "[]"
	if len(host.LastRoute) > 0 {
		if encoded, mErr := json.Marshal(host.LastRoute); mErr == nil {
			routeJSON = string(encoded)
		}
	}
	hopCount := len(host.LastRoute)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, false, fmt.Errorf("failed to begin transaction for host %s: %w", ip, err)
	}
	defer func() { _ = tx.Rollback() }()

	var wasOnline int
	err = tx.QueryRowContext(ctx, "SELECT is_online FROM hosts WHERE ip_address = ?", ip).Scan(&wasOnline)

	if err == sql.ErrNoRows {
		isNew = true
		host.IPAddress = ip
		host.IsOnline = true
		host.FirstSeen = now
		host.LastSeen = now
		host.HopCount = hopCount

		query := `
		INSERT INTO hosts (
			ip_address, hostname, notes, is_online, rtt_ms,
			first_seen, last_seen, hop_count, last_route
		) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)`

		_, err = tx.ExecContext(ctx, query,
			ip, host.Hostname, host.Notes, host.RTTMs,
			now, now, hopCount, routeJSON,
		)
		if err != nil {
			return false, false, fmt.Errorf("failed to insert new host %s: %w", ip, err)
		}
		if err := tx.Commit(); err != nil {
			return false, false, fmt.Errorf("failed to commit insert for host %s: %w", ip, err)
		}
		return true, false, nil
	} else if err != nil {
		return false, false, fmt.Errorf("failed to query host %s: %w", ip, err)
	}

	cameOnline = (wasOnline == 0)

	updateQuery := `
	UPDATE hosts SET
		hostname = CASE WHEN ? != '' THEN ? ELSE hostname END,
		is_online = 1,
		rtt_ms = ?,
		last_seen = ?,
		hop_count = CASE WHEN ? > 0 THEN ? ELSE hop_count END,
		last_route = CASE WHEN ? > 0 THEN ? ELSE last_route END
	WHERE ip_address = ?`

	_, err = tx.ExecContext(ctx, updateQuery,
		host.Hostname, host.Hostname,
		host.RTTMs,
		now,
		hopCount, hopCount,
		hopCount, routeJSON,
		ip,
	)
	if err != nil {
		return false, false, fmt.Errorf("failed to update host %s: %w", ip, err)
	}

	if err := tx.Commit(); err != nil {
		return false, false, fmt.Errorf("failed to commit update for host %s: %w", ip, err)
	}

	return false, cameOnline, nil
}

// MarkOfflineExcept marks previously online hosts not present in activeIPs as offline,
// recording last_offline while preserving last_seen as the last reachable timestamp.
func (s *SQLiteStorage) MarkOfflineExcept(ctx context.Context, activeIPs map[string]bool) ([]model.Host, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT ip_address, hostname, notes, is_online, rtt_ms, first_seen, last_seen, last_offline, hop_count, last_route
		FROM hosts WHERE is_online = 1`)
	if err != nil {
		return nil, err
	}

	var goneOffline []model.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		if !activeIPs[h.IPAddress] {
			goneOffline = append(goneOffline, h)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	if len(goneOffline) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}

	now := time.Now().UTC()
	stmt, err := tx.PrepareContext(ctx, "UPDATE hosts SET is_online = 0, last_offline = ? WHERE ip_address = ?")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	for i := range goneOffline {
		if _, err := stmt.ExecContext(ctx, now, goneOffline[i].IPAddress); err != nil {
			return nil, err
		}
		goneOffline[i].IsOnline = false
		offlineTime := now
		goneOffline[i].LastOffline = &offlineTime
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return goneOffline, nil
}

// UpdateTraceroute updates the stored route for an existing host without modifying online status or last_seen.
func (s *SQLiteStorage) UpdateTraceroute(ctx context.Context, ip string, hops []model.Hop) error {
	routeJSON := "[]"
	if len(hops) > 0 {
		encoded, err := json.Marshal(hops)
		if err != nil {
			return err
		}
		routeJSON = string(encoded)
	}

	_, err := s.db.ExecContext(ctx,
		"UPDATE hosts SET hop_count = ?, last_route = ? WHERE ip_address = ?",
		len(hops), routeJSON, strings.TrimSpace(ip),
	)
	return err
}

func (s *SQLiteStorage) GetHost(ctx context.Context, ip string) (*model.Host, error) {
	query := `
	SELECT ip_address, hostname, notes, is_online, rtt_ms, first_seen, last_seen, last_offline, hop_count, last_route
	FROM hosts WHERE ip_address = ?`

	row := s.db.QueryRowContext(ctx, query, strings.TrimSpace(ip))
	h, err := scanHost(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func (s *SQLiteStorage) ListHosts(ctx context.Context, onlineFilter *bool) ([]model.Host, error) {
	query := `
	SELECT ip_address, hostname, notes, is_online, rtt_ms, first_seen, last_seen, last_offline, hop_count, last_route
	FROM hosts`

	var args []interface{}
	if onlineFilter != nil {
		if *onlineFilter {
			query += " WHERE is_online = 1"
		} else {
			query += " WHERE is_online = 0"
		}
	}
	query += " ORDER BY is_online DESC, last_seen DESC, ip_address ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []model.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
}

func (s *SQLiteStorage) SetNotes(ctx context.Context, ip string, notes string) error {
	res, err := s.db.ExecContext(ctx, "UPDATE hosts SET notes = ? WHERE ip_address = ?", notes, strings.TrimSpace(ip))
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("host %s not found", ip)
	}
	return nil
}

func (s *SQLiteStorage) RecordEvent(ctx context.Context, ip string, eventType string, details string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO host_events (ip_address, event_type, details, timestamp) VALUES (?, ?, ?, ?)",
		strings.TrimSpace(ip), eventType, details, time.Now().UTC(),
	)
	return err
}

func (s *SQLiteStorage) GetRecentEvents(ctx context.Context, limit int) ([]model.HostEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, ip_address, event_type, details, timestamp FROM host_events ORDER BY id DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []model.HostEvent
	for rows.Next() {
		var ev model.HostEvent
		var details sql.NullString
		if err := rows.Scan(&ev.ID, &ev.IPAddress, &ev.EventType, &details, &ev.Timestamp); err != nil {
			return nil, err
		}
		ev.Details = details.String
		events = append(events, ev)
	}
	return events, rows.Err()
}

func (s *SQLiteStorage) GetMetrics(ctx context.Context) (*model.NetworkMetrics, error) {
	m := &model.NetworkMetrics{}
	yesterday := time.Now().UTC().Add(-24 * time.Hour)

	query := `
	SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN is_online = 1 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN first_seen >= ? THEN 1 ELSE 0 END), 0)
	FROM hosts`

	if err := s.db.QueryRowContext(ctx, query, yesterday).Scan(&m.TotalHosts, &m.OnlineHosts, &m.NewHosts24h); err != nil {
		return nil, err
	}
	m.OfflineHosts = m.TotalHosts - m.OnlineHosts

	return m, nil
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanHost(r rowScanner) (model.Host, error) {
	var h model.Host
	var isOnline int
	var hostname, notes, routeJSON sql.NullString
	var lastOffline sql.NullTime

	err := r.Scan(
		&h.IPAddress,
		&hostname,
		&notes,
		&isOnline,
		&h.RTTMs,
		&h.FirstSeen,
		&h.LastSeen,
		&lastOffline,
		&h.HopCount,
		&routeJSON,
	)
	if err != nil {
		return h, err
	}

	h.IsOnline = (isOnline == 1)
	h.Hostname = hostname.String
	h.Notes = notes.String
	if lastOffline.Valid {
		t := lastOffline.Time
		h.LastOffline = &t
	}
	if routeJSON.String != "" {
		_ = json.Unmarshal([]byte(routeJSON.String), &h.LastRoute)
	}
	if h.LastRoute == nil {
		h.LastRoute = []model.Hop{}
	}

	return h, nil
}
