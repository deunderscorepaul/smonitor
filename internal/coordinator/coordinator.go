package coordinator

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/smonitor/smonitor/internal/config"
	"github.com/smonitor/smonitor/internal/model"
	"github.com/smonitor/smonitor/internal/scanner"
	"github.com/smonitor/smonitor/internal/storage"
)

// Coordinator orchestrates reading IP ranges, running ping sweeps and traceroutes,
// persisting state in SQLite, and recording online/offline lifecycle events.
type Coordinator struct {
	mu            sync.RWMutex
	scanMu        sync.Mutex
	rangesPath    string
	engine        scanner.Engine
	store         storage.Storage
	scanInterval  time.Duration
	traceWorkers  int
	latestMetrics *model.NetworkMetrics
}

// NewCoordinator constructs a new Coordinator.
func NewCoordinator(rangesPath string, engine scanner.Engine, store storage.Storage, scanInterval time.Duration) *Coordinator {
	return &Coordinator{
		rangesPath:   rangesPath,
		engine:       engine,
		store:        store,
		scanInterval: scanInterval,
		traceWorkers: 8,
	}
}

// RunScan loads the configured IP ranges, pings all targets, traces reachable hosts,
// saves them to SQLite, and logs offline transitions with their last reachable timestamp.
func (c *Coordinator) RunScan(ctx context.Context) (*model.NetworkMetrics, error) {
	c.scanMu.Lock()
	defer c.scanMu.Unlock()

	startTime := time.Now()
	targets, ranges, err := config.LoadRangesFile(c.rangesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ranges: %w", err)
	}

	log.Printf("[SCANNER] Starting ping sweep across %d IPs (%d range(s))...", len(targets), len(ranges))

	pingResults, err := c.engine.PingSweep(ctx, targets)
	if err != nil {
		return nil, fmt.Errorf("ping sweep failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Execute traceroute concurrently for all reachable hosts.
	routes := make([][]model.Hop, len(pingResults))
	if len(pingResults) > 0 {
		workers := c.traceWorkers
		if workers <= 0 {
			workers = 8
		}
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup

	traceLoop:
		for i, res := range pingResults {
			if ctx.Err() != nil {
				break
			}
			select {
			case <-ctx.Done():
				break traceLoop
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(idx int, targetIP net.IP) {
				defer func() {
					<-sem
					wg.Done()
				}()
				hops, tErr := c.engine.Traceroute(ctx, targetIP)
				if tErr != nil {
					log.Printf("[WARN] Traceroute failed for %s: %v", targetIP.String(), tErr)
					return
				}
				routes[idx] = hops
			}(i, res.IP)
		}
		wg.Wait()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	activeIPs := make(map[string]bool, len(pingResults))
	for i, res := range pingResults {
		ipStr := res.IP.String()
		activeIPs[ipStr] = true

		host := &model.Host{
			IPAddress: ipStr,
			Hostname:  res.Hostname,
			RTTMs:     res.RTTMs,
			LastRoute: routes[i],
		}

		isNew, cameOnline, err := c.store.UpsertOnlineHost(ctx, host)
		if err != nil {
			log.Printf("[ERROR] Failed to persist host %s: %v", ipStr, err)
			continue
		}

		if isNew {
			details := fmt.Sprintf("Host reachable for the first time (RTT=%.2fms, Hops=%d, Hostname=%s)", res.RTTMs, len(routes[i]), res.Hostname)
			_ = c.store.RecordEvent(ctx, ipStr, model.EventDiscovered, details)
			log.Printf("[HOST] Discovered reachable host: IP=%s RTT=%.2fms Hops=%d Hostname=%q", ipStr, res.RTTMs, len(routes[i]), res.Hostname)
		} else if cameOnline {
			details := fmt.Sprintf("Host reachable again (RTT=%.2fms, Hops=%d)", res.RTTMs, len(routes[i]))
			_ = c.store.RecordEvent(ctx, ipStr, model.EventOnline, details)
			log.Printf("[HOST] Host back online: IP=%s RTT=%.2fms Hops=%d", ipStr, res.RTTMs, len(routes[i]))
		}
	}

	// Mark hosts that did not respond as offline while keeping last_seen intact.
	goneOffline, err := c.store.MarkOfflineExcept(ctx, activeIPs)
	if err != nil {
		log.Printf("[ERROR] Failed to reconcile offline hosts: %v", err)
	} else {
		for _, h := range goneOffline {
			lastReachable := h.LastSeen.UTC().Format(time.RFC3339)
			details := fmt.Sprintf("Host unreachable (last reachable: %s)", lastReachable)
			_ = c.store.RecordEvent(ctx, h.IPAddress, model.EventOffline, details)
			log.Printf("[OFFLINE] Host %s no longer reachable (last reachable: %s)", h.IPAddress, lastReachable)
		}
	}

	duration := time.Since(startTime)
	log.Printf("[SCANNER] Scan completed in %s. Reachable: %d/%d, Went offline: %d.",
		duration.Round(time.Millisecond), len(pingResults), len(targets), len(goneOffline))

	metrics, err := c.store.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	metrics.LastScanDurationMs = duration.Milliseconds()
	metrics.LastScanTimestamp = startTime.UTC()

	c.mu.Lock()
	c.latestMetrics = metrics
	c.mu.Unlock()

	return metrics, nil
}

// RunTraceroute executes a targeted traceroute to ip and updates stored route if the host is known.
func (c *Coordinator) RunTraceroute(ctx context.Context, ip net.IP) ([]model.Hop, error) {
	hops, err := c.engine.Traceroute(ctx, ip)
	if err != nil {
		return nil, err
	}
	_ = c.store.UpdateTraceroute(ctx, ip.String(), hops)
	return hops, nil
}

// StartBackgroundLoop runs periodic scans until ctx is canceled.
func (c *Coordinator) StartBackgroundLoop(ctx context.Context) {
	if _, err := c.RunScan(ctx); err != nil {
		log.Printf("[SCANNER] Initial scan failed: %v", err)
	}

	interval := c.scanInterval
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[SCANNER] Stopping background scan loop.")
			return
		case <-ticker.C:
			if _, err := c.RunScan(ctx); err != nil {
				log.Printf("[SCANNER] Periodic scan failed: %v", err)
			}
		}
	}
}

// GetLatestMetrics returns the metrics from the most recent scan.
func (c *Coordinator) GetLatestMetrics() *model.NetworkMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latestMetrics
}
