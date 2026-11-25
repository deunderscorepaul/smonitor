package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/smonitor/smonitor/internal/api"
	"github.com/smonitor/smonitor/internal/cli"
	"github.com/smonitor/smonitor/internal/config"
	"github.com/smonitor/smonitor/internal/coordinator"
	"github.com/smonitor/smonitor/internal/model"
	"github.com/smonitor/smonitor/internal/scanner"
	"github.com/smonitor/smonitor/internal/storage"
)

var version = "1.0.0"

func main() {
	flagDaemon := flag.Bool("daemon", false, "Run continuous periodic scanner and REST API server")
	flagScanOnce := flag.Bool("scan-once", false, "Perform a single ping + traceroute scan across configured ranges")
	flagList := flag.Bool("list", false, "List all monitored hosts from SQLite database")
	flagEvents := flag.Bool("events", false, "List recent online/offline lifecycle events from SQLite database")
	flagJSON := flag.Bool("json", false, "Output results in JSON format")

	flagTraceroute := flag.String("traceroute", "", "Run a single traceroute to the specified IPv4 address")
	flagSetNoteIP := flag.String("set-note", "", "Set description/note for a host by IPv4 address")
	flagNotes := flag.String("notes", "", "Note text (used with --set-note)")

	flagRanges := flag.String("ranges", "ranges.json", "Path to JSON file containing [[startIP, endIP], ...] pairs")
	flagDB := flag.String("db", "smonitor.db", "Path to SQLite database file (WAL mode)")
	flagPort := flag.String("port", ":8080", "REST API listen address (e.g. :8080 or 127.0.0.1:8080)")
	flagToken := flag.String("api-token", "", "Optional Bearer / X-API-Key token for REST API")
	flagInterval := flag.Duration("interval", 2*time.Minute, "Periodic scan interval in daemon mode")
	flagTimeout := flag.Duration("timeout", 1*time.Second, "Timeout per ICMP ping / traceroute hop")
	flagMaxHops := flag.Int("max-hops", 15, "Maximum TTL hops for traceroute")
	flagConcurrency := flag.Int("concurrency", 32, "Worker concurrency limit for fallback probing")
	flagVersion := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *flagVersion {
		fmt.Printf("smonitor %s (Static Go Network Monitor & Scanner)\n", version)
		os.Exit(0)
	}

	store, err := storage.NewSQLiteStorage(*flagDB)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize SQLite at %s: %v", *flagDB, err)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle setting notes on an existing host
	if *flagSetNoteIP != "" {
		parsed := net.ParseIP(*flagSetNoteIP)
		if parsed == nil || parsed.To4() == nil {
			log.Fatalf("[ERROR] Invalid IPv4 address: %q", *flagSetNoteIP)
		}
		canonicalIP := parsed.To4().String()
		if err := store.SetNotes(ctx, canonicalIP, *flagNotes); err != nil {
			log.Fatalf("[ERROR] Failed to set notes for %s: %v", canonicalIP, err)
		}
		fmt.Printf("Notes for host %s updated to: %q\n", canonicalIP, *flagNotes)
		return
	}

	// Handle listing stored hosts
	if *flagList {
		hosts, err := store.ListHosts(ctx, nil)
		if err != nil {
			log.Fatalf("[ERROR] Failed to list hosts: %v", err)
		}
		if hosts == nil {
			hosts = []model.Host{}
		}
		if *flagJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(hosts)
			return
		}
		cli.PrintHostTable(os.Stdout, hosts)
		if m, err := store.GetMetrics(ctx); err == nil {
			cli.PrintMetricsSummary(os.Stdout, m)
		}
		return
	}

	// Handle listing recent reachability events
	if *flagEvents {
		events, err := store.GetRecentEvents(ctx, 50)
		if err != nil {
			log.Fatalf("[ERROR] Failed to list events: %v", err)
		}
		if events == nil {
			events = []model.HostEvent{}
		}
		if *flagJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(events)
			return
		}
		for _, ev := range events {
			fmt.Printf("%s  %-10s  %-15s  %s\n",
				ev.Timestamp.Local().Format("2006-01-02 15:04:05"),
				ev.EventType,
				ev.IPAddress,
				ev.Details,
			)
		}
		return
	}

	// Initialize ICMP Scanner Engine
	engine := scanner.NewICMPScanner(scanner.Config{
		Timeout:     *flagTimeout,
		MaxHops:     *flagMaxHops,
		Concurrency: *flagConcurrency,
	})
	coord := coordinator.NewCoordinator(*flagRanges, engine, store, *flagInterval)

	// Handle single targeted traceroute
	if *flagTraceroute != "" {
		parsed := net.ParseIP(*flagTraceroute)
		if parsed == nil || parsed.To4() == nil {
			log.Fatalf("[ERROR] Invalid IPv4 address for traceroute: %q", *flagTraceroute)
		}
		hops, err := coord.RunTraceroute(ctx, parsed.To4())
		if err != nil {
			log.Fatalf("[ERROR] Traceroute failed: %v", err)
		}
		if *flagJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]interface{}{
				"ip":        parsed.To4().String(),
				"hop_count": len(hops),
				"hops":      hops,
			})
			return
		}
		cli.PrintTracerouteTable(os.Stdout, parsed.To4().String(), hops)
		return
	}

	if !*flagDaemon && !*flagScanOnce {
		printUsage()
		return
	}

	// Validate ranges file early before running scan/daemon
	targets, ranges, err := config.LoadRangesFile(*flagRanges)
	if err != nil {
		log.Fatalf("[FATAL] Invalid ranges configuration (%s): %v", *flagRanges, err)
	}
	log.Printf("[INIT] Loaded %d IP(s) from %d range(s) in %s | SQLite DB: %s", len(targets), len(ranges), *flagRanges, *flagDB)

	// Handle single scan (--scan-once)
	if *flagScanOnce {
		metrics, err := coord.RunScan(ctx)
		if err != nil {
			log.Fatalf("[FATAL] Scan failed: %v", err)
		}
		hosts, err := store.ListHosts(ctx, nil)
		if err != nil {
			log.Fatalf("[ERROR] Failed to query hosts: %v", err)
		}

		if *flagJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]interface{}{
				"metrics": metrics,
				"hosts":   hosts,
			})
			return
		}

		cli.PrintHostTable(os.Stdout, hosts)
		cli.PrintMetricsSummary(os.Stdout, metrics)
		return
	}

	// Daemon mode (--daemon)
	if *flagDaemon {
		if *flagInterval <= 0 {
			log.Fatalf("[FATAL] --interval must be positive, got %s", *flagInterval)
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		var loopWg sync.WaitGroup
		loopWg.Add(1)
		go func() {
			defer loopWg.Done()
			coord.StartBackgroundLoop(ctx)
		}()

		apiServer := api.NewServer(api.Config{
			ListenAddr: *flagPort,
			APIToken:   *flagToken,
			Storage:    store,
			TriggerScan: func(reqCtx context.Context) (*model.NetworkMetrics, error) {
				mergedCtx, stop := deriveRequestContext(ctx, reqCtx)
				defer stop()
				return coord.RunScan(mergedCtx)
			},
			TriggerTrace: func(reqCtx context.Context, ip net.IP) ([]model.Hop, error) {
				mergedCtx, stop := deriveRequestContext(ctx, reqCtx)
				defer stop()
				return coord.RunTraceroute(mergedCtx, ip)
			},
			GetMetricsFn: func() *model.NetworkMetrics {
				return coord.GetLatestMetrics()
			},
		})

		go func() {
			if err := apiServer.Start(); err != nil {
				log.Fatalf("[FATAL] REST API server error: %v", err)
			}
		}()

		log.Printf("[DAEMON] Smonitor running (interval=%s, api=%s). Press Ctrl+C to stop.", *flagInterval, *flagPort)
		sig := <-sigChan
		log.Printf("[DAEMON] Signal %v received. Shutting down...", sig)

		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = apiServer.Shutdown(shutdownCtx)
		loopWg.Wait()
		log.Println("[DAEMON] Shutdown complete.")
	}
}

// deriveRequestContext creates a context canceled when either the daemon parent or the HTTP request context ends.
func deriveRequestContext(parent, reqCtx context.Context) (context.Context, context.CancelFunc) {
	derived, cancel := context.WithCancel(reqCtx)
	stop := context.AfterFunc(parent, cancel)
	return derived, func() {
		stop()
		cancel()
	}
}

func printUsage() {
	fmt.Println("smonitor - Dependency-free Network Monitor & Scanner")
	fmt.Println("Usage:")
	fmt.Println("  smonitor --scan-once --ranges ranges.json     Scan all configured IP ranges once")
	fmt.Println("  smonitor --daemon --ranges ranges.json        Run periodic scans + REST API server")
	fmt.Println("  smonitor --traceroute <IP>                    Run traceroute to an IPv4 address")
	fmt.Println("  smonitor --list                               Show all recorded hosts from SQLite")
	fmt.Println("  smonitor --events                             Show online/offline lifecycle log")
	fmt.Println("  smonitor --set-note <IP> --notes \"Router\"     Set note for a stored host")
	fmt.Println("\nRun 'smonitor --help' for all flags.")
}
