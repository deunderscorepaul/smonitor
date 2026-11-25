package cli

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/smonitor/smonitor/internal/model"
)

// PrintHostTable outputs a clear tabular overview of monitored network hosts.
func PrintHostTable(w io.Writer, hosts []model.Host) {
	if w == nil {
		w = os.Stdout
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tIP ADDRESS\tHOSTNAME\tRTT\tHOPS\tNOTES\tFIRST SEEN\tLAST REACHABLE\tLAST OFFLINE")
	fmt.Fprintln(tw, "------\t----------\t--------\t---\t----\t-----\t----------\t--------------\t------------")

	for _, h := range hosts {
		status := "ONLINE"
		if !h.IsOnline {
			status = "OFFLINE"
		}

		hostname := truncate(h.Hostname, 22, "-")
		notes := truncate(h.Notes, 20, "-")
		rtt := fmt.Sprintf("%.2f ms", h.RTTMs)
		if !h.IsOnline {
			rtt = "-"
		}

		firstSeen := h.FirstSeen.Local().Format("2006-01-02 15:04")
		lastReachable := h.LastSeen.Local().Format("2006-01-02 15:04:05")
		lastOffline := "-"
		if h.LastOffline != nil {
			lastOffline = h.LastOffline.Local().Format("2006-01-02 15:04:05")
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			status,
			h.IPAddress,
			hostname,
			rtt,
			h.HopCount,
			notes,
			firstSeen,
			lastReachable,
			lastOffline,
		)
	}

	_ = tw.Flush()
}

// PrintTracerouteTable prints hop-by-hop traceroute results.
func PrintTracerouteTable(w io.Writer, target string, hops []model.Hop) {
	if w == nil {
		w = os.Stdout
	}

	fmt.Fprintf(w, "Traceroute to %s (%d hops):\n", target, len(hops))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOP\tIP ADDRESS\tRTT")
	fmt.Fprintln(tw, "---\t----------\t---")

	for _, hop := range hops {
		if hop.Timeout || hop.IP == "" {
			fmt.Fprintf(tw, "%d\t*\t*\n", hop.TTL)
			continue
		}
		fmt.Fprintf(tw, "%d\t%s\t%.2f ms\n", hop.TTL, hop.IP, hop.RTTMs)
	}

	_ = tw.Flush()
}

// PrintMetricsSummary prints an aggregated inventory summary.
func PrintMetricsSummary(w io.Writer, m *model.NetworkMetrics) {
	if w == nil {
		w = os.Stdout
	}

	fmt.Fprintln(w, "\n--- NETWORK MONITOR SUMMARY ---")
	fmt.Fprintf(w, "Total Hosts:         %d\n", m.TotalHosts)
	fmt.Fprintf(w, "Online (Reachable):  %d\n", m.OnlineHosts)
	fmt.Fprintf(w, "Offline:             %d\n", m.OfflineHosts)
	fmt.Fprintf(w, "New Hosts (24h):     %d\n", m.NewHosts24h)
	if m.LastScanDurationMs > 0 {
		fmt.Fprintf(w, "Last Scan Duration:  %d ms\n", m.LastScanDurationMs)
	}
	fmt.Fprintln(w, "-------------------------------")
}

func truncate(s string, maxLen int, fallback string) string {
	if s == "" {
		return fallback
	}
	runes := []rune(s)
	if len(runes) > maxLen {
		if maxLen <= 3 {
			return string(runes[:maxLen])
		}
		return string(runes[:maxLen-3]) + "..."
	}
	return s
}
