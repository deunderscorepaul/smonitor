package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/smonitor/smonitor/internal/model"
)

var (
	rePingRTT    = regexp.MustCompile(`(?i)(?:time|zeit)\s*([=<])\s*(\d+(?:[.,]\d+)?)\s*ms`)
	rePingTTL    = regexp.MustCompile(`(?i)\bttl\s*=\s*\d+`)
	reHopLine    = regexp.MustCompile(`^\s*(\d+)\s+(.+)$`)
	reIPv4       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reTraceRTT   = regexp.MustCompile(`(<?\s*\d+(?:[.,]\d+)?)\s*ms`)
)

func (s *ICMPScanner) osPingSweep(ctx context.Context, targets []net.IP) ([]PingResult, error) {
	concurrency := s.cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 32
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []PingResult
	)
	sem := make(chan struct{}, concurrency)

sendLoop:
	for _, ip := range targets {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
			break sendLoop
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(targetIP net.IP) {
			defer func() {
				<-sem
				wg.Done()
			}()

			rtt, ok := osPingOne(ctx, targetIP.String(), s.cfg.Timeout)
			if !ok {
				return
			}

			hostname := ResolveHostname(ctx, targetIP.String(), 300*time.Millisecond)
			mu.Lock()
			results = append(results, PingResult{
				IP:       targetIP,
				Hostname: hostname,
				RTTMs:    rtt,
			})
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func osPingOne(ctx context.Context, ip string, timeout time.Duration) (float64, bool) {
	if timeout <= 0 {
		timeout = time.Second
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		ms := int(timeout.Milliseconds())
		if ms < 100 {
			ms = 100
		}
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.Itoa(ms), ip)
	} else {
		sec := int((timeout + 999*time.Millisecond) / time.Second)
		if sec < 1 {
			sec = 1
		}
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(sec), ip)
	}

	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsedMs := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return 0, false
	}

	return parseOSPingOutput(string(out), elapsedMs)
}

func parseOSPingOutput(output string, fallbackRTTMs float64) (float64, bool) {
	lower := strings.ToLower(output)
	if strings.Contains(lower, "unreachable") ||
		strings.Contains(lower, "nicht erreichbar") ||
		strings.Contains(lower, "100% loss") ||
		strings.Contains(lower, "100% packet loss") ||
		strings.Contains(lower, "100% verlust") {
		return 0, false
	}

	if m := rePingRTT.FindStringSubmatch(output); len(m) == 3 {
		if m[1] == "<" {
			return 0.5, true
		}
		numStr := strings.ReplaceAll(m[2], ",", ".")
		if val, err := strconv.ParseFloat(numStr, 64); err == nil {
			return val, true
		}
	}

	if rePingTTL.MatchString(output) {
		return fallbackRTTMs, true
	}

	return 0, false
}

func (s *ICMPScanner) osTraceroute(ctx context.Context, target net.IP) ([]model.Hop, error) {
	maxHops := s.cfg.MaxHops
	if maxHops <= 0 {
		maxHops = 15
	}
	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		ms := int(timeout.Milliseconds())
		if ms < 100 {
			ms = 100
		}
		cmd = exec.CommandContext(ctx, "tracert", "-d", "-h", strconv.Itoa(maxHops), "-w", strconv.Itoa(ms), target.String())
	} else {
		sec := int((timeout + 999*time.Millisecond) / time.Second)
		if sec < 1 {
			sec = 1
		}
		if _, err := exec.LookPath("traceroute"); err == nil {
			cmd = exec.CommandContext(ctx, "traceroute", "-n", "-q", "1", "-m", strconv.Itoa(maxHops), "-w", strconv.Itoa(sec), target.String())
		} else {
			cmd = exec.CommandContext(ctx, "tracepath", "-n", "-m", strconv.Itoa(maxHops), target.String())
		}
	}

	out, err := cmd.CombinedOutput()
	hops := parseOSTracerouteOutput(string(out))
	if len(hops) == 0 && err != nil {
		return nil, fmt.Errorf("OS traceroute command failed: %w", err)
	}
	return hops, nil
}

func parseOSTracerouteOutput(output string) []model.Hop {
	var hops []model.Hop
	sc := bufio.NewScanner(bytes.NewBufferString(output))

	for sc.Scan() {
		line := sc.Text()
		m := reHopLine.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}

		ttl, err := strconv.Atoi(m[1])
		if err != nil || ttl <= 0 {
			continue
		}

		rest := m[2]
		ipMatch := reIPv4.FindString(rest)
		if ipMatch == "" {
			hops = append(hops, model.Hop{
				TTL:     ttl,
				Timeout: true,
			})
			continue
		}

		var rtt float64
		if rttMatches := reTraceRTT.FindAllStringSubmatch(rest, -1); len(rttMatches) > 0 {
			var sum float64
			var count int
			for _, rm := range rttMatches {
				rawVal := strings.TrimSpace(rm[1])
				if strings.HasPrefix(rawVal, "<") {
					sum += 0.5
					count++
					continue
				}
				rawVal = strings.ReplaceAll(rawVal, ",", ".")
				if val, err := strconv.ParseFloat(rawVal, 64); err == nil {
					sum += val
					count++
				}
			}
			if count > 0 {
				rtt = float64(int((sum/float64(count))*100+0.5)) / 100.0
			}
		}

		hops = append(hops, model.Hop{
			TTL:   ttl,
			IP:    ipMatch,
			RTTMs: rtt,
		})
	}

	return hops
}
