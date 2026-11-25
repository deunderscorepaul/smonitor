package config

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// maxIPsPerRange and maxTotalIPs guard against accidental multi-million IP expansions
// (e.g. 0.0.0.0 - 255.255.255.255) that could exhaust memory on a Raspberry Pi.
const (
	maxIPsPerRange = 1 << 20 // 1,048,576 IPs per range
	maxTotalIPs    = 1 << 20 // 1,048,576 IPs combined across all ranges
)

// IPRange represents a parsed inclusive IPv4 start/end pair.
type IPRange struct {
	Start net.IP
	End   net.IP
}

// LoadRangesFile reads a JSON file containing an array of [startIP, endIP] pairs
// and expands all ranges into a deduplicated slice of IPv4 targets.
func LoadRangesFile(path string) ([]net.IP, []IPRange, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read ranges file %q: %w", path, err)
	}
	return ParseRanges(data)
}

// ParseRanges parses JSON data of the form [["start_ip", "end_ip"], ...]
// and expands every pair into an inclusive, deduplicated list of IPv4 addresses.
func ParseRanges(data []byte) ([]net.IP, []IPRange, error) {
	// Strip UTF-8 BOM if present (common when JSON files are created on Windows).
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	var rawPairs [][]string
	if err := json.Unmarshal(data, &rawPairs); err != nil {
		return nil, nil, fmt.Errorf("invalid ranges JSON (expected array of [startIP, endIP] pairs): %w", err)
	}
	if len(rawPairs) == 0 {
		return nil, nil, fmt.Errorf("ranges configuration is empty")
	}

	var parsedRanges []IPRange
	var ips []net.IP
	seen := make(map[uint32]struct{})

	for i, pair := range rawPairs {
		if len(pair) != 2 {
			return nil, nil, fmt.Errorf("range entry %d must contain exactly 2 IP addresses, got %d", i, len(pair))
		}

		startU32, startIP, err := parseIPv4(pair[0])
		if err != nil {
			return nil, nil, fmt.Errorf("range entry %d start IP: %w", i, err)
		}
		endU32, endIP, err := parseIPv4(pair[1])
		if err != nil {
			return nil, nil, fmt.Errorf("range entry %d end IP: %w", i, err)
		}

		if startU32 > endU32 {
			startU32, endU32 = endU32, startU32
			startIP, endIP = endIP, startIP
		}

		count := uint64(endU32-startU32) + 1
		if count > maxIPsPerRange {
			return nil, nil, fmt.Errorf("range entry %d (%s - %s) spans %d IPs, exceeding limit of %d", i, startIP, endIP, count, maxIPsPerRange)
		}

		parsedRanges = append(parsedRanges, IPRange{Start: startIP, End: endIP})

		for cur := startU32; ; cur++ {
			if _, exists := seen[cur]; !exists {
				if len(seen) >= maxTotalIPs {
					return nil, nil, fmt.Errorf("total IP count across all ranges exceeds limit of %d", maxTotalIPs)
				}
				seen[cur] = struct{}{}
				ips = append(ips, uint32ToIPv4(cur))
			}
			if cur == endU32 {
				break
			}
		}
	}

	return ips, parsedRanges, nil
}

func parseIPv4(raw string) (uint32, net.IP, error) {
	trimmed := strings.TrimSpace(raw)
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return 0, nil, fmt.Errorf("invalid IP address %q", raw)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, nil, fmt.Errorf("address %q is not a valid IPv4 address", raw)
	}
	// Copy to guarantee a clean 4-byte slice.
	clean := make(net.IP, net.IPv4len)
	copy(clean, ip4)
	return binary.BigEndian.Uint32(clean), clean, nil
}

func uint32ToIPv4(n uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
