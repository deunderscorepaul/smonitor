package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRanges_SingleAndMultiple(t *testing.T) {
	raw := `[
		["192.168.1.1", "192.168.1.4"],
		["10.0.0.10", "10.0.0.12"]
	]`

	ips, ranges, err := ParseRanges([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(ranges))
	}

	want := []string{
		"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4",
		"10.0.0.10", "10.0.0.11", "10.0.0.12",
	}
	if len(ips) != len(want) {
		t.Fatalf("expected %d IPs, got %d", len(want), len(ips))
	}
	for i, w := range want {
		if ips[i].String() != w {
			t.Errorf("ip[%d] = %s, want %s", i, ips[i].String(), w)
		}
	}
}

func TestParseRanges_ReversedAndOverlappingDeduplication(t *testing.T) {
	raw := `[
		["192.168.1.5", "192.168.1.3"],
		["192.168.1.4", "192.168.1.6"]
	]`

	ips, _, err := ParseRanges([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"192.168.1.3", "192.168.1.4", "192.168.1.5", "192.168.1.6"}
	if len(ips) != len(want) {
		t.Fatalf("expected %d deduplicated IPs, got %d", len(want), len(ips))
	}
	for i, w := range want {
		if ips[i].String() != w {
			t.Errorf("ip[%d] = %s, want %s", i, ips[i].String(), w)
		}
	}
}

func TestParseRanges_CrossOctetBoundary(t *testing.T) {
	raw := `[["192.168.1.254", "192.168.2.2"]]`
	ips, _, err := ParseRanges([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.168.1.254", "192.168.1.255", "192.168.2.0", "192.168.2.1", "192.168.2.2"}
	if len(ips) != len(want) {
		t.Fatalf("expected %d IPs, got %d", len(want), len(ips))
	}
	for i, w := range want {
		if ips[i].String() != w {
			t.Errorf("ip[%d] = %s, want %s", i, ips[i].String(), w)
		}
	}
}

func TestParseRanges_InvalidInputs(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"empty array", `[]`},
		{"not two elements", `[["192.168.1.1"]]`},
		{"three elements", `[["192.168.1.1", "192.168.1.2", "192.168.1.3"]]`},
		{"invalid ip", `[["192.168.1.999", "192.168.1.2"]]`},
		{"ipv6 rejected", `[["::1", "::2"]]`},
		{"too large range", `[["0.0.0.0", "255.255.255.255"]]`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseRanges([]byte(tc.json)); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestLoadRangesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ranges.json")
	if err := os.WriteFile(path, []byte(`[["127.0.0.1", "127.0.0.2"]]`), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	ips, _, err := LoadRangesFile(path)
	if err != nil {
		t.Fatalf("LoadRangesFile failed: %v", err)
	}
	if len(ips) != 2 || ips[0].String() != "127.0.0.1" || ips[1].String() != "127.0.0.2" {
		t.Fatalf("unexpected ips: %v", ips)
	}
}

func TestParseRanges_UTF8BOM(t *testing.T) {
	raw := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`[["127.0.0.1", "127.0.0.2"]]`)...)
	ips, _, err := ParseRanges(raw)
	if err != nil {
		t.Fatalf("expected UTF-8 BOM JSON to parse cleanly, got %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(ips))
	}
}
