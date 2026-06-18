// edge/signal/signal_test — tests for network signal construction and JSON shape.
// Asserts contract field names, the edge source, and conditional hint emission.

package signal

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
)

var at = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

func TestNetworkSignalShape(t *testing.T) {
	s := Network("sess", "ja4", "t13d...", at)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema_version", "session_id", "layer", "kind", "value", "source", "observed_at"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing field %q", k)
		}
	}
	if m["layer"] != "network" || m["source"] != "edge" {
		t.Errorf("layer=%v source=%v", m["layer"], m["source"])
	}
	if m["observed_at"] != "2026-06-17T12:00:00Z" {
		t.Errorf("observed_at=%v", m["observed_at"])
	}
}

func TestFromClientHelloWithoutHint(t *testing.T) {
	ch := &fingerprint.ClientHello{Transport: "t", Version: 0x0304, CipherSuites: []uint16{0x1301}}
	sigs := FromClientHello("sess", ch, fingerprint.HintTable{}, at)
	if len(sigs) != 2 {
		t.Fatalf("want 2 signals (ja3, ja4), got %d", len(sigs))
	}
	if sigs[0].Kind != "ja3" || sigs[1].Kind != "ja4" {
		t.Errorf("kinds: %s %s", sigs[0].Kind, sigs[1].Kind)
	}
}

func TestFromClientHelloWithHint(t *testing.T) {
	ch := &fingerprint.ClientHello{Transport: "t", Version: 0x0304, CipherSuites: []uint16{0x1301}}
	table := fingerprint.HintTable{ch.JA4(): {Browser: "chrome", OS: "windows"}}
	sigs := FromClientHello("sess", ch, table, at)
	if len(sigs) != 4 {
		t.Fatalf("want 4 signals, got %d", len(sigs))
	}
	if sigs[2].Kind != "ja4_browser_hint" || sigs[2].Value != "chrome" {
		t.Errorf("browser hint: %+v", sigs[2])
	}
}

func TestFromH2(t *testing.T) {
	fp := fingerprint.H2Fingerprint{
		Settings:          []fingerprint.H2Setting{{ID: 1, Value: 65536}},
		WindowUpdate:      15663105,
		PseudoHeaderOrder: "m,a,s,p",
	}
	sigs := FromH2("sess", fp, at)
	if len(sigs) != 2 || sigs[0].Kind != "h2" || sigs[1].Kind != "h2_browser_hint" {
		t.Fatalf("want h2 + h2_browser_hint, got %+v", sigs)
	}
	if sigs[1].Value != "chrome" {
		t.Errorf("h2_browser_hint = %v, want chrome", sigs[1].Value)
	}
}

func TestFromH2UnknownEngineOmitsHint(t *testing.T) {
	fp := fingerprint.H2Fingerprint{PseudoHeaderOrder: "weird"}
	sigs := FromH2("sess", fp, at)
	if len(sigs) != 1 || sigs[0].Kind != "h2" {
		t.Errorf("want only the raw h2 signal for an unknown engine, got %+v", sigs)
	}
}

func TestFromH2EmitsSettingsHint(t *testing.T) {
	// A coherent Chrome preface: the Chrome SETTINGS profile {1,2,3,4,6} adds an h2_settings_hint.
	fp := fingerprint.H2Fingerprint{
		Settings: []fingerprint.H2Setting{
			{ID: 1, Value: 65536}, {ID: 2, Value: 0}, {ID: 3, Value: 1000},
			{ID: 4, Value: 6291456}, {ID: 6, Value: 262144},
		},
		PseudoHeaderOrder: "m,a,s,p",
	}
	kinds := map[string]string{}
	for _, s := range FromH2("sess", fp, at) {
		if v, ok := s.Value.(string); ok {
			kinds[s.Kind] = v
		}
	}
	if kinds["h2_browser_hint"] != "chrome" || kinds["h2_settings_hint"] != "chrome" {
		t.Errorf("want both hints = chrome, got %+v", kinds)
	}
}

func TestMarshalBatch(t *testing.T) {
	sigs := []Signal{Network("s", "ja3", "x", at)}
	b, err := Marshal(sigs)
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != '[' {
		t.Errorf("expected JSON array, got %s", b)
	}
}
