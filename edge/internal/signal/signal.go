// edge/signal — build contract-shaped network Signal envelopes from a fingerprint.
// Emits ja3/ja4 (and browser/os hints when known) as JSON the detector's /ingest accepts.

package signal

import (
	"encoding/json"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
)

// SchemaVersion is the contracts version this edge emits.
const SchemaVersion = "0.1"

// Signal mirrors contracts/signal.schema.json.
type Signal struct {
	SchemaVersion string `json:"schema_version"`
	SessionID     string `json:"session_id"`
	Layer         string `json:"layer"`
	Kind          string `json:"kind"`
	Value         any    `json:"value"`
	Source        string `json:"source"`
	ObservedAt    string `json:"observed_at"`
}

// Network builds one network-layer signal sourced from the edge.
func Network(sessionID, kind string, value any, at time.Time) Signal {
	return Signal{
		SchemaVersion: SchemaVersion,
		SessionID:     sessionID,
		Layer:         "network",
		Kind:          kind,
		Value:         value,
		Source:        "edge",
		ObservedAt:    at.UTC().Format(time.RFC3339),
	}
}

// FromClientHello produces the network signals for a fingerprinted session:
// always ja3 + ja4; browser/os hints only when the fingerprint is known to the table.
func FromClientHello(
	sessionID string,
	ch *fingerprint.ClientHello,
	hints fingerprint.HintTable,
	at time.Time,
) []Signal {
	ja4 := ch.JA4()
	out := []Signal{
		Network(sessionID, "ja3", ch.JA3(), at),
		Network(sessionID, "ja4", ja4, at),
	}
	if hint, ok := hints.Lookup(ja4); ok {
		// Emit each hint only when it carries a real label. A JA4_a+JA4_b prefix entry can classify the
		// TLS engine (browser) without pinning an OS, and emitting a blank/"unknown" os here would
		// falsely feed net.tls_os_vs_tcp_os; guard each independently.
		if hint.Browser != "" && hint.Browser != "unknown" {
			out = append(out, Network(sessionID, "ja4_browser_hint", hint.Browser, at))
		}
		if hint.OS != "" && hint.OS != "unknown" {
			out = append(out, Network(sessionID, "ja4_os_hint", hint.OS, at))
		}
	}
	// Raw wire-order fingerprints JA4 sorts away (the stronger impostor tell — a pinned TLS template emits a
	// fixed/Chrome-impossible order; GREASE normalized to "g" so placement is captured). Appended last so the
	// hint signals keep their positions.
	out = append(out,
		Network(sessionID, "tls_ext_order", ch.ExtOrder(), at),
		Network(sessionID, "tls_cipher_order", ch.CipherOrder(), at),
	)
	// ClientHello micro-tells (N5): ECH/ALPS/padding presence, cert-compression, key_share groups actually
	// sent (vs advertised) — the per-stack surface JA4 doesn't encode. Emitted when present.
	if extras := ch.TLSExtras(); extras != "" {
		out = append(out, Network(sessionID, "tls_extras", extras, at))
	}
	// TLS-resumption ticket id (pre_shared_key / session_ticket). A resumption ticket is client-specific session
	// material, so the same id arriving from distinct source IPs is one TLS identity shared across machines — a
	// coordination binding that survives JA4 rotation AND fp/trace fuzzing (the detector clusters on it).
	if tid := ch.TLSTicketID(); tid != "" {
		out = append(out, Network(sessionID, "tls_ticket_id", tid, at))
	}
	return out
}

// FromH2 produces the network signals for an HTTP/2 connection: the raw Akamai h2 fingerprint plus the
// engine it implies, so the detector can flag an h2 fingerprint that contradicts the UA (or the JA4).
func FromH2(sessionID string, fp fingerprint.H2Fingerprint, at time.Time) []Signal {
	out := []Signal{Network(sessionID, "h2", fp.String(), at)}
	if b := fp.Browser(); b != "unknown" {
		out = append(out, Network(sessionID, "h2_browser_hint", b, at))
	}
	// The SETTINGS-profile engine is a second, independent read of the same connection: when it
	// disagrees with the pseudo-header-order engine the h2 stack is only half-spoofed (net.h2_settings_vs_order).
	if b := fp.SettingsBrowser(); b != "unknown" {
		out = append(out, Network(sessionID, "h2_settings_hint", b, at))
	}
	return out
}

// Marshal serialises a batch of signals to the JSON array /ingest expects.
func Marshal(signals []Signal) ([]byte, error) {
	return json.Marshal(signals)
}
