package normalizer

import (
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
)

func newTestNormalizer() *Normalizer {
	return &Normalizer{cfg: &config.Config{NormalizerMode: "strict"}, version: "test"}
}

// A canonical Splunk envelope (what SplunkConnector.fetch_alerts emits) must
// normalize as an OCSF Security Finding with its fields preserved, so the
// fusion promoter promotes it regardless of severity (#528).
func TestSplunkProfileNormalizesNotableAsFinding(t *testing.T) {
	n := newTestNormalizer()
	raw := &RawEvent{
		ConnectorID:   "conn-1",
		ConnectorType: "splunk",
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-08-02T00:00:00Z",
		Payload: map[string]interface{}{
			"source":      "splunk",
			"external_id": "NOTABLE-42",
			"event_id":    "NOTABLE-42",
			"title":       "Brute Force Access Behavior Detected",
			"severity":    "medium",
			"src_ip":      "10.0.0.9",
			"hostname":    "web-01",
			"created_at":  "2026-08-01T23:59:00Z",
			"raw_event":   map[string]interface{}{"_time": "2026-08-01T23:59:00Z"},
		},
	}

	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}
	ocsf := ev.OcsfEvent

	if got := ocsf["class_uid"]; got != 2001 {
		t.Errorf("class_uid = %v, want 2001 (Security Finding)", got)
	}
	if got := ocsf["category_uid"]; got != 2 {
		t.Errorf("category_uid = %v, want 2 (Findings) so the promoter promotes it", got)
	}
	if got := ocsf["severity_id"]; got != 3 {
		t.Errorf("severity_id = %v, want 3 (medium preserved)", got)
	}
	if got := ocsf["message"]; got != "Brute Force Access Behavior Detected" {
		t.Errorf("message = %v, want the rule title", got)
	}
	// hostname -> device.name (nested)
	if dev, ok := ocsf["device"].(map[string]interface{}); !ok || dev["name"] != "web-01" {
		t.Errorf("device.name not preserved: %v", ocsf["device"])
	}
	// external_id must not become empty (the double-normalize regression, #528)
	if finding, ok := ocsf["finding"].(map[string]interface{}); !ok || finding["uid"] != "NOTABLE-42" {
		t.Errorf("finding.uid not preserved: %v", ocsf["finding"])
	}
}

// The canonical event ID must be stable across polls: same vendor id + tenant +
// connector => same ID even though ReceivedAt changes every poll (#529).
func TestGenerateEventIDStableAcrossPolls(t *testing.T) {
	poll1 := &RawEvent{
		ConnectorID: "conn-1", TenantID: "t1", ReceivedAt: "2026-08-02T00:00:00Z",
		Payload: map[string]interface{}{"external_id": "NOTABLE-42"},
	}
	poll2 := &RawEvent{
		ConnectorID: "conn-1", TenantID: "t1", ReceivedAt: "2026-08-02T00:05:00Z", // later poll
		Payload: map[string]interface{}{"external_id": "NOTABLE-42"},
	}
	if generateEventID(poll1) != generateEventID(poll2) {
		t.Error("event ID changed across polls despite identical vendor id (#529)")
	}
}

func TestGenerateEventIDDistinctForDifferentEvents(t *testing.T) {
	a := &RawEvent{ConnectorID: "c", TenantID: "t", Payload: map[string]interface{}{"external_id": "A"}}
	b := &RawEvent{ConnectorID: "c", TenantID: "t", Payload: map[string]interface{}{"external_id": "B"}}
	if generateEventID(a) == generateEventID(b) {
		t.Error("distinct vendor ids collided to the same event ID")
	}
}

// Two events with the same timestamp but different content and no stable vendor
// id must both be ingestible (distinct IDs), while a byte-identical replay
// collapses to one (#529).
func TestGenerateEventIDContentFallback(t *testing.T) {
	mk := func(msg string) *RawEvent {
		return &RawEvent{
			ConnectorID: "c", TenantID: "t", ReceivedAt: "2026-08-02T00:00:00Z",
			Payload: map[string]interface{}{"time": "2026-08-01T00:00:00Z", "message": msg},
		}
	}
	if generateEventID(mk("one")) == generateEventID(mk("two")) {
		t.Error("same-timestamp events with different content collided")
	}
	if generateEventID(mk("one")) != generateEventID(mk("one")) {
		t.Error("identical replay produced different IDs")
	}
}

// A canonical connector envelope (source + raw_event) must be recognised and
// mapped to an OCSF Security Finding regardless of connector_type, so
// CrowdStrike/SentinelOne/etc. stop falling to the generic Network-Activity
// profile (Wave 0).
func TestCanonicalEnvelopeMapsToFinding(t *testing.T) {
	n := newTestNormalizer()
	raw := &RawEvent{
		ConnectorID:   "c1",
		ConnectorType: "crowdstrike", // has no raw profile keyed "crowdstrike"
		TenantID:      "11111111-1111-1111-1111-111111111111",
		ReceivedAt:    "2026-08-02T00:00:00Z",
		Payload: map[string]interface{}{
			"source":      "crowdstrike",
			"external_id": "THREAT-9",
			"title":       "Malware Blocked",
			"severity":    "high",
			"src_ip":      "10.0.0.4",
			"hostname":    "ws-9",
			"created_at":  "2026-08-01T23:00:00Z",
			"raw_event":   map[string]interface{}{"id": "THREAT-9"},
		},
	}
	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	ocsf := ev.OcsfEvent
	if ocsf["class_uid"] != 2001 {
		t.Errorf("class_uid = %v, want 2001 (Security Finding, not generic 4001)", ocsf["class_uid"])
	}
	if ocsf["severity_id"] != 4 {
		t.Errorf("severity_id = %v, want 4 (high preserved)", ocsf["severity_id"])
	}
	if ocsf["message"] != "Malware Blocked" {
		t.Errorf("message = %v, want the canonical title", ocsf["message"])
	}
	// The envelope ID must be the replay-stable event_id, not a random UUID.
	if ev.ID != ocsf["event_id"] {
		t.Errorf("envelope ID %q != ocsf event_id %q (should be the deterministic id)", ev.ID, ocsf["event_id"])
	}
	if ev.ID != generateEventID(raw) {
		t.Errorf("envelope ID is not the deterministic generateEventID value")
	}
}

// Identity-provider canonical envelopes map to Authentication (3002).
func TestCanonicalEnvelopeIdpMapsToAuthentication(t *testing.T) {
	n := newTestNormalizer()
	ev, err := n.Normalize(&RawEvent{
		ConnectorID: "c2", ConnectorType: "okta", TenantID: "t-okta-uuid-1111-1111-111111111111",
		Payload: map[string]interface{}{
			"source": "okta", "external_id": "EVT-1", "title": "Suspicious sign-in",
			"severity": "medium", "raw_event": map[string]interface{}{},
		},
	})
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	if ev.OcsfEvent["class_uid"] != 3002 {
		t.Errorf("okta canonical class_uid = %v, want 3002 (Authentication)", ev.OcsfEvent["class_uid"])
	}
}

// Elastic Search pulls raw ECS firewall/network logs. Their canonical OCSF model
// is Network Activity (4001, category 4), not a Security Finding (2001). Keeping
// low/medium events out of the finding auto-promoter (class_uid//1000==2) lets the
// AiSOC detection ruleset own the gate; genuine high/critical events still promote
// via the severity_id>=4 gate. The connector's flat fields must be re-keyed onto
// proper OCSF Network Activity nested objects (src_endpoint.dst_endpoint.port,
// connection_info.protocol_name), per the elasticFieldMap.
func TestCanonicalEnvelopeElasticSearchMapsToNetworkActivity(t *testing.T) {
	n := newTestNormalizer()
	ev, err := n.Normalize(&RawEvent{
		ConnectorID: "elastic_search", ConnectorType: "elastic_search",
		TenantID: "11111111-1111-1111-1111-111111111111", ReceivedAt: "2026-08-02T00:00:00Z",
		Payload: map[string]interface{}{
			"source": "elastic_search",
			"external_id": "FW-4471",
			"title": "Blocked DNS To Foreign Resolver",
			"severity": "medium",
			"src_ip": "203.0.113.42",
			"dst_ip": "10.1.1.5",
			"dst_port": 53,
			"src_geo": "RU",
			"network_protocol": "dns",
			"hostname": "fw-perimeter-01",
			"raw_event": map[string]interface{}{},
		},
	})
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	ocsf := ev.OcsfEvent
	if ocsf["class_uid"] != 4001 {
		t.Errorf("class_uid = %v, want 4001 (Network Activity)", ocsf["class_uid"])
	}
	if ocsf["category_uid"] != 4 {
		t.Errorf("category_uid = %v, want 4 (network)", ocsf["category_uid"])
	}
	if ocsf["class_name"] != "Network Activity" {
		t.Errorf("class_name = %v, want Network Activity", ocsf["class_name"])
	}
	// Nested endpoint mapping (elasticFieldMap), not flat top-level keys.
	if se, ok := ocsf["src_endpoint"].(map[string]interface{}); !ok || se["ip"] != "203.0.113.42" {
		t.Errorf("src_endpoint.ip not mapped: %v", ocsf["src_endpoint"])
	}
	if de, ok := ocsf["dst_endpoint"].(map[string]interface{}); !ok || de["ip"] != "10.1.1.5" || de["port"] != 53 {
		t.Errorf("dst_endpoint.ip/port not mapped: %v", ocsf["dst_endpoint"])
	}
	if loc, ok := ocsf["src_endpoint"].(map[string]interface{})["location"].(map[string]interface{}); !ok || loc["country"] != "RU" {
		t.Errorf("src_endpoint.location.country not mapped: %v", ocsf["src_endpoint"])
	}
	if ci, ok := ocsf["connection_info"].(map[string]interface{}); !ok || ci["protocol_name"] != "dns" {
		t.Errorf("connection_info.protocol_name not mapped: %v", ocsf["connection_info"])
	}
	// Native severity preserved (medium -> severity_id 3).
	if ocsf["severity_id"] != 3 {
		t.Errorf("severity_id = %v, want 3 (medium preserved)", ocsf["severity_id"])
	}
	if ocsf["severity"] != "medium" {
		t.Errorf("severity = %v, want medium", ocsf["severity"])
	}
	// Flat field keys must NOT be left at the top level (they are re-keyed).
	for _, k := range []string{"src_ip", "dst_ip", "dst_port", "network_protocol", "src_geo"} {
		if _, present := ocsf[k]; present {
			t.Errorf("flat key %q leaked into OCSF top level; expected nested mapping", k)
		}
	}
}
