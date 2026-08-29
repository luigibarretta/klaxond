package klaxond

import (
	"encoding/json"
	"testing"
	"time"
)

func TestApplicationEventContract(t *testing.T) {
	event := Event{
		Kind:       "indexer_down",
		Severity:   SeverityWarning,
		Status:     StatusFiring,
		Title:      "Indexer down: example",
		Body:       "The indexer timed out.",
		OccurredAt: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC),
		DedupKey:   "indexer:example",
		Labels:     map[string]string{"host": "storage-01"},
	}
	payload := event.AlertmanagerPayload("lampo")

	if event.EndpointPath() != "/webhook/warning" {
		t.Fatalf("unexpected endpoint: %s", event.EndpointPath())
	}
	if payload.CommonLabels["kind"] != "indexer_down" || payload.CommonLabels["component"] != "lampo" {
		t.Fatalf("unexpected labels: %#v", payload.CommonLabels)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 || payload.Alerts[0].StartsAt != "2026-07-31T12:00:00Z" {
		t.Fatalf("unexpected payload: %s", encoded)
	}
}
