// Package klaxond defines the canonical application-event payload accepted by
// Klaxond's Alertmanager-compatible webhook endpoint.
package klaxond

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type Status string

const (
	StatusFiring   Status = "firing"
	StatusResolved Status = "resolved"
)

type Event struct {
	Kind       string
	Severity   Severity
	Status     Status
	Title      string
	Body       string
	OccurredAt time.Time
	DedupKey   string
	RunbookURL string
	Labels     map[string]string
}

type Alert struct {
	Status      Status            `json:"status"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    string            `json:"startsAt"`
}

type Payload struct {
	Status            Status            `json:"status"`
	Receiver          string            `json:"receiver"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	Alerts            []Alert           `json:"alerts"`
}

func (e Event) EndpointPath() string { return "/webhook/" + string(e.Severity) }

func (e Event) AlertmanagerPayload(source string) Payload {
	labels := map[string]string{
		"alertname": e.Title,
		"component": source,
		"source":    source,
		"kind":      e.Kind,
		"severity":  string(e.Severity),
	}
	if e.DedupKey != "" {
		labels["dedup_key"] = e.DedupKey
	}
	for key, value := range e.Labels {
		labels[key] = value
	}
	annotations := map[string]string{
		"summary":     e.Title,
		"description": e.Body,
	}
	if e.RunbookURL != "" {
		annotations["runbook_url"] = e.RunbookURL
	}
	occurredAt := e.OccurredAt.UTC().Format(time.RFC3339)
	return Payload{
		Status:            e.Status,
		Receiver:          source,
		CommonLabels:      labels,
		CommonAnnotations: annotations,
		Alerts: []Alert{{
			Status:      e.Status,
			Labels:      clone(labels),
			Annotations: clone(annotations),
			StartsAt:    occurredAt,
		}},
	}
}

func clone(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}
