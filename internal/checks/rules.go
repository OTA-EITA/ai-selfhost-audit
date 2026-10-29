package checks

import (
	"fmt"
	"strings"
)

// Severity orders findings. INFO < LOW < MEDIUM < HIGH.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	}
	return "UNKNOWN"
}

// ParseSeverity accepts info, low, medium, high (any case) and "none".
// "none" returns a value above HIGH so nothing reaches it.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return Info, nil
	case "low":
		return Low, nil
	case "medium":
		return Medium, nil
	case "high":
		return High, nil
	case "none", "never":
		return High + 1, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want info, low, medium, high or none)", s)
}

// Rule describes one check.
// Rule describes one check.
type Rule struct {
	ID          string
	Product     string
	Severity    Severity
	Title       string
	Remediation string
	// Refs are links to the upstream lines the rule is based on.
	Refs []string
}

// Rules is the catalogue, filled by each product file.
var Rules []Rule

func addRules(rs ...Rule) { Rules = append(Rules, rs...) }

// RuleByID returns the rule or nil.
func RuleByID(id string) *Rule {
	for i := range Rules {
		if Rules[i].ID == id {
			return &Rules[i]
		}
	}
	return nil
}
