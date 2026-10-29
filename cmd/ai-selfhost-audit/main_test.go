package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestTableOnN8N(t *testing.T) {
	code, out, _ := cli(t, "--compose", "../../testdata/n8n/docker-compose.yml")
	if code != 1 {
		t.Fatalf("exit %d, want 1 (HIGH finding)\n%s", code, out)
	}
	for _, want := range []string{"N8N010", "Detected: n8n (service n8n, 2.44.5)", "8 findings: 1 high, 6 medium, 0 low, 1 info", "chan****"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "changePassword") {
		t.Error("secret printed unmasked")
	}
}

func TestFailOn(t *testing.T) {
	if code, _, _ := cli(t, "--compose", "../../testdata/openwebui/docker-compose.yaml"); code != 0 {
		t.Errorf("no HIGH finding, want exit 0, got %d", code)
	}
	if code, _, _ := cli(t, "--compose", "../../testdata/openwebui/docker-compose.yaml", "--fail-on", "medium"); code != 1 {
		t.Errorf("want exit 1, got %d", code)
	}
}

func TestJSONAndSARIF(t *testing.T) {
	_, out, _ := cli(t, "--compose", "../../testdata/flowise/docker-compose.yml", "--format", "json", "--fail-on", "none")
	var j struct {
		Detected []string `json:"detected"`
		Findings []struct {
			RuleID  string `json:"rule_id"`
			Product string `json:"product"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &j); err != nil {
		t.Fatal(err)
	}
	if len(j.Detected) != 1 || len(j.Findings) == 0 || j.Findings[0].Product != "flowise" {
		t.Errorf("unexpected %+v", j)
	}
	_, out, _ = cli(t, "--compose", "../../testdata/litellm/docker-compose.yml", "--format", "sarif", "--fail-on", "none")
	var s struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil || s.Version != "2.1.0" || len(s.Runs[0].Results) == 0 {
		t.Errorf("bad sarif: %v %+v", err, s)
	}
}

func TestUsageErrors(t *testing.T) {
	if code, _, _ := cli(t, "--compose", "missing.yml"); code != 2 {
		t.Errorf("missing file: exit %d", code)
	}
	if code, _, _ := cli(t, "--compose", "../../testdata/n8n/docker-compose.yml", "--fail-on", "critical"); code != 2 {
		t.Errorf("bad severity: exit %d", code)
	}
	if code, out, _ := cli(t, "--list-rules"); code != 0 || !strings.Contains(out, "LGF008\tlangflow\tHIGH") {
		t.Errorf("list-rules: %d\n%s", code, out)
	}
}
