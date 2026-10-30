package checks

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/OTA-EITA/ai-selfhost-audit/internal/compose"
	"github.com/OTA-EITA/ai-selfhost-audit/internal/envfile"
)

// load runs the checks on testdata/<dir>, reading <dir>/.env when present.
func load(t *testing.T, dir string) Result {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", dir)
	env := envfile.New()
	if p := filepath.Join(root, ".env"); fileExists(p) {
		e, err := envfile.ParseFile(p, env)
		if err != nil {
			t.Fatal(err)
		}
		env.Merge(e)
	}
	var composeFile string
	for _, n := range []string{"docker-compose.yml", "docker-compose.yaml"} {
		if p := filepath.Join(root, n); fileExists(p) {
			composeFile = p
		}
	}
	p, err := compose.Load(composeFile, env)
	if err != nil {
		t.Fatal(err)
	}
	return Run(Input{Env: env, Project: p})
}

// inline runs the checks on a compose document written in the test.
func inline(t *testing.T, yaml string) Result {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(f, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := compose.Load(f, envfile.New())
	if err != nil {
		t.Fatal(err)
	}
	return Run(Input{Env: envfile.New(), Project: p})
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func ids(r Result) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.RuleID+"/"+f.Service)
	}
	return out
}

func has(r Result, id string) bool {
	for _, f := range r.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// The official compose files, as published at the pinned versions.
func TestOfficialComposeFiles(t *testing.T) {
	cases := map[string][]string{
		"n8n":       {"N8N010/n8n", "GEN007/n8n", "GEN007/postgres", "GEN007/postgres", "N8N001/n8n", "N8N003/n8n", "N8N008/n8n", "GEN002/n8n"},
		"openwebui": {"OWU001/open-webui", "GEN006/open-webui", "OWU008/open-webui", "GEN002/open-webui"},
		"litellm":   {"GEN001/db", "GEN001/prometheus", "GEN007/db", "GEN007/litellm", "LLM003/litellm", "GEN006/litellm", "GEN002/litellm"},
		"langflow":  {"GEN001/postgres", "GEN007/langflow", "GEN007/postgres", "GEN006/langflow", "GEN002/langflow"},
		"flowise":   {"FLW001/flowise", "FLW008/flowise", "GEN006/flowise", "GEN002/flowise"},
	}
	for dir, want := range cases {
		t.Run(dir, func(t *testing.T) {
			got := ids(load(t, dir))
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("got  %v\nwant %v", got, want)
			}
		})
	}
}

func TestDetectsProductsAndVersions(t *testing.T) {
	r := load(t, "n8n")
	if len(r.Detected) != 1 || r.Detected[0].Product != "n8n" || r.Detected[0].Version != "2.44.5" {
		t.Fatalf("detected %+v", r.Detected)
	}
}

func TestN8NSwitches(t *testing.T) {
	r := inline(t, `
services:
  n8n:
    image: n8nio/n8n:2.46.1
    ports: ["127.0.0.1:5678:5678"]
    environment:
      N8N_ENCRYPTION_KEY: changeEncryptionKey
      NODES_EXCLUDE: "[]"
      N8N_BLOCK_ENV_ACCESS_IN_NODE: "false"
      N8N_RESTRICT_FILE_ACCESS_TO: ""
      N8N_RUNNERS_INSECURE_MODE: "true"
      N8N_SSRF_PROTECTION_ENABLED: "true"
      N8N_SECURE_COOKIE: "false"
`)
	for _, id := range []string{"N8N002", "N8N004", "N8N005", "N8N006", "N8N007", "N8N009"} {
		if !has(r, id) {
			t.Errorf("missing %s in %v", id, ids(r))
		}
	}
	for _, id := range []string{"N8N001", "N8N008", "N8N010", "GEN002"} {
		if has(r, id) {
			t.Errorf("unexpected %s", id)
		}
	}
}

func TestN8NVersions(t *testing.T) {
	for v, want := range map[string]bool{
		"1.123.88": true, "1.123.89": false, "2.44.6": true, "2.45.4": true, "2.45.5": false,
		"2.46.0": true, "2.46.1": false, "2.47.0": false, "3.0.0": true, "3.0.1": false,
	} {
		if got := n8nVulnerable(v); got != want {
			t.Errorf("%s: got %v", v, got)
		}
	}
}

func TestOpenWebUIRisky(t *testing.T) {
	r := inline(t, `
services:
  open-webui:
    image: ghcr.io/open-webui/open-webui:v0.9.5
    ports: ["3000:8080"]
    environment:
      WEBUI_ADMIN_EMAIL: admin@example.com
      WEBUI_AUTH: "False"
      DEFAULT_USER_ROLE: user
      WEBUI_AUTH_TRUSTED_EMAIL_HEADER: X-Email
      ENABLE_RAG_LOCAL_WEB_FETCH: "true"
      ENABLE_OPENAI_API_PASSTHROUGH: "true"
      CORS_ALLOW_ORIGIN: https://chat.example.com
`)
	for _, id := range []string{"OWU002", "OWU003", "OWU004", "OWU005", "OWU006", "OWU007", "OWU009"} {
		if !has(r, id) {
			t.Errorf("missing %s in %v", id, ids(r))
		}
	}
	for _, id := range []string{"OWU001", "OWU008"} {
		if has(r, id) {
			t.Errorf("unexpected %s", id)
		}
	}
}

func TestOpenWebUISecretFallbackOnlyOnOldVersions(t *testing.T) {
	r := inline(t, "services:\n  w:\n    image: ghcr.io/open-webui/open-webui:v0.12.3\n")
	if has(r, "OWU003") {
		t.Error("0.12.3 has no fallback secret")
	}
	r = inline(t, "services:\n  w:\n    image: ghcr.io/open-webui/open-webui:v0.12.3\n    environment: [WEBUI_SECRET_KEY=your-secret-key]\n")
	if !has(r, "OWU003") {
		t.Error("placeholder from the docs should be flagged")
	}
}

func TestLiteLLM(t *testing.T) {
	r := inline(t, `
services:
  litellm:
    image: ghcr.io/berriai/litellm:v1.95.0-stable
    environment:
      LITELLM_MASTER_KEY: sk-1234
      LITELLM_SALT_KEY: a-long-random-salt-value-1234567890
      LITELLM_DANGEROUSLY_PERMIT_WEAK_OR_UNSET_MASTER_KEY: "true"
      LITELLM_CORS_ALLOW_CREDENTIALS: "true"
      LITELLM_DISABLE_REDACT_SECRETS: "true"
      LITELLM_ENABLE_MCP_STDIO: "1"
`)
	for _, id := range []string{"LLM001", "LLM002", "LLM004", "LLM005", "LLM006", "LLM007"} {
		if !has(r, id) {
			t.Errorf("missing %s in %v", id, ids(r))
		}
	}
	if has(r, "LLM003") {
		t.Error("salt key is set")
	}
	for v, want := range map[string]bool{"1.90.9": false, "1.91.0": true, "1.100.3": true, "1.100.4": false, "1.103.1": false, "1.104.0": false} {
		if got := litellm7hp6(v); got != want {
			t.Errorf("%s: got %v", v, got)
		}
	}
}

func TestLiteLLMWorkaroundSilences7hp6(t *testing.T) {
	r := inline(t, "services:\n  l:\n    image: ghcr.io/berriai/litellm:v1.95.0\n    environment: [EXPERIMENTAL_UI_LOGIN=false, LITELLM_SALT_KEY=x]\n")
	if has(r, "LLM004") {
		t.Errorf("workaround applied: %v", ids(r))
	}
}

func TestLangflowOldImage(t *testing.T) {
	r := inline(t, "services:\n  lf:\n    image: langflowai/langflow:1.2.0\n")
	for _, id := range []string{"LGF001", "LGF003", "LGF008"} {
		if !has(r, id) {
			t.Errorf("missing %s in %v", id, ids(r))
		}
	}
	r = inline(t, "services:\n  lf:\n    image: langflowai/langflow:1.10.2\n")
	for _, id := range []string{"LGF001", "LGF003", "LGF008"} {
		if has(r, id) {
			t.Errorf("unexpected %s", id)
		}
	}
	if !has(r, "LGF009") {
		t.Error("1.10.2 is below 1.10.3")
	}
	// CVE-2026-9198 (KEV) covers 1.0.0 through 1.10.0.
	r = inline(t, "services:\n  lf:\n    image: langflowai/langflow:1.10.0\n")
	if !has(r, "LGF008") {
		t.Errorf("1.10.0 is in the KEV range: %v", ids(r))
	}
}

func TestLangflowSwitches(t *testing.T) {
	r := inline(t, `
services:
  lf:
    image: langflowai/langflow:1.12.7
    environment:
      LANGFLOW_AUTO_LOGIN: "true"
      LANGFLOW_SKIP_AUTH_AUTO_LOGIN: "true"
      LANGFLOW_SUPERUSER_PASSWORD: superuser
      LANGFLOW_SECRET_KEY: short
      LANGFLOW_NEW_USER_IS_ACTIVE: "true"
      LANGFLOW_WEBHOOK_AUTH_ENABLE: "false"
      LANGFLOW_SSRF_PROTECTION_ENABLED: "false"
`)
	for _, id := range []string{"LGF001", "LGF002", "LGF003", "LGF004", "LGF005", "LGF006", "LGF007"} {
		if !has(r, id) {
			t.Errorf("missing %s in %v", id, ids(r))
		}
	}
}

func TestFlowise(t *testing.T) {
	r := inline(t, `
services:
  flowise:
    image: flowiseai/flowise:3.0.13
    ports: ["127.0.0.1:3000:3000"]
    environment:
      - FLOWISE_PASSWORD=admin
      - TOOL_FUNCTION_BUILTIN_DEP=crypto,fs
      - TOOL_FUNCTION_EXTERNAL_DEP=axios,puppeteer
      - HTTP_SECURITY_CHECK=false
      - CUSTOM_MCP_PROTOCOL=stdio
      - CORS_ORIGINS=*
      - TRUST_PROXY=
`)
	for _, id := range []string{"FLW002", "FLW004", "FLW005", "FLW006", "FLW007"} {
		if !has(r, id) {
			t.Errorf("missing %s in %v", id, ids(r))
		}
	}
	for _, id := range []string{"FLW001", "FLW008"} {
		if has(r, id) {
			t.Errorf("unexpected %s (bound to 127.0.0.1)", id)
		}
	}
	if has(r, "FLW003") {
		t.Error("3.0.x still uses FLOWISE_USERNAME/PASSWORD for the migration")
	}
	r = inline(t, "services:\n  f:\n    image: flowiseai/flowise:3.1.4\n    environment: [FLOWISE_PASSWORD=x]\n")
	if !has(r, "FLW003") {
		t.Error("3.1.4 no longer reads FLOWISE_PASSWORD")
	}
	for _, f := range r.Findings {
		if f.RuleID == "FLW004" && strings.Contains(f.Message, "crypto") {
			t.Errorf("crypto is in the default allowlist: %s", f.Message)
		}
	}
}

func TestContainerRules(t *testing.T) {
	r := inline(t, `
services:
  app:
    image: flowiseai/flowise
    privileged: true
    network_mode: host
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
  cache:
    image: redis:7
    ports: ["6379:6379"]
    environment: {REDIS_PASSWORD: password}
`)
	for _, id := range []string{"GEN001", "GEN003", "GEN004", "GEN005", "GEN006", "GEN007"} {
		if !has(r, id) {
			t.Errorf("missing %s in %v", id, ids(r))
		}
	}
}

func TestUnknownServicesOnlyGetContainerChecks(t *testing.T) {
	r := inline(t, "services:\n  web:\n    image: nginx:1.29\n    ports: [\"80:80\"]\n")
	if len(r.Detected) != 0 || len(r.Findings) != 0 {
		t.Errorf("detected %v findings %v", r.Detected, ids(r))
	}
}

func TestImageTags(t *testing.T) {
	for tag, want := range map[string]bool{"": true, "latest": true, "main": true, "main-stable": true, "nightly": true, "1.2.3": false, "v0.12.3": false, "main-v1.80.0": false} {
		if got := unpinnedTag(tag); got != want {
			t.Errorf("%q: got %v", tag, got)
		}
	}
	for img, want := range map[string]string{"n8nio/n8n:2.44.5": "2.44.5", "ghcr.io/open-webui/open-webui:v0.12.3": "v0.12.3", "flowiseai/flowise": "", "localhost:5000/flowiseai/flowise:3.1.4": "3.1.4", "x/y:main": ""} {
		if got := imageVersion(img); got != want {
			t.Errorf("%s: got %q", img, got)
		}
	}
}

func TestRulesCatalogue(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if seen[r.ID] {
			t.Errorf("duplicate %s", r.ID)
		}
		seen[r.ID] = true
		if r.Title == "" || r.Remediation == "" || r.Product == "" {
			t.Errorf("%s incomplete", r.ID)
		}
		for _, ref := range r.Refs {
			if !strings.HasPrefix(ref, "https://") {
				t.Errorf("%s: bad ref %s", r.ID, ref)
			}
		}
	}
}
