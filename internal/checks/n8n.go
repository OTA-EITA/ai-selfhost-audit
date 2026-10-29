package checks

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	n8nSrc  = "https://github.com/n8n-io/n8n/blob/n8n@2.44.6/"
	n8nHost = "https://github.com/n8n-io/n8n-hosting/blob/b690a87c814aed2f56981047fb617d22e488b861/"
)

func init() {
	addRules(
		Rule{ID: "N8N001", Product: "n8n", Severity: Medium, Title: "First visitor can claim the n8n owner account",
			Remediation: "Create the owner before exposing the port, or set N8N_INSTANCE_OWNER_MANAGED_BY_ENV=true with the owner in env; bind the port to 127.0.0.1 until then.",
			Refs:        []string{n8nSrc + "packages/cli/src/controllers/owner.controller.ts#L25-L29", n8nSrc + "packages/cli/src/services/ownership.service.ts#L227-L232"}},
		Rule{ID: "N8N002", Product: "n8n", Severity: High, Title: "N8N_ENCRYPTION_KEY is an example value",
			Remediation: "Generate a key (openssl rand -hex 24). Credentials in the database, the JWT secret and the HMAC secret all derive from it.",
			Refs:        []string{n8nHost + "docker-compose/withPostgresAndWorker/.env#L10", n8nSrc + "packages/cli/src/services/jwt.service.ts#L32-L44"}},
		Rule{ID: "N8N003", Product: "n8n", Severity: Medium, Title: "Task runner auth token is an example value",
			Remediation: "Generate N8N_RUNNERS_AUTH_TOKEN; anything that reaches the broker with the token can register as a runner.",
			Refs:        []string{n8nHost + "docker-compose/withPostgres/.env#L10"}},
		Rule{ID: "N8N004", Product: "n8n", Severity: High, Title: "Execute Command node is allowed",
			Remediation: `Keep "n8n-nodes-base.executeCommand" in NODES_EXCLUDE (the default excludes it); it runs commands on the host container.`,
			Refs:        []string{n8nSrc + "packages/@n8n/config/src/configs/nodes.config.ts#L38-L39"}},
		Rule{ID: "N8N005", Product: "n8n", Severity: High, Title: "Workflows can read environment variables",
			Remediation: "Remove N8N_BLOCK_ENV_ACCESS_IN_NODE=false; $env exposes the database password and the encryption key to workflow editors.",
			Refs:        []string{n8nSrc + "packages/workflow/src/workflow-data-proxy-env-provider.ts#L15-L17"}},
		Rule{ID: "N8N006", Product: "n8n", Severity: High, Title: "File nodes can reach the whole filesystem",
			Remediation: "Do not set N8N_RESTRICT_FILE_ACCESS_TO to an empty value or N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES=false.",
			Refs:        []string{n8nSrc + "packages/@n8n/config/src/configs/security.config.ts#L41-L57"}},
		Rule{ID: "N8N007", Product: "n8n", Severity: High, Title: "An n8n safety switch is turned off",
			Remediation: "Remove N8N_DEPRECATED_NODES_BLOCK=false, N8N_RUNNERS_INSECURE_MODE=true and N8N_PREVIEW_MODE=true.",
			Refs:        []string{n8nSrc + "packages/@n8n/config/src/configs/nodes.config.ts#L60-L61", n8nSrc + "packages/@n8n/config/src/configs/runners.config.ts#L89-L90", n8nSrc + "packages/cli/src/auth/auth.service.ts#L203-L208"}},
		Rule{ID: "N8N008", Product: "n8n", Severity: Medium, Title: "n8n SSRF protection is off",
			Remediation: "Set N8N_SSRF_PROTECTION_ENABLED=true (off by default); n8n advisories recommend it.",
			Refs:        []string{n8nSrc + "packages/@n8n/config/src/configs/ssrf-protection.config.ts#L91-L92"}},
		Rule{ID: "N8N009", Product: "n8n", Severity: Medium, Title: "n8n session cookie is not Secure",
			Remediation: "Remove N8N_SECURE_COOKIE=false and serve n8n over HTTPS.",
			Refs:        []string{n8nSrc + "packages/@n8n/config/src/configs/auth.config.ts#L12-L13"}},
		Rule{ID: "N8N010", Product: "n8n", Severity: High, Title: "n8n version has an unpatched expression sandbox escape",
			Remediation: "Upgrade to 1.123.89, 2.45.5, 2.46.1, 3.0.1 or later (GHSA-gx3v-3x3v-f8r5).",
			Refs:        []string{"https://github.com/n8n-io/n8n/security/advisories/GHSA-gx3v-3x3v-f8r5"}},
	)
	register(product{Name: "n8n", Image: regexp.MustCompile(`(^|/)n8nio/n8n([:@]|$)`), Check: checkN8N})
}

var n8nExampleKeys = []string{"changeEncryptionKey", "changeRunnerAuthToken"}

func checkN8N(c *ctx, d Detected) {
	s := d.Service

	if publishedEverywhere(s) {
		if st, managed := c.isTrue(s, "N8N_INSTANCE_OWNER_MANAGED_BY_ENV"); !managed {
			c.add("N8N001", d, st, "The port is published on every interface and POST /rest/owner/setup needs no login until an owner exists.")
		}
	}
	if st := c.val(s, "N8N_ENCRYPTION_KEY", ""); st.set && weakSecret(st.value, n8nExampleKeys, 16) {
		c.add("N8N002", d, st, fmt.Sprintf("N8N_ENCRYPTION_KEY is %s.", Mask(st.value)))
	}
	if st := c.val(s, "N8N_RUNNERS_AUTH_TOKEN", ""); st.set && weakSecret(st.value, n8nExampleKeys, 16) {
		c.add("N8N003", d, st, fmt.Sprintf("N8N_RUNNERS_AUTH_TOKEN is %s.", Mask(st.value)))
	}
	if st := c.env(s, "NODES_EXCLUDE", ""); st.set && !strings.Contains(st.value, "n8n-nodes-base.executeCommand") {
		c.add("N8N004", d, st, fmt.Sprintf("NODES_EXCLUDE is %q, which no longer excludes executeCommand.", st.value))
	}
	if st, off := c.isFalse(s, "N8N_BLOCK_ENV_ACCESS_IN_NODE"); off {
		c.add("N8N005", d, st, "N8N_BLOCK_ENV_ACCESS_IN_NODE=false")
	}
	if st := c.env(s, "N8N_RESTRICT_FILE_ACCESS_TO", "~/.n8n-files"); st.set && strings.TrimSpace(st.value) == "" {
		c.add("N8N006", d, st, "N8N_RESTRICT_FILE_ACCESS_TO is empty, which removes the restriction.")
	}
	if st, off := c.isFalse(s, "N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES"); off {
		c.add("N8N006", d, st, "N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES=false exposes ~/.n8n/config, which holds the encryption key.")
	}
	if st, off := c.isFalse(s, "N8N_DEPRECATED_NODES_BLOCK"); off {
		c.add("N8N007", d, st, "N8N_DEPRECATED_NODES_BLOCK=false re-enables code nodes that run in the main process.")
	}
	if st, on := c.isTrue(s, "N8N_RUNNERS_INSECURE_MODE"); on {
		c.add("N8N007", d, st, "N8N_RUNNERS_INSECURE_MODE=true")
	}
	if st, on := c.isTrue(s, "N8N_PREVIEW_MODE"); on {
		c.add("N8N007", d, st, "N8N_PREVIEW_MODE=true skips authentication.")
	}
	if st, on := c.isTrue(s, "N8N_SSRF_PROTECTION_ENABLED"); !on {
		c.add("N8N008", d, st, "N8N_SSRF_PROTECTION_ENABLED is not true.")
	}
	if st, off := c.isFalse(s, "N8N_SECURE_COOKIE"); off {
		c.add("N8N009", d, st, "N8N_SECURE_COOKIE=false")
	}
	if v := d.Version; v != "" && n8nVulnerable(v) {
		c.add("N8N010", d, setting{service: s.Name, file: c.in.Project.File, line: s.Line}, fmt.Sprintf("Image tag %s is affected by GHSA-gx3v-3x3v-f8r5.", v))
	}
}

// n8nVulnerable reports whether v is below the fixed release of its line.
func n8nVulnerable(v string) bool {
	p, ok := parseVersion(v)
	if !ok {
		return false
	}
	switch {
	case p[0] == 1:
		return versionLess(v, "1.123.89")
	case p[0] == 2 && p[1] <= 45:
		return versionLess(v, "2.45.5")
	case p[0] == 2 && p[1] == 46:
		return versionLess(v, "2.46.1")
	case p[0] == 3:
		return versionLess(v, "3.0.1")
	}
	return false
}
