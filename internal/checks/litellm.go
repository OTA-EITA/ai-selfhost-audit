package checks

import (
	"fmt"
	"regexp"
	"strings"
)

const llmSrc = "https://github.com/BerriAI/litellm/blob/v1.106.2/"

func init() {
	addRules(
		Rule{ID: "LLM001", Product: "litellm", Severity: High, Title: "LiteLLM is allowed to start without a real master key",
			Remediation: "Remove LITELLM_DANGEROUSLY_PERMIT_WEAK_OR_UNSET_MASTER_KEY; with no master key every request is accepted as an internal user.",
			Refs:        []string{llmSrc + "litellm/proxy/auth/master_key_boot_check.py#L14-L22", llmSrc + "litellm/proxy/auth/user_api_key_auth.py#L1951-L1962"}},
		Rule{ID: "LLM002", Product: "litellm", Severity: High, Title: "LITELLM_MASTER_KEY is weak",
			Remediation: "Generate a long random master key (openssl rand -hex 32, prefixed sk-). It is also the admin UI password unless UI_PASSWORD is set.",
			Refs:        []string{llmSrc + "litellm/proxy/auth/master_key_boot_check.py#L203-L211", llmSrc + "litellm/proxy/auth/login_utils.py#L121-L145"}},
		Rule{ID: "LLM003", Product: "litellm", Severity: Medium, Title: "LITELLM_SALT_KEY is not set",
			Remediation: "Set LITELLM_SALT_KEY once and never change it; without it the master key also encrypts the provider credentials stored in the database.",
			Refs:        []string{llmSrc + "litellm/proxy/common_utils/encrypt_decrypt_utils.py#L32-L40"}},
		Rule{ID: "LLM004", Product: "litellm", Severity: High, Title: "LiteLLM version has a known critical authentication flaw",
			Remediation: "Upgrade: below 1.84.0 a Host header bypasses authentication (GHSA-4xpc-pv4p-pm3w); 1.91.0 up to the fixed releases allow privilege escalation to RCE (GHSA-7hp6-4w63-5g45).",
			Refs:        []string{"https://github.com/BerriAI/litellm/security/advisories/GHSA-4xpc-pv4p-pm3w", "https://github.com/BerriAI/litellm/security/advisories/GHSA-7hp6-4w63-5g45"}},
		Rule{ID: "LLM005", Product: "litellm", Severity: Medium, Title: "LiteLLM CORS sends credentials to any origin",
			Remediation: "List LITELLM_CORS_ORIGINS explicitly when LITELLM_CORS_ALLOW_CREDENTIALS=true.",
			Refs:        []string{llmSrc + "litellm/proxy/proxy_server.py#L2292-L2331"}},
		Rule{ID: "LLM006", Product: "litellm", Severity: Medium, Title: "LiteLLM secret redaction in logs is off",
			Remediation: "Remove LITELLM_DISABLE_REDACT_SECRETS=true.",
			Refs:        []string{llmSrc + "litellm/_logging.py#L73"}},
		Rule{ID: "LLM007", Product: "litellm", Severity: Medium, Title: "LiteLLM can start MCP servers as local commands",
			Remediation: "Remove LITELLM_ENABLE_MCP_STDIO=true unless admins need stdio MCP servers; it lets admins run npx, uvx, python, docker and more.",
			Refs:        []string{llmSrc + "litellm/proxy/_experimental/mcp_server/stdio_gate.py#L7-L15"}},
	)
	register(product{Name: "litellm", Image: regexp.MustCompile(`(^|/)berriai/litellm(-[a-z]+)?([:@]|$)`), Check: checkLiteLLM})
}

func checkLiteLLM(c *ctx, d Detected) {
	s := d.Service

	if st, on := c.isTrue(s, "LITELLM_DANGEROUSLY_PERMIT_WEAK_OR_UNSET_MASTER_KEY"); on {
		c.add("LLM001", d, st, "LITELLM_DANGEROUSLY_PERMIT_WEAK_OR_UNSET_MASTER_KEY=true")
	}
	if st := c.val(s, "LITELLM_MASTER_KEY", ""); st.set && weakSecret(st.value, []string{"sk-1234"}, 20) {
		c.add("LLM002", d, st, fmt.Sprintf("LITELLM_MASTER_KEY is %s.", Mask(st.value)))
	}
	if st := c.val(s, "LITELLM_SALT_KEY", ""); !st.set {
		c.add("LLM003", d, st, "LITELLM_SALT_KEY is not set, so it falls back to the master key.")
	}
	if v := d.Version; v != "" {
		at := setting{service: s.Name, file: c.in.Project.File, line: s.Line}
		switch {
		case versionLess(v, "1.84.0"):
			c.add("LLM004", d, at, fmt.Sprintf("Image tag %s is below 1.84.0 (GHSA-4xpc-pv4p-pm3w).", v))
		case litellm7hp6(v):
			if _, off := c.isFalse(s, "EXPERIMENTAL_UI_LOGIN"); !off {
				c.add("LLM004", d, at, fmt.Sprintf("Image tag %s is affected by GHSA-7hp6-4w63-5g45 and EXPERIMENTAL_UI_LOGIN is not false.", v))
			}
		}
	}
	if st, on := c.isTrue(s, "LITELLM_CORS_ALLOW_CREDENTIALS"); on {
		origins := c.val(s, "LITELLM_CORS_ORIGINS", "*")
		if strings.TrimSpace(origins.value) == "*" {
			c.add("LLM005", d, st, "LITELLM_CORS_ALLOW_CREDENTIALS=true with origins *")
		}
	}
	if st, on := c.isTrue(s, "LITELLM_DISABLE_REDACT_SECRETS"); on {
		c.add("LLM006", d, st, "LITELLM_DISABLE_REDACT_SECRETS=true")
	}
	if st, on := c.isTrue(s, "LITELLM_ENABLE_MCP_STDIO"); on {
		c.add("LLM007", d, st, "LITELLM_ENABLE_MCP_STDIO=true")
	}
}

// litellm7hp6 reports whether v is in 1.91.0 up to the fixed releases of
// GHSA-7hp6-4w63-5g45 (1.100.4, 1.101.3, 1.102.2, 1.103.1, 1.104.0).
func litellm7hp6(v string) bool {
	p, ok := parseVersion(v)
	if !ok || p[0] != 1 || p[1] < 91 || p[1] >= 104 {
		return false
	}
	fixed := map[int]string{100: "1.100.4", 101: "1.101.3", 102: "1.102.2", 103: "1.103.1"}
	if f, ok := fixed[p[1]]; ok {
		return versionLess(v, f)
	}
	return true
}
