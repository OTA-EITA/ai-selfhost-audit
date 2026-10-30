package checks

import (
	"fmt"
	"regexp"
	"strings"
)

const flwSrc = "https://github.com/FlowiseAI/Flowise/blob/flowise%403.1.4/"

func init() {
	addRules(
		Rule{ID: "FLW001", Product: "flowise", Severity: Medium, Title: "First visitor can register as the Flowise owner",
			Remediation: "Register the owner before exposing the port, or bind it to 127.0.0.1 until then (GHSA-v5w9-prxf-w882).",
			Refs:        []string{flwSrc + "packages/server/src/enterprise/services/account.service.ts#L178-L197", flwSrc + "packages/server/src/utils/constants.ts#L33"}},
		Rule{ID: "FLW002", Product: "flowise", Severity: High, Title: "Flowise version has hard-coded secrets or unauthenticated endpoints",
			Remediation: "Upgrade to 3.1.3 or later: before 3.1.0 the JWT, session and token-hash secrets had public defaults and SSRF checks were off; 3.1.3 fixes several unauthenticated token and RCE issues.",
			Refs:        []string{"https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-cc4f-hjpj-g9p8", "https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-qgvm-j2hm-6m38"}},
		Rule{ID: "FLW003", Product: "flowise", Severity: Medium, Title: "FLOWISE_USERNAME / FLOWISE_PASSWORD have no effect",
			Remediation: "Username and password auth is deprecated since 3.0.1 (it was only used to migrate to the built-in accounts), and 3.1.4 no longer reads the variables. Use the built-in accounts and remove them.",
			Refs:        []string{"https://github.com/FlowiseAI/FlowiseDocs/blob/32d7f0cc7929bbd9e592cbc8e7a69bb82625f418/en/configuration/authorization/app-level.md#L11-L13"}},
		Rule{ID: "FLW004", Product: "flowise", Severity: High, Title: "Custom code may load dangerous modules",
			Remediation: "Remove fs, child_process, os, net, http, * and similar from TOOL_FUNCTION_BUILTIN_DEP, and puppeteer, playwright, typeorm, pg, mysql2 from TOOL_FUNCTION_EXTERNAL_DEP.",
			Refs:        []string{"https://github.com/FlowiseAI/Flowise/blob/flowise%403.1.4/packages/components/src/utils.ts#L1728-L1733", "https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-9gvv-qjj3-2p6g"}},
		Rule{ID: "FLW005", Product: "flowise", Severity: High, Title: "A Flowise security check is off",
			Remediation: "Remove HTTP_SECURITY_CHECK=false, PATH_TRAVERSAL_SAFETY=false and CUSTOM_MCP_SECURITY_CHECK=false.",
			Refs:        []string{flwSrc + "packages/components/src/httpSecurity.ts#L35-L48", flwSrc + "packages/components/src/validator.ts#L40-L41", flwSrc + "packages/components/nodes/tools/MCP/CustomMCP/CustomMCP.ts#L176"}},
		Rule{ID: "FLW006", Product: "flowise", Severity: High, Title: "Custom MCP servers run as local commands",
			Remediation: "Remove CUSTOM_MCP_PROTOCOL=stdio unless every user is trusted with host commands.",
			Refs:        []string{flwSrc + "packages/components/nodes/tools/MCP/CustomMCP/CustomMCP.ts#L186-L187"}},
		Rule{ID: "FLW007", Product: "flowise", Severity: Medium, Title: "Flowise allows any origin",
			Remediation: "List origins in CORS_ORIGINS, MCP_CORS_ORIGINS and IFRAME_ORIGINS instead of *.",
			Refs:        []string{flwSrc + "packages/server/src/utils/XSS.ts#L83-L196"}},
		Rule{ID: "FLW008", Product: "flowise", Severity: Medium, Title: "X-Forwarded-For is trusted from any client",
			Remediation: "Set TRUST_PROXY to the proxy's address (or false) when the port is reachable directly; the default trusts every client, so rate limits can be bypassed.",
			Refs:        []string{flwSrc + "packages/server/src/index.ts#L183-L196"}},
	)
	register(product{Name: "flowise", Image: regexp.MustCompile(`(^|/)flowiseai/flowise([:@]|$)`), Check: checkFlowise})
}

func checkFlowise(c *ctx, d Detected) {
	s := d.Service
	at := setting{service: s.Name, file: c.in.Project.File, line: s.Line}

	if publishedEverywhere(s) {
		c.add("FLW001", d, at, "The port is published on every interface and POST /api/v1/account/register needs no login until an organization exists.")
	}
	if v := d.Version; v != "" && versionLess(v, "3.1.3") {
		c.add("FLW002", d, at, fmt.Sprintf("Image tag %s is below 3.1.3.", v))
	}
	if d.Version == "" || !versionLess(d.Version, "3.1.4") {
		for _, k := range []string{"FLOWISE_USERNAME", "FLOWISE_PASSWORD"} {
			if st := c.val(s, k, ""); st.set {
				c.add("FLW003", d, st, k+" is set but ignored.")
			}
		}
	}
	if st := c.val(s, "TOOL_FUNCTION_BUILTIN_DEP", ""); st.set {
		if hit := listHas(st.value, "*", "fs", "child_process", "os", "net", "http", "https", "vm", "worker_threads", "process", "cluster", "dgram", "inspector"); len(hit) > 0 {
			c.add("FLW004", d, st, "TOOL_FUNCTION_BUILTIN_DEP allows "+strings.Join(hit, ", ")+".")
		}
	}
	if st := c.val(s, "TOOL_FUNCTION_EXTERNAL_DEP", ""); st.set {
		if hit := listHas(st.value, "puppeteer", "playwright", "typeorm", "pg", "mysql2"); len(hit) > 0 {
			c.add("FLW004", d, st, "TOOL_FUNCTION_EXTERNAL_DEP allows "+strings.Join(hit, ", ")+".")
		}
	}
	for _, k := range []string{"HTTP_SECURITY_CHECK", "PATH_TRAVERSAL_SAFETY", "CUSTOM_MCP_SECURITY_CHECK"} {
		if st, off := c.isFalse(s, k); off {
			c.add("FLW005", d, st, k+"=false")
		}
	}
	if st := c.val(s, "CUSTOM_MCP_PROTOCOL", "sse"); st.set && strings.EqualFold(strings.TrimSpace(st.value), "stdio") {
		c.add("FLW006", d, st, "CUSTOM_MCP_PROTOCOL=stdio")
	}
	for _, k := range []string{"CORS_ORIGINS", "MCP_CORS_ORIGINS", "IFRAME_ORIGINS"} {
		if st := c.val(s, k, ""); st.set && strings.TrimSpace(st.value) == "*" {
			c.add("FLW007", d, st, k+"=*")
		}
	}
	if publishedEverywhere(s) {
		tp := c.val(s, "TRUST_PROXY", "")
		if !tp.set || truthy(tp.value) {
			c.add("FLW008", d, tp, "TRUST_PROXY is unset or true and the port is published on every interface.")
		}
	}
}
