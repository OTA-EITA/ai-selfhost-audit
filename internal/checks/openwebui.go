package checks

import (
	"fmt"
	"regexp"
	"strings"
)

const owuSrc = "https://github.com/open-webui/open-webui/blob/v0.12.3/"

func init() {
	addRules(
		Rule{ID: "OWU001", Product: "open-webui", Severity: Medium, Title: "First visitor can sign up as the Open WebUI admin",
			Remediation: "Set WEBUI_ADMIN_EMAIL and WEBUI_ADMIN_PASSWORD so the admin is created at startup, or bind the port to 127.0.0.1 until the admin exists.",
			Refs:        []string{owuSrc + "backend/open_webui/routers/auths.py#L811-L827", owuSrc + "backend/open_webui/env.py#L804-L806"}},
		Rule{ID: "OWU002", Product: "open-webui", Severity: High, Title: "Open WebUI authentication is off",
			Remediation: "Remove WEBUI_AUTH=false; with it every visitor is signed in as admin@localhost.",
			Refs:        []string{owuSrc + "backend/open_webui/routers/auths.py#L728-L758"}},
		Rule{ID: "OWU003", Product: "open-webui", Severity: High, Title: "WEBUI_SECRET_KEY is a known value",
			Remediation: "Generate a random WEBUI_SECRET_KEY; it signs every session token. Versions up to 0.9.5 fell back to the public value t0p-s3cr3t when unset.",
			Refs:        []string{owuSrc + "backend/open_webui/env.py#L766-L794", "https://github.com/open-webui/open-webui/blob/v0.9.5/backend/open_webui/env.py#L593"}},
		Rule{ID: "OWU004", Product: "open-webui", Severity: High, Title: "New Open WebUI sign-ups get an active role",
			Remediation: "Keep DEFAULT_USER_ROLE=pending (the default) so an admin approves new accounts.",
			Refs:        []string{owuSrc + "backend/open_webui/config.py#L1748", owuSrc + "backend/open_webui/utils/auth.py#L567-L573"}},
		Rule{ID: "OWU005", Product: "open-webui", Severity: High, Title: "Trusted header sign-in with the port published directly",
			Remediation: "Only use WEBUI_AUTH_TRUSTED_EMAIL_HEADER behind a proxy that strips the header, and do not publish the app port on all interfaces.",
			Refs:        []string{owuSrc + "backend/open_webui/routers/auths.py#L672-L716"}},
		Rule{ID: "OWU006", Product: "open-webui", Severity: High, Title: "Web fetch may reach private addresses",
			Remediation: "Remove ENABLE_LOCAL_WEB_FETCH / ENABLE_RAG_LOCAL_WEB_FETCH=true; users can then reach internal services such as Ollama.",
			Refs:        []string{owuSrc + "backend/open_webui/config.py#L1117-L1156"}},
		Rule{ID: "OWU007", Product: "open-webui", Severity: High, Title: "OpenAI API passthrough is on",
			Remediation: "Remove ENABLE_OPENAI_API_PASSTHROUGH=true; any user can reach any upstream endpoint with the admin's API key.",
			Refs:        []string{owuSrc + "backend/open_webui/env.py#L868"}},
		Rule{ID: "OWU008", Product: "open-webui", Severity: Low, Title: "CORS allows any origin",
			Remediation: "Set CORS_ALLOW_ORIGIN to the site's own origin; the default * only logs a warning.",
			Refs:        []string{owuSrc + "backend/open_webui/config.py#L2179-L2187", owuSrc + "backend/open_webui/main.py#L864-L870"}},
		Rule{ID: "OWU009", Product: "open-webui", Severity: High, Title: "Open WebUI version lets any website steal a signed-in token",
			Remediation: "Upgrade to 0.11.4 or later (GHSA-vpq8-f445-hcq7).",
			Refs:        []string{"https://github.com/open-webui/open-webui/security/advisories/GHSA-vpq8-f445-hcq7"}},
	)
	register(product{Name: "open-webui", Image: regexp.MustCompile(`(^|/)open-webui/open-webui([:@]|$)`), Check: checkOpenWebUI})
}

var owuExampleKeys = []string{"t0p-s3cr3t", "your-secret-key", "secret"}

func checkOpenWebUI(c *ctx, d Detected) {
	s := d.Service

	if publishedEverywhere(s) {
		email := c.val(s, "WEBUI_ADMIN_EMAIL", "")
		if !email.set {
			c.add("OWU001", d, email, "The port is published on every interface and the first account to sign up becomes admin.")
		}
	}
	if st, off := c.isFalse(s, "WEBUI_AUTH"); off {
		c.add("OWU002", d, st, "WEBUI_AUTH=false")
	}
	key := c.val(s, "WEBUI_SECRET_KEY", "")
	switch {
	case key.set && weakSecret(key.value, owuExampleKeys, 16):
		c.add("OWU003", d, key, fmt.Sprintf("WEBUI_SECRET_KEY is %s.", Mask(key.value)))
	case !key.set && d.Version != "" && versionLess(d.Version, "0.9.6"):
		c.add("OWU003", d, key, fmt.Sprintf("WEBUI_SECRET_KEY is not set and %s falls back to t0p-s3cr3t.", d.Version))
	}
	if st := c.val(s, "DEFAULT_USER_ROLE", "pending"); st.set && strings.ToLower(st.value) != "pending" {
		c.add("OWU004", d, st, fmt.Sprintf("DEFAULT_USER_ROLE=%s", st.value))
	}
	if st := c.val(s, "WEBUI_AUTH_TRUSTED_EMAIL_HEADER", ""); st.set && publishedEverywhere(s) {
		c.add("OWU005", d, st, fmt.Sprintf("WEBUI_AUTH_TRUSTED_EMAIL_HEADER=%s and the app port is published on every interface.", st.value))
	}
	for _, k := range []string{"ENABLE_LOCAL_WEB_FETCH", "ENABLE_RAG_LOCAL_WEB_FETCH"} {
		if st, on := c.isTrue(s, k); on {
			c.add("OWU006", d, st, k+"=true")
		}
	}
	if st, on := c.isTrue(s, "ENABLE_OPENAI_API_PASSTHROUGH"); on {
		c.add("OWU007", d, st, "ENABLE_OPENAI_API_PASSTHROUGH=true")
	}
	if st := c.val(s, "CORS_ALLOW_ORIGIN", "*"); strings.TrimSpace(st.value) == "*" {
		c.add("OWU008", d, st, "CORS_ALLOW_ORIGIN is * (the middleware also allows credentials).")
	}
	if v := d.Version; v != "" && versionLess(v, "0.11.4") {
		c.add("OWU009", d, setting{service: s.Name, file: c.in.Project.File, line: s.Line}, fmt.Sprintf("Image tag %s is affected by GHSA-vpq8-f445-hcq7.", v))
	}
}
