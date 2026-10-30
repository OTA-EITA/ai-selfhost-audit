package checks

import (
	"fmt"
	"regexp"
)

const lgfSrc = "https://github.com/langflow-ai/langflow/blob/v1.12.7/"

func init() {
	addRules(
		Rule{ID: "LGF001", Product: "langflow", Severity: High, Title: "Langflow auto login gives every visitor superuser access",
			Remediation: "Set LANGFLOW_AUTO_LOGIN=false (the image default from 1.10.2; the code default is still true).",
			Refs:        []string{lgfSrc + "src/lfx/src/lfx/services/settings/auth.py#L96-L104", lgfSrc + "src/backend/base/langflow/api/v1/login.py#L117-L179", lgfSrc + "docker/build_and_push.Dockerfile#L234-L235"}},
		Rule{ID: "LGF002", Product: "langflow", Severity: High, Title: "Langflow API calls without a key run as the superuser",
			Remediation: "Remove LANGFLOW_SKIP_AUTH_AUTO_LOGIN=true.",
			Refs:        []string{lgfSrc + "src/lfx/src/lfx/services/settings/auth.py#L105-L107", lgfSrc + "src/backend/base/langflow/services/auth/service.py#L1069-L1098"}},
		Rule{ID: "LGF003", Product: "langflow", Severity: High, Title: "Langflow superuser password is weak or a sample",
			Remediation: "Set a generated LANGFLOW_SUPERUSER_PASSWORD. Images before 1.10.2 defaulted to langflow/langflow.",
			Refs:        []string{lgfSrc + "src/lfx/src/lfx/services/settings/constants.py#L3-L6", lgfSrc + "deploy/.env.example#L11-L12"}},
		Rule{ID: "LGF004", Product: "langflow", Severity: Medium, Title: "LANGFLOW_SECRET_KEY is short",
			Remediation: "Use at least 32 random characters; the key signs tokens and encrypts stored credentials.",
			Refs:        []string{lgfSrc + "src/lfx/src/lfx/services/settings/auth.py#L350-L380"}},
		Rule{ID: "LGF005", Product: "langflow", Severity: High, Title: "Langflow sign-ups are active immediately",
			Remediation: "Remove LANGFLOW_NEW_USER_IS_ACTIVE=true (sign-up is on by default and any active user can run custom Python).",
			Refs:        []string{lgfSrc + "src/lfx/src/lfx/services/settings/auth.py#L121-L133", lgfSrc + "src/lfx/src/lfx/services/settings/groups/security.py#L117-L134"}},
		Rule{ID: "LGF006", Product: "langflow", Severity: Medium, Title: "Langflow webhooks run without authentication",
			Remediation: "Remove LANGFLOW_WEBHOOK_AUTH_ENABLE=false.",
			Refs:        []string{lgfSrc + "src/lfx/src/lfx/services/settings/auth.py#L109-L113"}},
		Rule{ID: "LGF007", Product: "langflow", Severity: High, Title: "A Langflow file or network guard is off",
			Remediation: "Remove LANGFLOW_RESTRICT_LOCAL_FILE_ACCESS=false and LANGFLOW_SSRF_PROTECTION_ENABLED=false.",
			Refs:        []string{lgfSrc + "src/lfx/src/lfx/services/settings/groups/security.py#L22-L31", lgfSrc + "src/lfx/src/lfx/services/settings/groups/security.py#L259-L276"}},
		Rule{ID: "LGF008", Product: "langflow", Severity: High, Title: "Langflow version has vulnerabilities known to be exploited",
			Remediation: "Upgrade: 1.10.0 and earlier carry CVE-2025-3248, CVE-2025-34291, CVE-2026-0770, CVE-2026-33017, CVE-2026-55255 and CVE-2026-9198, all in the CISA KEV catalog.",
			Refs:        []string{"https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "https://github.com/langflow-ai/langflow/security/advisories"}},
		Rule{ID: "LGF009", Product: "langflow", Severity: Medium, Title: "Langflow version is below the latest security fixes",
			Remediation: "Upgrade to 1.10.3 or later (weak credential encryption key before 1.10.1, MCP command injection and SSRF fixes in 1.10.3).",
			Refs:        []string{"https://github.com/langflow-ai/langflow/security/advisories"}},
	)
	register(product{Name: "langflow", Image: regexp.MustCompile(`(^|/)langflowai/langflow(-backend)?([:@]|$)`), Check: checkLangflow})
}

var lgfSamplePasswords = []string{"langflow", "superuser", "admin", "password", "changeme"}

func checkLangflow(c *ctx, d Detected) {
	s := d.Service
	old := d.Version != "" && versionLess(d.Version, "1.10.2")

	auto := c.val(s, "LANGFLOW_AUTO_LOGIN", "")
	switch {
	case auto.set && truthy(auto.value):
		c.add("LGF001", d, auto, "LANGFLOW_AUTO_LOGIN=true")
	case !auto.set && old:
		c.add("LGF001", d, auto, fmt.Sprintf("LANGFLOW_AUTO_LOGIN is not set and the %s image defaults it to true.", d.Version))
	}
	if st, on := c.isTrue(s, "LANGFLOW_SKIP_AUTH_AUTO_LOGIN"); on {
		c.add("LGF002", d, st, "LANGFLOW_SKIP_AUTH_AUTO_LOGIN=true")
	}
	pw := c.val(s, "LANGFLOW_SUPERUSER_PASSWORD", "")
	switch {
	case pw.set && weakSecret(pw.value, lgfSamplePasswords, 12):
		c.add("LGF003", d, pw, fmt.Sprintf("LANGFLOW_SUPERUSER_PASSWORD is %s.", Mask(pw.value)))
	case !pw.set && old:
		c.add("LGF003", d, pw, fmt.Sprintf("LANGFLOW_SUPERUSER_PASSWORD is not set and %s defaults to langflow.", d.Version))
	}
	if st := c.val(s, "LANGFLOW_SECRET_KEY", ""); st.set && len(st.value) < 32 {
		c.add("LGF004", d, st, fmt.Sprintf("LANGFLOW_SECRET_KEY is %d characters.", len(st.value)))
	}
	if st, on := c.isTrue(s, "LANGFLOW_NEW_USER_IS_ACTIVE"); on {
		c.add("LGF005", d, st, "LANGFLOW_NEW_USER_IS_ACTIVE=true")
	}
	if st, off := c.isFalse(s, "LANGFLOW_WEBHOOK_AUTH_ENABLE"); off {
		c.add("LGF006", d, st, "LANGFLOW_WEBHOOK_AUTH_ENABLE=false")
	}
	for _, k := range []string{"LANGFLOW_RESTRICT_LOCAL_FILE_ACCESS", "LANGFLOW_SSRF_PROTECTION_ENABLED"} {
		if st, off := c.isFalse(s, k); off {
			c.add("LGF007", d, st, k+"=false")
		}
	}
	if v := d.Version; v != "" {
		at := setting{service: s.Name, file: c.in.Project.File, line: s.Line}
		switch {
		case versionLess(v, "1.10.1"):
			c.add("LGF008", d, at, fmt.Sprintf("Image tag %s is 1.10.0 or earlier.", v))
		case versionLess(v, "1.10.3"):
			c.add("LGF009", d, at, fmt.Sprintf("Image tag %s is below 1.10.3.", v))
		}
	}
}
