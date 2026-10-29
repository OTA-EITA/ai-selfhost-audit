package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/OTA-EITA/ai-selfhost-audit/internal/compose"
)

func init() {
	addRules(
		Rule{ID: "GEN001", Product: "any", Severity: Medium, Title: "Datastore port published on all host interfaces",
			Remediation: `Remove the ports entry, or bind it to 127.0.0.1 ("127.0.0.1:5432:5432"). Other containers reach it over the compose network without it.`},
		Rule{ID: "GEN002", Product: "any", Severity: Info, Title: "Application port published on all host interfaces",
			Remediation: `Expected for the entry point. Put it behind a reverse proxy with TLS, or bind it to 127.0.0.1 while the instance is not ready for other users.`},
		Rule{ID: "GEN003", Product: "any", Severity: High, Title: "Service runs privileged",
			Remediation: "Remove privileged: true; grant only the capabilities the service needs."},
		Rule{ID: "GEN004", Product: "any", Severity: High, Title: "Docker socket mounted into a container",
			Remediation: "Remove the docker.sock mount; it gives the container root on the host."},
		Rule{ID: "GEN005", Product: "any", Severity: Medium, Title: "Service uses the host network",
			Remediation: "Use a compose network; host networking bypasses port publishing and network isolation."},
		Rule{ID: "GEN006", Product: "any", Severity: Low, Title: "Image is not pinned to a version",
			Remediation: "Use a version tag (or a digest) so upgrades are deliberate and known-vulnerable versions can be spotted."},
		Rule{ID: "GEN007", Product: "any", Severity: Medium, Title: "Database password is an example from an official compose file",
			Remediation: "Generate the database password; the example values are published in the projects' repositories.",
			Refs: []string{
				"https://github.com/n8n-io/n8n-hosting/blob/b690a87c814aed2f56981047fb617d22e488b861/docker-compose/withPostgres/.env#L3-L8",
				"https://github.com/BerriAI/litellm/blob/v1.106.2/docker-compose.yml#L42-L45",
				"https://github.com/langflow-ai/langflow/blob/v1.12.7/docker_example/docker-compose.yml#L23-L26",
			}},
	)
}

// Example database passwords shipped in the supported projects' compose files.
var examplePasswords = map[string]bool{
	"changepassword": true, "dbpassword9090": true, "litellm": true, "langflow": true,
	"mypassword": true, "difyai123456": true, "password": true, "postgres": true,
}

var passwordKeys = regexp.MustCompile(`^(POSTGRES(_NON_ROOT)?_PASSWORD|DB_(POSTGRESDB_)?PASSWORD|DATABASE_PASSWORD|MYSQL(_ROOT)?_PASSWORD|REDIS_PASSWORD)$`)

var urlPassword = regexp.MustCompile(`^[a-z0-9+]+://[^:/@]*:([^@]*)@`)

// Images that hold data rather than serve users.
var datastoreImage = regexp.MustCompile(`(?i)(^|/)(postgres|pgvector|mysql|mariadb|mongo|redis|valkey|qdrant|weaviate|milvus|chroma|elasticsearch|opensearch|clickhouse|minio|prometheus|ollama)([:@]|$)`)

func (c *ctx) container(s *compose.Service) {
	product := ""
	for _, d := range c.res.Detected {
		if d.Service == s {
			product = d.Product
		}
	}
	d := Detected{Product: product, Service: s}
	at := func(line int) setting {
		return setting{service: s.Name, file: c.in.Project.File, line: line}
	}

	for _, p := range s.Ports {
		if !p.AllInterfaces() {
			continue
		}
		switch {
		case datastoreImage.MatchString(s.Image):
			c.add("GEN001", d, at(p.Line), fmt.Sprintf("%s publishes %s on every host interface.", s.Image, p.Raw))
		case product != "":
			c.add("GEN002", d, at(p.Line), fmt.Sprintf("%s is reachable on every host interface at port %s.", product, p.Published))
		}
	}
	if s.Privileged {
		c.add("GEN003", d, at(s.PrivilegedLine), "privileged: true")
	}
	for _, m := range s.Mounts {
		if strings.HasSuffix(m.Source, "docker.sock") {
			c.add("GEN004", d, at(m.Line), fmt.Sprintf("Mounts %s.", m.Source))
		}
	}
	for k, v := range s.Env {
		pw := ""
		switch {
		case passwordKeys.MatchString(k):
			pw = v.Value
		case strings.HasSuffix(k, "DATABASE_URL"):
			if m := urlPassword.FindStringSubmatch(v.Value); m != nil {
				pw = m[1]
			}
		}
		if pw != "" && examplePasswords[strings.ToLower(pw)] {
			c.add("GEN007", d, setting{service: s.Name, file: v.File, line: v.Line}, fmt.Sprintf("%s uses the example password %s.", k, Mask(pw)))
		}
	}
	if s.NetworkMode == "host" {
		c.add("GEN005", d, at(s.NetworkModeLine), "network_mode: host")
	}
	if product != "" {
		if tag := imageTag(s.Image); unpinnedTag(tag) {
			shown := tag
			if shown == "" {
				shown = "(no tag, so latest)"
			}
			c.add("GEN006", d, at(s.Line), fmt.Sprintf("%s uses %s.", s.Image, shown))
		}
	}
}

// unpinnedTag reports whether an image tag follows a moving branch rather
// than a release ("latest", "main", "main-stable", "nightly", "dev").
func unpinnedTag(tag string) bool {
	t := strings.ToLower(tag)
	if t == "" || t == "latest" || t == "nightly" || t == "dev" || t == "edge" {
		return true
	}
	return (t == "main" || strings.HasPrefix(t, "main-")) && imageVersion(":"+t) == "" && !strings.Contains(t, "-v")
}
