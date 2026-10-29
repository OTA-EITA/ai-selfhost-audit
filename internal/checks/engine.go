// Package checks turns a compose project into findings for the AI platforms
// it recognises.
package checks

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/OTA-EITA/ai-selfhost-audit/internal/compose"
	"github.com/OTA-EITA/ai-selfhost-audit/internal/envfile"
)

// Finding is one problem at one place.
type Finding struct {
	RuleID   string
	Severity Severity
	Title    string
	Message  string
	Product  string
	Service  string
	File     string
	Line     int
}

// Input is what the checks look at. Env holds the --env files used to
// interpolate the compose file.
type Input struct {
	Env         *envfile.Env
	Project     *compose.Project
	AllProfiles bool
}

// Detected is a service recognised as one of the supported products.
type Detected struct {
	Product string
	Service *compose.Service
	// Version is the image tag when it looks like a version, else "".
	Version string
}

// Result holds findings plus context for the report.
type Result struct {
	Findings []Finding
	Detected []Detected
	// Skipped lists services not evaluated because their profile is off.
	Skipped []string
}

// product is one supported platform: how to recognise its container and
// which checks to run on it.
type product struct {
	Name  string
	Image *regexp.Regexp
	Check func(c *ctx, d Detected)
}

var products []product

func register(p product) { products = append(products, p) }

// Products lists the supported platform names.
func Products() []string {
	var out []string
	for _, p := range products {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

var versionTag = regexp.MustCompile(`^v?(\d+)\.(\d+)(?:\.(\d+))?`)

// Run evaluates every rule.
func Run(in Input) Result {
	if in.Env == nil {
		in.Env = envfile.New()
	}
	c := &ctx{in: in}
	for _, s := range in.Project.Services {
		if !c.active(s) {
			c.res.Skipped = append(c.res.Skipped, s.Name)
			continue
		}
		for _, p := range products {
			if p.Image.MatchString(s.Image) {
				d := Detected{Product: p.Name, Service: s, Version: imageVersion(s.Image)}
				c.res.Detected = append(c.res.Detected, d)
				p.Check(c, d)
			}
		}
		c.container(s)
	}

	sort.SliceStable(c.res.Findings, func(i, j int) bool {
		a, b := c.res.Findings[i], c.res.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return a.Line < b.Line
	})
	return c.res
}

// imageVersion returns the tag of an image reference when it starts with a
// version number ("1.3.0", "v0.6.5-main"), else "".
func imageVersion(image string) string {
	ref := image
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon <= slash {
		return ""
	}
	tag := ref[colon+1:]
	if versionTag.MatchString(tag) {
		return tag
	}
	return ""
}

// imageTag returns the tag of an image reference, "" when there is none.
func imageTag(image string) string {
	ref := image
	if i := strings.Index(ref, "@"); i >= 0 {
		return "@" + ref[i+1:]
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon <= slash {
		return ""
	}
	return ref[colon+1:]
}

// versionLess compares dotted versions numerically (prefix "v" ignored);
// pre-release suffixes are ignored. It returns false when either side does
// not parse.
func versionLess(a, b string) bool {
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	if !oka || !okb {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func parseVersion(s string) ([3]int, bool) {
	var out [3]int
	m := versionTag.FindStringSubmatch(s)
	if m == nil {
		return out, false
	}
	for i := 1; i <= 3; i++ {
		if m[i] == "" {
			continue
		}
		fmt.Sscanf(m[i], "%d", &out[i-1])
	}
	return out, true
}

type ctx struct {
	in  Input
	res Result
}

func (c *ctx) active(s *compose.Service) bool {
	return c.in.AllProfiles || s.Active(c.in.Project.Profiles)
}

// setting is a resolved container variable and where it was decided.
type setting struct {
	value   string
	set     bool
	file    string
	line    int
	service string
}

// env resolves a variable in a service's container environment. When the
// variable is not set, value is def and the location is the service.
func (c *ctx) env(s *compose.Service, key, def string) setting {
	if v, ok := s.Env[key]; ok {
		return setting{value: v.Value, set: true, file: v.File, line: v.Line, service: s.Name}
	}
	return setting{value: def, service: s.Name, file: c.in.Project.File, line: s.Line}
}

func (c *ctx) add(id string, d Detected, st setting, msg string) {
	r := RuleByID(id)
	if r == nil {
		panic("unknown rule " + id)
	}
	c.res.Findings = append(c.res.Findings, Finding{
		RuleID: r.ID, Severity: r.Severity, Title: r.Title, Message: msg,
		Product: d.Product, Service: st.service, File: st.file, Line: st.line,
	})
}

// Mask shows enough of a secret to recognise it without printing it.
func Mask(s string) string {
	if s == "" {
		return `""`
	}
	if len(s) <= 6 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 4) + fmt.Sprintf(" (%d chars)", len(s))
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	}
	return false
}

func falsy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false", "f", "no", "n", "off":
		return true
	}
	return false
}
