package checks

import (
	"strings"

	"github.com/OTA-EITA/ai-selfhost-audit/internal/compose"
)

// val returns the variable, treating an empty value as unset. Several
// upstream compose files pass every variable as KEY=${KEY}, so an unset
// variable reaches the container as "".
func (c *ctx) val(s *compose.Service, key, def string) setting {
	st := c.env(s, key, def)
	if st.set && strings.TrimSpace(st.value) == "" {
		st.value = def
		st.set = false
	}
	return st
}

// isTrue reports whether the variable is set to a true value.
func (c *ctx) isTrue(s *compose.Service, key string) (setting, bool) {
	st := c.val(s, key, "")
	return st, st.set && truthy(st.value)
}

// isFalse reports whether the variable is set to a false value.
func (c *ctx) isFalse(s *compose.Service, key string) (setting, bool) {
	st := c.val(s, key, "")
	return st, st.set && falsy(st.value)
}

// publishedEverywhere reports whether any port of the service is published
// on all host interfaces.
func publishedEverywhere(s *compose.Service) bool {
	for _, p := range s.Ports {
		if p.AllInterfaces() {
			return true
		}
	}
	return false
}

// listHas reports whether a comma or space separated list contains any of
// the items (case-insensitive).
func listHas(list string, items ...string) []string {
	var hit []string
	for _, f := range strings.FieldsFunc(strings.ToLower(list), func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		for _, it := range items {
			if f == it {
				hit = append(hit, f)
			}
		}
	}
	return hit
}

// weakSecret reports whether a secret value is a known example or too short.
func weakSecret(v string, examples []string, minLen int) bool {
	l := strings.ToLower(strings.TrimSpace(v))
	for _, e := range examples {
		if l == strings.ToLower(e) {
			return true
		}
	}
	if strings.HasPrefix(l, "change-me") || strings.HasPrefix(l, "changeme") || strings.HasPrefix(l, "your-") || strings.HasPrefix(l, "your_") {
		return true
	}
	return minLen > 0 && len(v) < minLen
}
