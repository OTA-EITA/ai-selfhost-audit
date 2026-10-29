// Command ai-selfhost-audit reads a docker-compose file (and its .env) for
// self-hosted AI platforms (n8n, Open WebUI, LiteLLM, Langflow, Flowise) and
// reports insecure defaults. It only reads files; it never contacts Docker or
// the network.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/OTA-EITA/ai-selfhost-audit/internal/checks"
	"github.com/OTA-EITA/ai-selfhost-audit/internal/compose"
	"github.com/OTA-EITA/ai-selfhost-audit/internal/envfile"
	"github.com/OTA-EITA/ai-selfhost-audit/internal/report"
)

var version = "dev"

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("ai-selfhost-audit", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var envFiles multi
	fl.Var(&envFiles, "env", "env file to read (repeatable; later files win). Default: .env next to the compose file, or ./.env")
	composePath := fl.String("compose", "", "docker-compose.yaml to read. Default: ./docker-compose.yaml if it exists")
	format := fl.String("format", "table", "output format: table, json or sarif")
	failOn := fl.String("fail-on", "high", "exit 1 when a finding is at or above this severity: info, low, medium, high, none")
	allProfiles := fl.Bool("all-profiles", false, "also check services whose compose profile is not active")
	listRules := fl.Bool("list-rules", false, "print the rule catalogue and exit")
	showVersion := fl.Bool("version", false, "print version and exit")
	fl.Usage = func() {
		fmt.Fprintf(stderr, "Usage: ai-selfhost-audit [--compose docker-compose.yaml] [--env .env ...] [flags]\n\n")
		fmt.Fprintf(stderr, "Supported: %s\n\n", strings.Join(checks.Products(), ", "))
		fl.PrintDefaults()
		fmt.Fprintf(stderr, "\nExit codes: 0 nothing at or above --fail-on, 1 findings at or above --fail-on, 2 usage or parse error.\n")
	}
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fl.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n", fl.Arg(0))
		fl.Usage()
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if *listRules {
		for _, r := range checks.Rules {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", r.ID, r.Product, r.Severity, r.Title)
		}
		return 0
	}
	threshold, err := checks.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	if *composePath == "" {
		for _, name := range []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"} {
			if exists(name) {
				*composePath = name
				break
			}
		}
	}
	if len(envFiles) == 0 {
		dir := "."
		if *composePath != "" {
			dir = filepath.Dir(*composePath)
		}
		if p := filepath.Join(dir, ".env"); exists(p) {
			envFiles = append(envFiles, p)
		}
	}
	if *composePath == "" {
		fmt.Fprintln(stderr, "nothing to check: pass --compose (no compose.yaml or docker-compose.yaml in this directory)")
		return 2
	}

	env := envfile.New()
	for _, p := range envFiles {
		e, err := envfile.ParseFile(p, env)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		env.Merge(e)
	}

	meta := report.Meta{Tool: "ai-selfhost-audit", Version: version, EnvFiles: envFiles}
	p, err := compose.Load(*composePath, env)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	meta.ComposeFile = *composePath
	meta.Profiles = p.SortedProfiles()
	meta.Notes = p.Notes

	res := checks.Run(checks.Input{Env: env, Project: p, AllProfiles: *allProfiles})
	if len(res.Detected) == 0 {
		meta.Notes = append(meta.Notes, "no supported platform found in the compose file (supported: "+strings.Join(checks.Products(), ", ")+"); only container-level checks ran")
	}
	for _, d := range res.Detected {
		v := d.Version
		if v == "" {
			v = "version unknown"
		}
		meta.Detected = append(meta.Detected, fmt.Sprintf("%s (service %s, %s)", d.Product, d.Service.Name, v))
	}
	if err := report.Write(stdout, *format, res, meta); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	for _, f := range res.Findings {
		if f.Severity >= threshold {
			return 1
		}
	}
	return 0
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}
