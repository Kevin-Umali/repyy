package app

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// gateTarget is one repository a shell command would clone, install from, or
// open. Target is a Git URL or an absolute local directory. A non-empty
// Unverifiable says why the guard cannot scan what the command would use.
type gateTarget struct {
	Kind         string `json:"kind"`
	Trigger      string `json:"trigger"`
	Target       string `json:"target"`
	Unverifiable string `json:"unverifiable,omitempty"`
}

const (
	gateClone   = "clone"
	gateInstall = "install"
	gateOpen    = "open"
	gateCompose = "compose"
)

// gateHandlers maps a program name to the repositories its arguments would
// touch. A program absent from this table never triggers a scan.
var gateHandlers = map[string]func(args []string, cwd string) []gateTarget{
	"git":            gitGate,
	"gh":             ghGate,
	"npm":            packageManagerGate("npm", []string{"install", "i", "ci", "add", "install-test", "it", "install-ci-test", "cit"}, false, "--prefix"),
	"pnpm":           packageManagerGate("pnpm", []string{"install", "i", "add"}, false, "-C", "--dir"),
	"yarn":           packageManagerGate("yarn", []string{"install", "add"}, true, "--cwd"),
	"bun":            packageManagerGate("bun", []string{"install", "i", "add"}, false, "--cwd"),
	"pip":            pipGate,
	"pip3":           pipGate,
	"python":         pythonGate,
	"python3":        pythonGate,
	"uv":             uvGate,
	"code":           editorGate("code"),
	"code-insiders":  editorGate("code-insiders"),
	"cursor":         editorGate("cursor"),
	"windsurf":       editorGate("windsurf"),
	"docker":         dockerGate,
	"docker-compose": composeGate("docker-compose"),
}

// wrapperOptions describes a program that runs its remaining arguments as a
// command, so its own options and leading operands can be skipped.
type wrapperOptions struct {
	short    string          // short options that take a value
	long     map[string]bool // long options that take a value
	operands int             // operands before the command, such as timeout's DURATION
	split    map[string]bool // options whose value is itself a command line (env -S)
	stdin    bool            // the command's trailing arguments come from stdin (xargs)
}

var commandWrappers = map[string]wrapperOptions{
	"sudo":    {short: "CDRTUghprtu", long: set("--chdir", "--chroot", "--close-from", "--command-timeout", "--group", "--host", "--other-user", "--prompt", "--role", "--type", "--user")},
	"doas":    {short: "Cu"},
	"env":     {short: "CSu", long: set("--chdir", "--split-string", "--unset"), split: set("-S", "--split-string")},
	"timeout": {short: "ks", long: set("--kill-after", "--signal"), operands: 1},
	"nice":    {short: "n", long: set("--adjustment")},
	"nohup":   {},
	"command": {},
	"builtin": {},
	"exec":    {short: "a"},
	"time":    {short: "fo", long: set("--format", "--output")},
	"xargs":   {short: "EILPadns", long: set("--arg-file", "--delimiter", "--max-args", "--max-chars", "--max-procs", "--process-slot-var"), stdin: true},
}

func set(values ...string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true}

// xargsInput stands in for the arguments xargs appends from stdin, so a handler
// still recognizes "xargs git clone" as a clone.
const xargsInput = "\x00stdin"

const stdinUnverifiable = "xargs supplies the arguments from stdin, which repyy guard cannot see"

// gateTargets returns the deduplicated repositories a shell command would
// clone, install, or open. It never expands variables or runs anything.
func gateTargets(command, cwd string) []gateTarget {
	var out []gateTarget
	type key struct{ kind, target, unverifiable string }
	seen := map[key]bool{}
	add := func(targets []gateTarget) {
		for _, t := range targets {
			if k := (key{t.Kind, t.Target, t.Unverifiable}); !seen[k] {
				seen[k] = true
				out = append(out, t)
			}
		}
	}
	for _, words := range shellSegments(command) {
		words, fromStdin := stripWrappers(words)
		if len(words) == 0 {
			continue
		}
		program := filepath.Base(words[0])
		if program == "cd" {
			if len(words) > 1 && !strings.HasPrefix(words[1], "-") {
				cwd = resolvePath(words[1], cwd)
			}
			continue
		}
		if shells[program] {
			if nested, ok := shellCommandString(words[1:]); ok {
				add(gateTargets(nested, cwd))
			}
			continue
		}
		handler := gateHandlers[program]
		if handler == nil {
			continue
		}
		if !fromStdin {
			add(handler(words[1:], cwd))
			continue
		}
		targets := handler(append(words[1:len(words):len(words)], xargsInput), cwd)
		for i := range targets {
			targets[i].Target, targets[i].Unverifiable = "(stdin)", stdinUnverifiable
		}
		add(targets)
	}
	return out
}

// shellCommandString returns the command string of `sh -c`, accepting option
// clusters such as -lc or -ec and long options before it.
func shellCommandString(args []string) (string, bool) {
	hasC := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--" || a == "-":
			if hasC && i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case strings.HasPrefix(a, "--"):
			if a == "--rcfile" || a == "--init-file" {
				i++
			}
		case strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+"):
			if a[0] == '-' && strings.ContainsRune(a[1:], 'c') {
				hasC = true
			}
			if strings.ContainsAny(a[1:], "oO") {
				i++
			}
		default:
			return a, hasC
		}
	}
	return "", false
}

// stripWrappers removes leading environment assignments and command wrappers
// with their options. fromStdin reports an xargs wrapper, whose command gets
// more arguments from stdin.
func stripWrappers(words []string) (rest []string, fromStdin bool) {
	for len(words) > 0 {
		if isEnvAssignment(words[0]) {
			words = words[1:]
			continue
		}
		wrapper, ok := commandWrappers[filepath.Base(words[0])]
		if !ok {
			break
		}
		fromStdin = fromStdin || wrapper.stdin
		words = wrapper.skip(words[1:])
	}
	return words, fromStdin
}

func (w wrapperOptions) skip(args []string) []string {
	var prefix []string
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			args = args[1:]
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		args = args[1:]
		name, value, hasValue := a, "", false
		if strings.HasPrefix(a, "--") {
			var inline bool
			name, value, inline = strings.Cut(a, "=")
			hasValue = inline || !w.long[name]
		} else {
			for j := 1; j < len(a); j++ {
				if strings.IndexByte(w.short, a[j]) >= 0 {
					name, value, hasValue = "-"+a[j:j+1], a[j+1:], a[j+1:] != ""
					break
				}
				hasValue = true
			}
		}
		if !hasValue && len(args) > 0 {
			value, args = args[0], args[1:]
		}
		if w.split[name] {
			for _, segment := range shellSegments(value) {
				prefix = append(prefix, segment...)
			}
		}
	}
	args = args[min(w.operands, len(args)):]
	return append(prefix, args...)
}

func isEnvAssignment(word string) bool {
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" {
		return false
	}
	for i, r := range name {
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (i == 0 || r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// shellSegments splits a command line into simple commands at control
// operators and tokenizes each with POSIX-style quoting. Unterminated quotes
// consume the rest of the input as one word.
func shellSegments(command string) [][]string {
	var segments [][]string
	var words []string
	var word strings.Builder
	inWord := false
	flushWord := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	flushSegment := func() {
		flushWord()
		if len(words) > 0 {
			segments = append(segments, words)
		}
		words = nil
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		switch {
		case c == '\\' && i+1 < len(command):
			i++
			if command[i] != '\n' {
				word.WriteByte(command[i])
				inWord = true
			}
		case c == '\'':
			inWord = true
			end := strings.IndexByte(command[i+1:], '\'')
			if end < 0 {
				word.WriteString(command[i+1:])
				i = len(command)
				break
			}
			word.WriteString(command[i+1 : i+1+end])
			i += end + 1
		case c == '"':
			inWord = true
			for i++; i < len(command) && command[i] != '"'; i++ {
				if command[i] == '\\' && i+1 < len(command) && strings.IndexByte("\"\\$`", command[i+1]) >= 0 {
					i++
				}
				word.WriteByte(command[i])
			}
		case c == ' ' || c == '\t':
			flushWord()
		case c == '\n' || c == ';' || c == '&' || c == '|' || c == '(' || c == ')':
			flushSegment()
		case c == '#' && !inWord:
			for i < len(command) && command[i] != '\n' {
				i++
			}
			flushSegment()
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	flushSegment()
	return segments
}

func resolvePath(path, cwd string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	return filepath.Clean(path)
}

func isRemoteURL(v string) bool {
	if strings.Contains(v, "://") {
		return true
	}
	// scp-like syntax: user@host:path
	at, colon := strings.IndexByte(v, '@'), strings.IndexByte(v, ':')
	return at > 0 && colon > at && !strings.ContainsRune(v[:at], '/')
}

// positionals returns the non-flag arguments, skipping the values of flags in
// valueFlags. "--" ends flag parsing.
func positionals(args []string, valueFlags map[string]bool) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return append(out, args[i+1:]...)
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			if valueFlags[a] {
				i++
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// flagValue returns the last value given for any of names, accepting both
// "--name value" and "--name=value".
func flagValue(args []string, names ...string) (string, bool) {
	value, found := "", false
	for i, a := range args {
		if a == "--" {
			break
		}
		for _, name := range names {
			if a == name && i+1 < len(args) {
				value, found = args[i+1], true
			} else if v, ok := strings.CutPrefix(a, name+"="); ok {
				value, found = v, true
			}
		}
	}
	return value, found
}

func hasFlag(args []string, names ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		for _, name := range names {
			if a == name {
				return true
			}
		}
	}
	return false
}

var gitGlobalValueFlags = map[string]bool{"-C": true, "-c": true, "--git-dir": true, "--work-tree": true, "--namespace": true, "--exec-path": true, "--config-env": true}

var gitCloneValueFlags = map[string]bool{
	"-b": true, "--branch": true, "-o": true, "--origin": true, "--depth": true, "-c": true, "--config": true,
	"--reference": true, "--reference-if-able": true, "--separate-git-dir": true, "-j": true, "--jobs": true,
	"--template": true, "--filter": true, "--shallow-since": true, "--shallow-exclude": true, "-u": true,
	"--upload-pack": true, "--server-option": true, "--bundle-uri": true, "--revision": true,
}

func gitGate(args []string, cwd string) []gateTarget {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-C" && i+1 < len(args) {
			cwd = resolvePath(args[i+1], cwd)
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			if gitGlobalValueFlags[a] {
				i++
			}
			continue
		}
		if a != "clone" {
			return nil
		}
		repos := positionals(args[i+1:], gitCloneValueFlags)
		if len(repos) == 0 {
			return nil
		}
		return []gateTarget{cloneGateTarget("git clone", cloneTarget(repos[0], cwd), args[i+1:])}
	}
	return nil
}

// cloneGateTarget blocks a clone of a non-default ref, because the guard's scan
// checks out only the default branch and would vouch for different code.
func cloneGateTarget(trigger, repo string, cloneArgs []string) gateTarget {
	target := gateTarget{Kind: gateClone, Trigger: trigger, Target: repo}
	for _, a := range cloneArgs {
		if a == "--" {
			break
		}
		if a == "-b" || a == "--branch" || a == "--revision" || strings.HasPrefix(a, "--branch=") || strings.HasPrefix(a, "--revision=") ||
			(strings.HasPrefix(a, "-b") && !strings.HasPrefix(a, "--")) {
			target.Unverifiable = "the scan checks the default branch; repyy guard cannot verify a clone of another ref"
			break
		}
	}
	return target
}

func cloneTarget(repo, cwd string) string {
	if isRemoteURL(repo) {
		return repo
	}
	return resolvePath(repo, cwd)
}

func ghGate(args []string, cwd string) []gateTarget {
	repos := positionals(args, map[string]bool{"-R": true, "--repo": true, "-u": true, "--upstream-remote-name": true})
	if len(repos) < 3 || repos[0] != "repo" || repos[1] != "clone" {
		return nil
	}
	repo := repos[2]
	if !isRemoteURL(repo) {
		parts := strings.Split(strings.TrimSuffix(repo, ".git"), "/")
		switch len(parts) {
		case 2:
			repo = "https://github.com/" + parts[0] + "/" + parts[1] + ".git"
		case 3:
			repo = "https://" + parts[0] + "/" + parts[1] + "/" + parts[2] + ".git"
		}
	}
	var gitArgs []string
	if i := slices.Index(args, "--"); i >= 0 {
		gitArgs = args[i+1:]
	}
	return []gateTarget{cloneGateTarget("gh repo clone", cloneTarget(repo, cwd), gitArgs)}
}

// packageManagerGate scans the project directory before a package manager
// installs into it, since installs run the project's lifecycle scripts.
func packageManagerGate(name string, verbs []string, bareInstalls bool, dirFlags ...string) func([]string, string) []gateTarget {
	verbSet := map[string]bool{}
	for _, v := range verbs {
		verbSet[v] = true
	}
	valueFlags := map[string]bool{}
	for _, f := range dirFlags {
		valueFlags[f] = true
	}
	return func(args []string, cwd string) []gateTarget {
		if hasFlag(args, "-g", "--global", "--location=global") {
			return nil
		}
		words := positionals(args, valueFlags)
		if len(words) == 0 && !bareInstalls {
			return nil
		}
		if len(words) > 0 && !verbSet[words[0]] {
			return nil
		}
		dir := cwd
		if value, ok := flagValue(args, dirFlags...); ok {
			dir = resolvePath(value, cwd)
		}
		trigger := name + " install"
		if len(words) > 0 {
			trigger = name + " " + words[0]
		}
		return []gateTarget{{Kind: gateInstall, Trigger: trigger, Target: dir}}
	}
}

var pipValueFlags = map[string]bool{
	"-r": true, "--requirement": true, "-c": true, "--constraint": true, "-e": true, "--editable": true,
	"-t": true, "--target": true, "-i": true, "--index-url": true, "--extra-index-url": true, "-f": true,
	"--find-links": true, "--prefix": true, "--root": true, "--src": true, "--upgrade-strategy": true,
	"--python-version": true, "--platform": true, "--implementation": true, "--abi": true, "--only-binary": true,
	"--no-binary": true, "--progress-bar": true, "--log": true, "--proxy": true, "--retries": true, "--timeout": true,
	"--exists-action": true, "--trusted-host": true, "--cert": true, "--client-cert": true, "--cache-dir": true,
	"--report": true, "--config-settings": true, "-C": true, "--python": true,
}

func pipGate(args []string, cwd string) []gateTarget {
	words := positionals(args, pipValueFlags)
	if len(words) == 0 || words[0] != "install" {
		return nil
	}
	var out []gateTarget
	paths := words[1:]
	if editable, ok := flagValue(args, "-e", "--editable"); ok {
		paths = append(paths, editable)
	}
	for _, p := range paths {
		if isLocalPathArg(p) {
			out = append(out, gateTarget{Kind: gateInstall, Trigger: "pip install", Target: resolvePath(p, cwd)})
		}
	}
	if _, ok := flagValue(args, "-r", "--requirement"); ok && len(out) == 0 {
		out = append(out, gateTarget{Kind: gateInstall, Trigger: "pip install -r", Target: cwd})
	}
	return out
}

func isLocalPathArg(p string) bool {
	return p == "." || p == ".." || strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~/")
}

func pythonGate(args []string, cwd string) []gateTarget {
	if len(args) >= 2 && args[0] == "-m" && args[1] == "pip" {
		return pipGate(args[2:], cwd)
	}
	return nil
}

func uvGate(args []string, cwd string) []gateTarget {
	if len(args) >= 1 && args[0] == "pip" {
		return pipGate(args[1:], cwd)
	}
	return nil
}

var editorValueFlags = map[string]bool{
	"-g": true, "--goto": true, "--folder-uri": true, "--file-uri": true, "--user-data-dir": true,
	"--extensions-dir": true, "--profile": true, "--install-extension": true, "--uninstall-extension": true,
	"--locale": true, "--log": true, "--sync": true, "--category": true,
}

// editorGate scans a directory before an editor opens it as a workspace, where
// workspace tasks and extensions recommendations can run.
func editorGate(name string) func([]string, string) []gateTarget {
	return func(args []string, cwd string) []gateTarget {
		var out []gateTarget
		for _, p := range positionals(args, editorValueFlags) {
			dir := resolvePath(p, cwd)
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				out = append(out, gateTarget{Kind: gateOpen, Trigger: name, Target: dir})
			}
		}
		return out
	}
}

func dockerGate(args []string, cwd string) []gateTarget {
	words := positionals(args, map[string]bool{"-H": true, "--host": true, "--context": true, "-c": true, "--config": true, "-l": true, "--log-level": true})
	if len(words) == 0 || words[0] != "compose" {
		return nil
	}
	for i, a := range args {
		if a == "compose" {
			return composeGate("docker compose")(args[i+1:], cwd)
		}
	}
	return nil
}

var composeValueFlags = map[string]bool{
	"-f": true, "--file": true, "-p": true, "--project-name": true, "--project-directory": true,
	"--env-file": true, "--profile": true, "--ansi": true, "--progress": true, "--parallel": true,
}

// composeGate scans the compose project before containers are built or
// started from it.
func composeGate(trigger string) func([]string, string) []gateTarget {
	return func(args []string, cwd string) []gateTarget {
		words := positionals(args, composeValueFlags)
		if len(words) == 0 || (words[0] != "up" && words[0] != "run" && words[0] != "build") {
			return nil
		}
		dir := cwd
		if file, ok := flagValue(args, "-f", "--file"); ok {
			dir = filepath.Dir(resolvePath(file, cwd))
		}
		if project, ok := flagValue(args, "--project-directory"); ok {
			dir = resolvePath(project, cwd)
		}
		return []gateTarget{{Kind: gateCompose, Trigger: trigger + " " + words[0], Target: dir}}
	}
}
