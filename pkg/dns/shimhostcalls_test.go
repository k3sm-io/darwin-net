/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dns

import (
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The two functions in shim/getaddrinfo_shim.c allowed to call the real
// getaddrinfo. k3sm_host_getaddrinfo is the host-resolver chokepoint that traces
// every host consult under K3SM_DNS_DEBUG; k3sm_service_port performs a
// service-only lookup (a NULL node) that resolves no name.
const (
	hostChokepointFunc = "k3sm_host_getaddrinfo"
	servicePortFunc    = "k3sm_service_port"
)

// hostCallRE matches a call to the real getaddrinfo: the identifier must not be
// preceded by an identifier character, so k3sm_getaddrinfo( and
// k3sm_host_getaddrinfo( are not calls to it.
var hostCallRE = regexp.MustCompile(`(^|[^A-Za-z0-9_])getaddrinfo\s*\(`)

// hostCall is one call to the real getaddrinfo found in C source.
type hostCall struct {
	fn       string // enclosing top-level function, "" at file scope
	firstArg string // the first argument's text, trimmed
}

// stripC returns src with comments removed and the contents of string and
// character literals blanked, preserving every newline and brace outside them,
// so a call written in a comment or a string is never counted.
func stripC(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	const (
		code = iota
		lineComment
		blockComment
		str
		chr
	)
	state := code
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch state {
		case code:
			switch {
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				state = lineComment
				i++
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				state = blockComment
				b.WriteByte(' ')
				i++
			case c == '"':
				state = str
				b.WriteByte('"')
			case c == '\'':
				state = chr
				b.WriteByte('\'')
			default:
				b.WriteByte(c)
			}
		case lineComment:
			if c == '\n' {
				state = code
				b.WriteByte('\n')
			}
		case blockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				state = code
				i++
			} else if c == '\n' {
				b.WriteByte('\n')
			}
		case str, chr:
			quote := byte('"')
			if state == chr {
				quote = '\''
			}
			switch {
			case c == '\\':
				i++ // skip the escaped byte
			case c == quote:
				state = code
				b.WriteByte(quote)
			case c == '\n':
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

// funcSpan is a top-level brace block and the function name it belongs to.
type funcSpan struct {
	name       string
	start, end int // offsets of the opening and closing brace
}

// topLevelSpans finds every top-level brace block in stripped C source and
// names it after the identifier that precedes the parameter list closing just
// before the brace ("int f(void) {" is f). A block that is not a function body
// (an initializer, a struct) gets whatever that rule yields, usually "".
func topLevelSpans(src string) []funcSpan {
	var spans []funcSpan
	depth := 0
	headerStart := 0
	cur := funcSpan{}
	for i := 0; i < len(src); i++ {
		switch src[i] {
		case '{':
			if depth == 0 {
				cur = funcSpan{name: funcNameFromHeader(src[headerStart:i]), start: i}
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				cur.end = i
				spans = append(spans, cur)
				headerStart = i + 1
			}
		case ';':
			if depth == 0 {
				headerStart = i + 1
			}
		}
	}
	return spans
}

var identBeforeParenRE = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*$`)

// funcNameFromHeader returns the function name in a definition header: the
// identifier immediately before the parenthesized list the header ends with.
func funcNameFromHeader(h string) string {
	h = strings.TrimSpace(h)
	if !strings.HasSuffix(h, ")") {
		return ""
	}
	depth := 0
	for i := len(h) - 1; i >= 0; i-- {
		switch h[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				if m := identBeforeParenRE.FindStringSubmatch(h[:i]); m != nil {
					return m[1]
				}
				return ""
			}
		}
	}
	return ""
}

// findHostCalls returns every call to the real getaddrinfo in C source, each
// attributed to its enclosing top-level function.
func findHostCalls(src string) []hostCall {
	stripped := stripC(src)
	spans := topLevelSpans(stripped)
	var calls []hostCall
	for _, loc := range hostCallRE.FindAllStringIndex(stripped, -1) {
		open := loc[1] - 1 // the '('
		fn := ""
		for _, s := range spans {
			if open > s.start && open < s.end {
				fn = s.name
				break
			}
		}
		calls = append(calls, hostCall{fn: fn, firstArg: firstCallArg(stripped[open+1:])})
	}
	return calls
}

// firstCallArg returns the trimmed text of the first argument of a call whose
// argument list starts at s (just after the opening parenthesis).
func firstCallArg(s string) string {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return strings.TrimSpace(s[:i])
			}
			depth--
		case ',':
			if depth == 0 {
				return strings.TrimSpace(s[:i])
			}
		}
	}
	return strings.TrimSpace(s)
}

// hostCallProblems checks the chokepoint contract over C source and returns a
// description of every violation (nil when the source conforms): the real
// getaddrinfo is called from exactly the two allowed functions, and every call
// in the service-port function passes a literal NULL node.
func hostCallProblems(src string) []string {
	var problems []string
	callers := map[string]bool{}
	for _, c := range findHostCalls(src) {
		callers[c.fn] = true
		if c.fn == servicePortFunc && c.firstArg != "NULL" {
			problems = append(problems, "the "+servicePortFunc+" call passes node "+c.firstArg+", want a literal NULL (a service-only lookup that resolves no name)")
		}
	}
	got := make([]string, 0, len(callers))
	for fn := range callers {
		if fn == "" {
			fn = "<file scope>"
		}
		got = append(got, fn)
	}
	sort.Strings(got)
	want := []string{hostChokepointFunc, servicePortFunc}
	if !slices.Equal(got, want) {
		problems = append(problems, "functions calling the real getaddrinfo = "+strings.Join(got, ", ")+"; want exactly "+strings.Join(want, ", "))
	}
	return problems
}

// TestShimHostCallsUseChokepoint pins that every host-resolver consult in the
// shim passes the traced chokepoint, so a test that observes "no HOST trace
// line" has observed every host path. It reads the .c as text, strips comments
// and literals, and attributes each real getaddrinfo( call to its enclosing
// function. The self-test table proves the checker goes red on the shapes it
// exists to catch, so a green verdict is not a vacuous one.
func TestShimHostCallsUseChokepoint(t *testing.T) {
	t.Run("self-test", func(t *testing.T) {
		const good = `
int k3sm_host_getaddrinfo(const char *r, const char *n, const char *s,
                          const struct addrinfo *h, struct addrinfo **res) {
    if (dbg) { fprintf(stderr, "k3sm-dns: HOST %s node=%s\n", r, n); }
    return getaddrinfo(n, s, h, res);
}
static int k3sm_service_port(const char *service, uint16_t *port) {
    struct addrinfo *r = NULL;
    int rc = getaddrinfo(NULL, service, &h, &r);
    return rc;
}
`
		tests := []struct {
			name    string
			src     string
			wantRed bool
		}{
			{name: "the two allowed functions conform", src: good},
			{name: "a call in a block comment of a third function is ignored",
				src: good + "int other(void) { /* return getaddrinfo(n, s, h, r); */ return 0; }\n"},
			{name: "a call in a line comment is ignored",
				src: good + "int other(void) {\n  // getaddrinfo(n, s, h, r);\n  return 0;\n}\n"},
			{name: "a call spelled inside a string literal is ignored",
				src: good + "int other(void) { puts(\"getaddrinfo(x)\"); return 0; }\n"},
			{name: "a k3sm_-prefixed function call is ignored",
				src: good + "int other(void) { return k3sm_getaddrinfo(n, s, h, r) + k3sm_host_getaddrinfo(\"x\", n, s, h, r); }\n"},
			{name: "an interpose table entry is not a call",
				src: good + "static const interpose_t t[] __attribute__((section(\"__DATA,__interpose\"))) = {\n  {(const void *)k3sm_getaddrinfo, (const void *)getaddrinfo},\n};\n"},
			{name: "a real call in a third function is flagged", wantRed: true,
				src: good + "int other(const char *n) {\n  if (n) { return getaddrinfo(n, 0, 0, 0); }\n  return 0;\n}\n"},
			{name: "a call with whitespace before the paren is flagged", wantRed: true,
				src: good + "int other(void) { return getaddrinfo (n, 0, 0, 0); }\n"},
			{name: "a call at file scope is flagged", wantRed: true,
				src: good + "int x = getaddrinfo(n, 0, 0, 0);\n"},
			{name: "a service-port call with a non-NULL node is flagged", wantRed: true,
				src: strings.Replace(good, "getaddrinfo(NULL, service", "getaddrinfo(node, service", 1)},
			{name: "a missing chokepoint is flagged", wantRed: true,
				src: strings.Replace(good, "return getaddrinfo(n, s, h, res);", "return 0;", 1)},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				problems := hostCallProblems(tt.src)
				if red := len(problems) > 0; red != tt.wantRed {
					t.Fatalf("hostCallProblems red = %v, want %v; problems: %v", red, tt.wantRed, problems)
				}
			})
		}
	})

	const shimPath = "../../shim/getaddrinfo_shim.c"
	src, err := os.ReadFile(shimPath)
	if err != nil {
		t.Fatalf("read shim source %s: %v", shimPath, err)
	}
	if problems := hostCallProblems(string(src)); len(problems) > 0 {
		for _, p := range problems {
			t.Errorf("%s: %s", shimPath, p)
		}
		for _, c := range findHostCalls(string(src)) {
			t.Logf("real getaddrinfo call in %q (first arg %q)", c.fn, c.firstArg)
		}
	}
}
