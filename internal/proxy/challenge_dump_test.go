package proxy

import (
	"os"
	"testing"

	"github.com/llldkkw/waf/internal/store"
)

// Writes a rendered challenge page for the browser-side solver check
// (CHALLENGE_DUMP=path go test -run TestDumpChallenge).
func TestDumpChallenge(t *testing.T) {
	out := os.Getenv("CHALLENGE_DUMP")
	if out == "" {
		t.Skip("CHALLENGE_DUMP not set")
	}
	be := backend(t)
	p, _ := setup(t, store.Site{Name: "a", Enabled: true, Hosts: []string{"a.test"}, Upstreams: []string{be.URL},
		Mode: store.ModeOff, Challenge: store.Challenge{Mode: "always", Difficulty: 18}}, "")
	w := do(p, "GET", "http://a.test/", "198.51.100.1:1", nil)
	if err := os.WriteFile(out, w.Body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
