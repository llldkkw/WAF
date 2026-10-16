package actions

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/llldkkw/waf/internal/secure"
)

func TestLinks(t *testing.T) {
	box, err := secure.LoadOrCreateKey(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	if NewSigner(box, "") != nil || NewSigner(box, "").ForAttacker("1.2.3.4") != nil {
		t.Fatal("no public URL must disable links")
	}
	s := NewSigner(box, "https://10.8.0.1:9443/")
	links := s.ForBanned("203.0.113.9")
	if len(links) != 3 || !strings.HasPrefix(links[0].URL, "https://10.8.0.1:9443/actions?t=") {
		t.Fatalf("links: %+v", links)
	}
	u, _ := url.Parse(links[0].URL)
	tok := u.Query().Get("t")
	c, err := Verify(box, tok)
	if err != nil || c.Action != Unban || c.IP != "203.0.113.9" {
		t.Fatalf("verify: %+v %v", c, err)
	}
	// Tampering with the payload breaks the signature.
	if _, err := Verify(box, "x"+tok); err == nil {
		t.Fatal("tampered token accepted")
	}
	other, _ := secure.LoadOrCreateKey(filepath.Join(t.TempDir(), "k2"))
	if _, err := Verify(other, tok); err == nil {
		t.Fatal("token accepted with another key")
	}
}
