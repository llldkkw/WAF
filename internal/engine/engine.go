// Package engine builds Coraza WAF instances (OWASP CRS) per site and turns
// their verdicts into events.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/llldkkw/waf/internal/store"
)

// Cache reuses compiled WAFs across reloads: compiling the CRS is expensive,
// and most config changes do not touch a site's rule settings.
type Cache struct {
	maxBody int64

	mu   sync.Mutex
	wafs map[string]coraza.WAF
}

func NewCache(maxBody int64) *Cache {
	return &Cache{maxBody: maxBody, wafs: map[string]coraza.WAF{}}
}

// Get returns a WAF for the site, or nil when the site's mode is off.
func (c *Cache) Get(s *store.Site) (coraza.WAF, error) {
	if s.Mode == store.ModeOff {
		return nil, nil
	}
	directives := Directives(s, c.maxBody)
	sum := sha256.Sum256([]byte(directives))
	key := hex.EncodeToString(sum[:])

	c.mu.Lock()
	defer c.mu.Unlock()
	if w, ok := c.wafs[key]; ok {
		return w, nil
	}
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(directives))
	if err != nil {
		return nil, fmt.Errorf("site %q: %w", s.Name, err)
	}
	c.wafs[key] = w
	return w, nil
}

// Retain drops cached WAFs not used by the given sites.
func (c *Cache) Retain(sites []store.Site) {
	keep := map[string]bool{}
	for i := range sites {
		sum := sha256.Sum256([]byte(Directives(&sites[i], c.maxBody)))
		keep[hex.EncodeToString(sum[:])] = true
	}
	c.mu.Lock()
	for k := range c.wafs {
		if !keep[k] {
			delete(c.wafs, k)
		}
	}
	c.mu.Unlock()
}

// Directives renders the SecLang configuration for a site. Inputs were
// validated by Site.Normalize (paths are restricted to a safe charset).
func Directives(s *store.Site, maxBody int64) string {
	var b strings.Builder
	engine := "On"
	if s.Mode == store.ModeDetect {
		engine = "DetectionOnly"
	}
	fmt.Fprintf(&b, `Include @coraza.conf-recommended
SecRuleEngine %s
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecAuditEngine Off
Include @crs-setup.conf.example
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=4"
`, engine, maxBody, min(maxBody, 1<<20), s.ParanoiaLevel, s.AnomalyThreshold)

	// Path-scoped exclusions must run before the CRS rules (phase 1, low IDs).
	exs := append([]store.RuleExclusion(nil), s.RuleExclusions...)
	sort.Slice(exs, func(i, j int) bool {
		if exs[i].RuleID != exs[j].RuleID {
			return exs[i].RuleID < exs[j].RuleID
		}
		return exs[i].Path < exs[j].Path
	})
	var global []string
	for i, ex := range exs {
		if ex.Path == "" {
			global = append(global, strconv.Itoa(ex.RuleID))
			continue
		}
		fmt.Fprintf(&b, "SecRule REQUEST_FILENAME \"@beginsWith %s\" \"id:%d,phase:1,pass,t:none,nolog,ctl:ruleRemoveById=%d\"\n",
			ex.Path, 10000+i, ex.RuleID)
	}
	b.WriteString("Include @owasp_crs/*.conf\n")
	if len(global) > 0 {
		b.WriteString("SecRuleRemoveById " + strings.Join(global, " ") + "\n")
	}
	return b.String()
}

// Verdict is the outcome of inspecting one request.
type Verdict struct {
	Interrupted bool
	Status      int
	// Would be blocked if the site were in block mode (detect mode).
	Detected bool
	RuleID   int
	Message  string
	Category string
	Severity string
	Matches  []store.Match
}

// Inspect runs phases 1-2 against the request. When the body is inspected,
// r.Body is replaced so the proxy can still forward it.
func Inspect(w coraza.WAF, detectOnly bool, r *http.Request, clientIP string, clientPort int) (*Verdict, func(), error) {
	tx := w.NewTransaction()
	done := func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}
	it, err := processRequest(tx, r, clientIP, clientPort)
	if err != nil {
		return nil, done, err
	}
	v := &Verdict{}
	collect(tx.MatchedRules(), v)
	if it != nil && it.Action != "allow" {
		v.Interrupted = true
		v.Status = it.Status
		if v.Status == 0 {
			v.Status = http.StatusForbidden
		}
		if v.RuleID == 0 {
			v.RuleID = it.RuleID
		}
	} else if detectOnly && anomalyExceeded(tx.MatchedRules()) {
		v.Detected = true
	}
	return v, done, nil
}

func processRequest(tx types.Transaction, r *http.Request, ip string, port int) (*types.Interruption, error) {
	tx.ProcessConnection(ip, port, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}
	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			return nil, err
		}
		if it != nil {
			return it, nil
		}
		rbr, err := tx.RequestBodyReader()
		if err != nil {
			return nil, err
		}
		r.Body = readCloser{io.MultiReader(rbr, r.Body), r.Body}
	}
	return tx.ProcessRequestBody()
}

type readCloser struct {
	io.Reader
	io.Closer
}

// CRS bookkeeping rules: they carry the final score, not the attack itself.
func isScoringRule(id int) bool {
	return id >= 949000 && id < 950000 || id >= 980000 && id < 981000 || id >= 900000 && id < 902000
}

func anomalyExceeded(ms []types.MatchedRule) bool {
	for _, m := range ms {
		if m.Rule().ID() == 949110 || m.Rule().ID() == 949111 {
			return true
		}
	}
	return false
}

// collect picks the most relevant matched rule (highest severity attack rule)
// as the headline and keeps the rest as details.
func collect(ms []types.MatchedRule, v *Verdict) {
	best := -1
	bestSev := 99
	for _, m := range ms {
		rule := m.Rule()
		id := rule.ID()
		if id == 0 || m.Message() == "" {
			continue
		}
		var variable string
		if md := m.MatchedDatas(); len(md) > 0 {
			variable = md[0].Variable().Name()
			if k := md[0].Key(); k != "" {
				variable += ":" + k
			}
		}
		v.Matches = append(v.Matches, store.Match{
			RuleID:   id,
			Message:  m.Message(),
			Data:     truncate(m.Data(), 300),
			Severity: severityName(rule.Severity()),
			Variable: variable,
		})
		if isScoringRule(id) {
			continue
		}
		sev := int(rule.Severity())
		if rule.Severity() == types.RuleSeverityUnset {
			sev = 50
		}
		if best == -1 || sev < bestSev {
			best, bestSev = len(v.Matches)-1, sev
			v.Category = Category(rule.Tags())
		}
	}
	if best >= 0 {
		bm := v.Matches[best]
		v.RuleID, v.Message, v.Severity = bm.RuleID, bm.Message, bm.Severity
	} else if len(v.Matches) > 0 {
		bm := v.Matches[0]
		v.RuleID, v.Message, v.Severity = bm.RuleID, bm.Message, bm.Severity
	}
	if len(v.Matches) > 20 {
		v.Matches = v.Matches[:20]
	}
}

// Category maps CRS tags to a short attack category.
func Category(tags []string) string {
	for _, t := range tags {
		if c, ok := strings.CutPrefix(t, "attack-"); ok {
			switch {
			case strings.HasPrefix(c, "reputation"):
				return "scanner"
			case c == "injection-generic":
				return "injection"
			}
			return c
		}
	}
	return ""
}

func severityName(s types.RuleSeverity) string {
	switch {
	case s == types.RuleSeverityUnset:
		return "notice"
	case s <= types.RuleSeverityCritical:
		return "critical"
	case s == types.RuleSeverityError:
		return "error"
	case s == types.RuleSeverityWarning:
		return "warning"
	}
	return "notice"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
