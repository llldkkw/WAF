package admin

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/llldkkw/waf/internal/actions"
	"github.com/llldkkw/waf/internal/report"
	"github.com/llldkkw/waf/internal/store"
)

// --- certificates ---

type certReq struct {
	Name string `json:"name"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListCerts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"certs": list})
}

func (s *Server) handleSaveCert(w http.ResponseWriter, r *http.Request) {
	var req certReq
	if !decode(w, r, &req) {
		return
	}
	c, err := store.ParseCertificate(strings.TrimSpace(req.Cert)+"\n", strings.TrimSpace(req.Key)+"\n")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	c.Name = strings.TrimSpace(req.Name)
	if c.Name == "" {
		c.Name = c.Domains[0]
	}
	if c.KeyEnc, err = s.box.Seal([]byte(strings.TrimSpace(req.Key) + "\n")); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	action := "cert_upload"
	if r.Method == http.MethodPut {
		if c.ID, err = pathID(r); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		action = "cert_replace"
	}
	if err := s.st.SaveCert(r.Context(), c); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, errors.New("证书不存在"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.changed(r, action, c.Name, map[string]any{"domains": c.Domains, "not_after": time.Unix(c.NotAfter, 0).Format("2006-01-02")})
	writeJSON(w, map[string]any{"cert": c})
}

func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	if err := s.st.DeleteCert(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.changed(r, "cert_delete", r.PathValue("id"), nil)
	writeJSON(w, map[string]bool{"ok": true})
}

// --- one-click action links ---

func (s *Server) handleInspectAction(w http.ResponseWriter, r *http.Request) {
	c, err := actions.Verify(s.box, r.URL.Query().Get("t"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	used, err := s.st.ActionNonceUsed(r.Context(), c.Nonce)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{
		"action": c.Action, "ip": c.IP, "minutes": c.Minutes, "reason": c.Reason,
		"expires_at": c.Exp, "used": used, "description": c.Describe(),
		"location": s.geo.Lookup(c.IP).String(),
	})
}

type actionReq struct {
	Token string `json:"token"`
}

func (s *Server) handleExecuteAction(w http.ResponseWriter, r *http.Request) {
	var req actionReq
	if !decode(w, r, &req) {
		return
	}
	c, err := actions.Verify(s.box, req.Token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ok, err := s.st.UseActionNonce(r.Context(), c.Nonce)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusConflict, errors.New("该链接已经使用过"))
		return
	}
	addr := netip.MustParseAddr(c.IP)
	cidr := netip.PrefixFrom(addr, addr.BitLen()).String()
	user := userFrom(r).Username
	switch c.Action {
	case actions.Ban:
		rule := &store.IPRule{CIDR: cidr, Action: store.IPDeny, Note: c.Reason, Source: "link", CreatedBy: user}
		if c.Minutes > 0 {
			rule.ExpiresAt = time.Now().Add(time.Duration(c.Minutes) * time.Minute).Unix()
		}
		err = s.st.AddIPRule(r.Context(), rule)
	case actions.Allow:
		err = s.st.AddIPRule(r.Context(), &store.IPRule{CIDR: cidr, Action: store.IPAllow, Note: c.Reason, Source: "link", CreatedBy: user})
	case actions.Unban:
		_, err = s.st.DeleteDenyRules(r.Context(), cidr)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.changed(r, "action_link", c.Describe(), c)
	writeJSON(w, map[string]any{"ok": true, "description": c.Describe()})
}

// --- reports ---

func (s *Server) handleGetReportSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.rep.Settings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"settings": st, "timezone": s.cfg.Timezone})
}

func (s *Server) handleSaveReportSettings(w http.ResponseWriter, r *http.Request) {
	var st report.Settings
	if !decode(w, r, &st) {
		return
	}
	if err := s.rep.SaveSettings(r.Context(), st); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.changed(r, "report_settings", "安全报告", st)
	writeJSON(w, map[string]any{"settings": st})
}

type sendReportReq struct {
	Period string `json:"period"` // daily, weekly
}

// handleSendReport sends a report for the last 24 hours / 7 days right now.
func (s *Server) handleSendReport(w http.ResponseWriter, r *http.Request) {
	var req sendReportReq
	if !decode(w, r, &req) {
		return
	}
	now := time.Now().In(s.cfg.Location())
	from, title := now.Add(-24*time.Hour), "安全报告（近 24 小时）"
	if req.Period == "weekly" {
		from, title = now.AddDate(0, 0, -7), "安全报告（近 7 天）"
	}
	m, err := s.rep.Build(r.Context(), from, now, title)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.nt.Notify(*m)
	writeJSON(w, map[string]any{"ok": true, "preview": m.Body})
}
