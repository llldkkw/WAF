package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/llldkkw/waf/internal/notify"
	"github.com/llldkkw/waf/internal/store"
)

func pathID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func queryInt(r *http.Request, k string) int64 {
	v, _ := strconv.ParseInt(r.URL.Query().Get(k), 10, 64)
	return v
}

// changed records an audit entry and notifies about configuration changes.
func (s *Server) changed(r *http.Request, action, target string, detail any) {
	d := ""
	if detail != nil {
		b, _ := json.Marshal(detail)
		d = string(b)
	}
	s.audit(r, action, target, d)
	s.nt.Notify(notify.Message{
		Level: notify.Info, Kind: "config",
		Title: "配置变更",
		Body:  fmt.Sprintf("用户 %s (%s) 执行了 %s: %s", userFrom(r).Username, remoteIP(r), actionLabel(action), target),
	})
}

func actionLabel(a string) string {
	if l, ok := map[string]string{
		"site_create": "新建站点", "site_update": "修改站点", "site_delete": "删除站点", "rule_exclusion": "添加误报排除",
		"ip_add": "添加 IP 规则", "ip_delete": "删除 IP 规则",
		"channel_save": "保存通知渠道", "channel_delete": "删除通知渠道",
		"user_create": "新建用户", "user_update": "修改用户", "user_delete": "删除用户", "user_reset": "重置用户凭据",
	}[a]; ok {
		return l
	}
	return a
}

// --- dashboard ---

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	var (
		span   time.Duration
		bucket int64
	)
	switch r.URL.Query().Get("range") {
	case "1h":
		span, bucket = time.Hour, 60
	case "7d":
		span, bucket = 7*24*time.Hour, 3600
	case "30d":
		span, bucket = 30*24*time.Hour, 6*3600
	default:
		span, bucket = 24*time.Hour, 900
	}
	ov, err := s.st.Overview(r.Context(), time.Now().Add(-span).Unix(), bucket, queryInt(r, "site"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"overview": ov, "bucket": bucket})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	writeJSON(w, map[string]any{
		"version":    s.version,
		"uptime":     int64(time.Since(s.started).Seconds()),
		"goroutines": runtime.NumGoroutine(),
		"memory_mb":  m.Alloc >> 20,
		"proxy":      s.px.Status(),
		"acme":       s.cfg.ACME.Enabled,
	})
}

// --- sites ---

func (s *Server) handleListSites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.st.ListSites(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"sites": sites})
}

func (s *Server) handleGetSite(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	st, err := s.st.GetSite(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, errors.New("站点不存在"))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"site": st})
}

func (s *Server) handleSaveSite(w http.ResponseWriter, r *http.Request) {
	var site store.Site
	if !decode(w, r, &site) {
		return
	}
	site.ID = 0
	if r.Method == http.MethodPut {
		id, err := pathID(r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		site.ID = id
	}
	if err := site.Normalize(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.checkHostConflict(r, &site); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	action := "site_update"
	if site.ID == 0 {
		action = "site_create"
	}
	if err := s.st.SaveSite(r.Context(), &site); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, errors.New("站点不存在"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.changed(r, action, site.Name, site)
	writeJSON(w, map[string]any{"site": site})
}

func (s *Server) checkHostConflict(r *http.Request, site *store.Site) error {
	all, err := s.st.ListSites(r.Context())
	if err != nil {
		return err
	}
	for _, o := range all {
		if o.ID == site.ID {
			continue
		}
		for _, h := range o.Hosts {
			for _, n := range site.Hosts {
				if h == n {
					return fmt.Errorf("域名 %s 已被站点 %q 使用", n, o.Name)
				}
			}
		}
	}
	return nil
}

func (s *Server) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	st, err := s.st.GetSite(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, errors.New("站点不存在"))
		return
	}
	if err := s.st.DeleteSite(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.changed(r, "site_delete", st.Name, nil)
	writeJSON(w, map[string]bool{"ok": true})
}

// handleAddExclusion is the one-click "this was a false positive" action.
func (s *Server) handleAddExclusion(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	var ex store.RuleExclusion
	if !decode(w, r, &ex) {
		return
	}
	st, err := s.st.GetSite(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, errors.New("站点不存在"))
		return
	}
	for _, e := range st.RuleExclusions {
		if e.RuleID == ex.RuleID && e.Path == ex.Path {
			writeJSON(w, map[string]any{"site": st})
			return
		}
	}
	st.RuleExclusions = append(st.RuleExclusions, ex)
	if err := st.Normalize(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.st.SaveSite(r.Context(), st); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.changed(r, "rule_exclusion", fmt.Sprintf("%s 规则 %d %s", st.Name, ex.RuleID, ex.Path), ex)
	writeJSON(w, map[string]any{"site": st})
}

// --- IP rules ---

func (s *Server) handleListIPRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.st.ListIPRules(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"rules": rules})
}

type ipRuleReq struct {
	CIDR    string `json:"cidr"`
	Action  string `json:"action"`
	SiteID  int64  `json:"site_id"`
	Note    string `json:"note"`
	Minutes int    `json:"minutes"` // 0 = permanent
}

func (s *Server) handleAddIPRule(w http.ResponseWriter, r *http.Request) {
	var req ipRuleReq
	if !decode(w, r, &req) {
		return
	}
	rule := &store.IPRule{CIDR: req.CIDR, Action: req.Action, SiteID: req.SiteID, Note: truncate(req.Note, 200), CreatedBy: userFrom(r).Username}
	if req.Minutes > 0 {
		rule.ExpiresAt = time.Now().Add(time.Duration(req.Minutes) * time.Minute).Unix()
	}
	if err := rule.Normalize(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// Guard against an operator banning the address they are managing from.
	if rule.Action == store.IPDeny && rule.SiteID == 0 && strings.HasSuffix(rule.CIDR, "/0") {
		writeErr(w, http.StatusBadRequest, errors.New("不允许封禁全部地址"))
		return
	}
	if err := s.st.AddIPRule(r.Context(), rule); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.changed(r, "ip_add", rule.Action+" "+rule.CIDR, rule)
	writeJSON(w, map[string]any{"rule": rule})
}

func (s *Server) handleDeleteIPRule(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	if err := s.st.DeleteIPRule(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.changed(r, "ip_delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, map[string]bool{"ok": true})
}

// --- events & audit ---

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{
		From: queryInt(r, "from"), To: queryInt(r, "to"), SiteID: queryInt(r, "site"),
		IP: q.Get("ip"), Action: q.Get("action"), Category: q.Get("category"), Query: q.Get("q"),
		Limit: int(queryInt(r, "limit")), Offset: int(queryInt(r, "offset")),
	}
	evs, total, err := s.st.QueryEvents(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"events": evs, "total": total})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	list, total, err := s.st.ListAudit(r.Context(), int(queryInt(r, "limit")), int(queryInt(r, "offset")))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"entries": list, "total": total})
}

// --- notification channels ---

const secretMask = "••••••"

func (s *Server) handleChannelTypes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"types": notify.ChannelTypes})
}

func (s *Server) handleListChannels(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListChannels(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	for i := range list {
		cfg, err := s.nt.DecryptConfig(list[i].ConfigEnc)
		if err != nil {
			cfg = map[string]string{}
		}
		secret := notify.SecretKeys(list[i].Type)
		for k, v := range cfg {
			if secret[k] && v != "" {
				cfg[k] = secretMask
			}
		}
		list[i].Config = cfg
	}
	writeJSON(w, map[string]any{"channels": list})
}

func (s *Server) handleSaveChannel(w http.ResponseWriter, r *http.Request) {
	var c store.Channel
	if !decode(w, r, &c) {
		return
	}
	c.ID = 0
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		writeErr(w, http.StatusBadRequest, errors.New("名称不能为空"))
		return
	}
	if _, err := notify.ParseLevel(c.MinLevel); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if c.MinLevel == "" {
		c.MinLevel = "warning"
	}
	if c.Config == nil {
		c.Config = map[string]string{}
	}
	if r.Method == http.MethodPut {
		id, _ := pathID(r)
		c.ID = id
		// Masked secrets mean "unchanged": restore them from the stored config.
		old, err := s.channelConfig(r, id)
		if err != nil {
			writeErr(w, http.StatusNotFound, errors.New("渠道不存在"))
			return
		}
		for k, v := range c.Config {
			if v == secretMask {
				c.Config[k] = old[k]
			}
		}
	}
	if err := notify.ValidateConfig(c.Type, c.Config); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	enc, err := s.nt.EncryptConfig(c.Config)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	c.ConfigEnc = enc
	if err := s.st.SaveChannel(r.Context(), &c); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.nt.Reload(r.Context())
	s.changed(r, "channel_save", c.Name, map[string]any{"type": c.Type, "min_level": c.MinLevel, "enabled": c.Enabled})
	writeJSON(w, map[string]any{"id": c.ID})
}

func (s *Server) channelConfig(r *http.Request, id int64) (map[string]string, error) {
	list, err := s.st.ListChannels(r.Context())
	if err != nil {
		return nil, err
	}
	for _, c := range list {
		if c.ID == id {
			return s.nt.DecryptConfig(c.ConfigEnc)
		}
	}
	return nil, store.ErrNotFound
}

func (s *Server) handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	if err := s.st.DeleteChannel(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.nt.Reload(r.Context())
	s.changed(r, "channel_delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	list, err := s.st.ListChannels(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	for _, c := range list {
		if c.ID != id {
			continue
		}
		cfg, err := s.nt.DecryptConfig(c.ConfigEnc)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if err := s.nt.Test(r.Context(), c.Type, cfg); err != nil {
			writeErr(w, http.StatusBadGateway, fmt.Errorf("发送失败: %v", err))
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
		return
	}
	writeErr(w, http.StatusNotFound, errors.New("渠道不存在"))
}
