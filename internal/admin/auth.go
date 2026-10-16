package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/llldkkw/waf/internal/notify"
	"github.com/llldkkw/waf/internal/secure"
	"github.com/llldkkw/waf/internal/store"
)

const (
	cookieName   = "waf_session"
	minPasswdLen = 10
	issuer       = "WAF Gateway"
)

// A real hash to compare against when the user does not exist, so response
// timing does not reveal valid usernames.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)

func HashPassword(pw string) (string, error) {
	if len(pw) < minPasswdLen {
		return "", fmt.Errorf("密码至少 %d 位", minPasswdLen)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(h), err
}

// NewTOTP generates a TOTP key for a user.
func NewTOTP(username string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: username})
}

// throttle limits failed logins per key (IP or username).
type throttle struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

const (
	maxFails   = 5
	failWindow = 15 * time.Minute
)

func newThrottle() *throttle { return &throttle{fails: map[string][]time.Time{}} }

func (t *throttle) blocked(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.recent(key)) >= maxFails
}

func (t *throttle) fail(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := append(t.recent(key), time.Now())
	t.fails[key] = f
	return len(f)
}

func (t *throttle) clear(key string) {
	t.mu.Lock()
	delete(t.fails, key)
	t.mu.Unlock()
}

func (t *throttle) recent(key string) []time.Time {
	cut := time.Now().Add(-failWindow)
	f := t.fails[key]
	i := 0
	for i < len(f) && f[i].Before(cut) {
		i++
	}
	f = f[i:]
	if len(f) == 0 {
		delete(t.fails, key)
	} else {
		t.fails[key] = f
	}
	return f
}

// totpGuard rejects re-use of a code within its validity window.
type totpGuard struct {
	mu   sync.Mutex
	used map[int64]map[string]time.Time
}

func (g *totpGuard) use(userID int64, code string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.used == nil {
		g.used = map[int64]map[string]time.Time{}
	}
	m := g.used[userID]
	if m == nil {
		m = map[string]time.Time{}
		g.used[userID] = m
	}
	now := time.Now()
	for c, t := range m {
		if now.Sub(t) > 2*time.Minute {
			delete(m, c)
		}
	}
	if _, ok := m[code]; ok {
		return false
	}
	m[code] = now
	return true
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

var errBadLogin = errors.New("用户名、密码或验证码错误")

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !decode(w, r, &req) {
		return
	}
	ip := remoteIP(r)
	req.Username = strings.TrimSpace(req.Username)
	if s.throttle.blocked("ip:"+ip) || s.throttle.blocked("user:"+req.Username) {
		writeErr(w, http.StatusTooManyRequests, errors.New("失败次数过多，请 15 分钟后再试"))
		return
	}
	u, err := s.authenticate(r.Context(), req)
	if err != nil {
		n := s.throttle.fail("ip:" + ip)
		s.throttle.fail("user:" + req.Username)
		_ = s.st.Audit(r.Context(), store.AuditEntry{Username: req.Username, IP: ip, Action: "login_failed"})
		if n == maxFails {
			s.nt.Notify(notify.Message{
				Level: notify.Warning, Kind: "login", Key: "login-fail:" + ip,
				Title: "后台登录多次失败",
				Body:  fmt.Sprintf("IP %s 连续 %d 次登录失败（用户名: %s），已暂时锁定 15 分钟。", ip, n, req.Username),
			})
		}
		writeErr(w, http.StatusUnauthorized, errBadLogin)
		return
	}
	s.throttle.clear("ip:" + ip)
	s.throttle.clear("user:" + req.Username)

	known, _ := s.st.HasLoggedInFrom(r.Context(), u.ID, ip)
	token := secure.Token(32)
	now := time.Now()
	se := &store.Session{
		TokenHash: secure.HashToken(token), UserID: u.ID, IP: ip,
		UserAgent: truncate(r.UserAgent(), 256), CreatedAt: now.Unix(), LastSeen: now.Unix(),
		ExpiresAt: now.Add(time.Duration(s.cfg.Admin.SessionHours) * time.Hour).Unix(),
	}
	if err := s.st.CreateSession(r.Context(), se); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.st.TouchLogin(r.Context(), u.ID, ip)
	_ = s.st.Audit(r.Context(), store.AuditEntry{Username: u.Username, IP: ip, Action: "login"})
	if !known {
		s.nt.Notify(notify.Message{
			Level: notify.Critical, Kind: "login",
			Title: "管理后台新 IP 登录",
			Body:  fmt.Sprintf("用户 %s 从新地址 %s 登录了管理后台。\n如非本人操作，请立即修改密码并重置两步验证。", u.Username, ip),
		})
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", HttpOnly: true,
		Secure: s.tls, SameSite: http.SameSiteStrictMode,
		Expires: time.Unix(se.ExpiresAt, 0),
	})
	writeJSON(w, map[string]any{"user": u})
}

func (s *Server) authenticate(ctx context.Context, req loginReq) (*store.User, error) {
	u, err := s.st.UserByName(ctx, req.Username)
	if errors.Is(err, store.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
		return nil, errBadLogin
	}
	if err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil || u.Disabled {
		return nil, errBadLogin
	}
	secret, err := s.box.Open(u.TOTPEnc)
	if err != nil {
		return nil, err
	}
	code := strings.ReplaceAll(req.Code, " ", "")
	if !totp.Validate(code, string(secret)) || !s.totpUsed.use(u.ID, code) {
		return nil, errBadLogin
	}
	return u, nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_ = s.st.DeleteSession(r.Context(), secure.HashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.tls, SameSite: http.SameSiteStrictMode})
	writeJSON(w, map[string]bool{"ok": true})
}

type ctxUser struct{}

// session resolves the logged-in user, enforcing absolute and idle timeouts.
func (s *Server) session(r *http.Request) (*store.User, error) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil, store.ErrNotFound
	}
	h := secure.HashToken(c.Value)
	se, err := s.st.SessionByHash(r.Context(), h)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	idle := int64(s.cfg.Admin.IdleMinutes * 60)
	if se.ExpiresAt < now || now-se.LastSeen > idle {
		_ = s.st.DeleteSession(r.Context(), h)
		return nil, store.ErrNotFound
	}
	u, err := s.st.UserByID(r.Context(), se.UserID)
	if err != nil || u.Disabled {
		return nil, store.ErrNotFound
	}
	// Background refreshes (dashboard auto-refresh, websocket) must not count
	// as activity, otherwise an open tab would never idle out.
	if now-se.LastSeen > 30 && r.Header.Get("X-Background") != "1" && !strings.HasPrefix(r.URL.Path, "/api/ws") {
		_ = s.st.TouchSession(r.Context(), h, now)
	}
	return u, nil
}

func userFrom(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser{}).(*store.User)
	return u
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := s.session(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, errors.New("未登录或会话已过期"))
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxUser{}, u)))
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r).Role != store.RoleAdmin {
			writeErr(w, http.StatusForbidden, errors.New("需要管理员权限"))
			return
		}
		next(w, r)
	})
}

type passwordReq struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req passwordReq
	if !decode(w, r, &req) {
		return
	}
	u := userFrom(r)
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Current)) != nil {
		writeErr(w, http.StatusBadRequest, errors.New("当前密码错误"))
		return
	}
	h, err := HashPassword(req.New)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.st.UpdateUserPassword(r.Context(), u.ID, h); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// Log out every other session of this user.
	_ = s.st.DeleteUserSessions(r.Context(), u.ID)
	s.audit(r, "change_password", u.Username, "")
	s.handleLogout(w, r)
}
