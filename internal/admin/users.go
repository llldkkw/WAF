package admin

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/llldkkw/waf/internal/store"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,32}$`)

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.st.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"users": users})
}

type userReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Disabled bool   `json:"disabled"`
}

func validRole(r string) bool { return r == store.RoleAdmin || r == store.RoleViewer }

// enrollment is returned once when credentials are created or reset; the
// TOTP secret is never readable again afterwards.
type enrollment struct {
	User       *store.User `json:"user"`
	TOTPSecret string      `json:"totp_secret"`
	TOTPURL    string      `json:"totp_url"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req userReq
	if !decode(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !usernameRe.MatchString(req.Username) {
		writeErr(w, http.StatusBadRequest, errors.New("用户名为 3-32 位字母、数字或 _.-"))
		return
	}
	if !validRole(req.Role) {
		writeErr(w, http.StatusBadRequest, errors.New("角色无效"))
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	key, err := NewTOTP(req.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	enc, err := s.box.Seal([]byte(key.Secret()))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	u := &store.User{Username: req.Username, PasswordHash: hash, TOTPEnc: enc, Role: req.Role}
	if err := s.st.CreateUser(r.Context(), u); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, http.StatusBadRequest, errors.New("用户名已存在"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.changed(r, "user_create", u.Username, map[string]string{"role": u.Role})
	writeJSON(w, enrollment{User: u, TOTPSecret: key.Secret(), TOTPURL: key.URL()})
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	var req userReq
	if !decode(w, r, &req) {
		return
	}
	if !validRole(req.Role) {
		writeErr(w, http.StatusBadRequest, errors.New("角色无效"))
		return
	}
	u, err := s.st.UserByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, errors.New("用户不存在"))
		return
	}
	if err := s.keepAnAdmin(r, u, req.Role != store.RoleAdmin || req.Disabled); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.st.UpdateUserRole(r.Context(), id, req.Role, req.Disabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if req.Disabled {
		_ = s.st.DeleteUserSessions(r.Context(), id)
	}
	s.changed(r, "user_update", u.Username, map[string]any{"role": req.Role, "disabled": req.Disabled})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	u, err := s.st.UserByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, errors.New("用户不存在"))
		return
	}
	if u.ID == userFrom(r).ID {
		writeErr(w, http.StatusBadRequest, errors.New("不能删除自己"))
		return
	}
	if err := s.keepAnAdmin(r, u, true); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.st.DeleteUser(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.changed(r, "user_delete", u.Username, nil)
	writeJSON(w, map[string]bool{"ok": true})
}

// keepAnAdmin refuses changes that would leave no active administrator.
func (s *Server) keepAnAdmin(r *http.Request, u *store.User, losingAdmin bool) error {
	if !losingAdmin || u.Role != store.RoleAdmin || u.Disabled {
		return nil
	}
	n, err := s.st.CountActiveAdmins(r.Context())
	if err != nil {
		return err
	}
	if n <= 1 {
		return errors.New("至少需要保留一个启用的管理员")
	}
	return nil
}

type resetReq struct {
	Password string `json:"password"`
}

// handleResetUser sets a new password and a new TOTP secret, and ends all of
// the user's sessions. Used when a phone or password is lost.
func (s *Server) handleResetUser(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	var req resetReq
	if !decode(w, r, &req) {
		return
	}
	u, err := s.st.UserByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, errors.New("用户不存在"))
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	key, err := NewTOTP(u.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	enc, err := s.box.Seal([]byte(key.Secret()))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.st.UpdateUserPassword(r.Context(), id, hash); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.st.UpdateUserTOTP(r.Context(), id, enc); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.st.DeleteUserSessions(r.Context(), id)
	s.changed(r, "user_reset", u.Username, nil)
	writeJSON(w, enrollment{User: u, TOTPSecret: key.Secret(), TOTPURL: key.URL()})
}
