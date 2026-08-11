package clashapi

import (
	"encoding/json"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// Per-protocol user-updater interfaces. Each user-carrying inbound implements
// the matching one so the panel can swap its user set at runtime instead of
// restarting the whole sing-box core on every user add/remove (which drops all
// live connections). This is the sing-box equivalent of Xray's HandlerService.
// hysteria2UserUpdater lives in hysteria2_users.go.
type (
	vlessUserUpdater interface {
		UpdateUsers(users []option.VLESSUser) error
	}
	vmessUserUpdater interface {
		UpdateUsers(users []option.VMessUser) error
	}
	trojanUserUpdater interface {
		UpdateUsers(users []option.TrojanUser) error
	}
	tuicUserUpdater interface {
		UpdateUsers(users []option.TUICUser) error
	}
	shadowsocksUserUpdater interface {
		UpdateUsers(users []string, uPSKs []string) error
	}
)

// updateInboundUsersRequest is the generic body: the "type" field selects how
// "users" is decoded (into the matching []option.XxxUser) and which inbound
// interface it is dispatched to.
type updateInboundUsersRequest struct {
	Type  string          `json:"type"`
	Users json.RawMessage `json:"users"`
}

func inboundUsersRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Put("/{tag}/users", updateInboundUsers(server))
	return r
}

// PUT /inbounds/{tag}/users  {"type":"vless","users":[{"name":"...","uuid":"...","flow":"..."}]}
func updateInboundUsers(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		if tag == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("missing inbound tag"))
			return
		}
		var req updateInboundUsersRequest
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if req.Type == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("missing inbound type"))
			return
		}
		if server.inbound == nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError("inbound manager unavailable"))
			return
		}
		ib, found := server.inbound.Get(tag)
		if !found {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError("inbound not found: "+tag))
			return
		}
		count, status, err := dispatchUpdateUsers(ib, req.Type, req.Users)
		if err != nil {
			render.Status(r, status)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.Status(r, http.StatusOK)
		render.JSON(w, r, render.M{"count": count})
	}
}

// dispatchUpdateUsers decodes the raw user array according to typ and calls the
// matching inbound's UpdateUsers. It returns the applied user count, the HTTP
// status to respond with, and an error (nil on success).
func dispatchUpdateUsers(ib adapter.Inbound, typ string, raw json.RawMessage) (int, int, error) {
	switch typ {
	case C.TypeHysteria2:
		var users []option.Hysteria2User
		if err := json.Unmarshal(raw, &users); err != nil {
			return 0, http.StatusBadRequest, err
		}
		updater, ok := ib.(hysteria2UserUpdater)
		if !ok {
			return 0, http.StatusBadRequest, E.New("inbound does not support hysteria2 user hot-reload")
		}
		if err := updater.UpdateUsers(users); err != nil {
			return 0, http.StatusInternalServerError, err
		}
		return len(users), http.StatusOK, nil
	case C.TypeVLESS:
		var users []option.VLESSUser
		if err := json.Unmarshal(raw, &users); err != nil {
			return 0, http.StatusBadRequest, err
		}
		updater, ok := ib.(vlessUserUpdater)
		if !ok {
			return 0, http.StatusBadRequest, E.New("inbound does not support vless user hot-reload")
		}
		if err := updater.UpdateUsers(users); err != nil {
			return 0, http.StatusInternalServerError, err
		}
		return len(users), http.StatusOK, nil
	case C.TypeVMess:
		var users []option.VMessUser
		if err := json.Unmarshal(raw, &users); err != nil {
			return 0, http.StatusBadRequest, err
		}
		updater, ok := ib.(vmessUserUpdater)
		if !ok {
			return 0, http.StatusBadRequest, E.New("inbound does not support vmess user hot-reload")
		}
		if err := updater.UpdateUsers(users); err != nil {
			return 0, http.StatusInternalServerError, err
		}
		return len(users), http.StatusOK, nil
	case C.TypeTrojan:
		var users []option.TrojanUser
		if err := json.Unmarshal(raw, &users); err != nil {
			return 0, http.StatusBadRequest, err
		}
		updater, ok := ib.(trojanUserUpdater)
		if !ok {
			return 0, http.StatusBadRequest, E.New("inbound does not support trojan user hot-reload")
		}
		if err := updater.UpdateUsers(users); err != nil {
			return 0, http.StatusInternalServerError, err
		}
		return len(users), http.StatusOK, nil
	case C.TypeTUIC:
		var users []option.TUICUser
		if err := json.Unmarshal(raw, &users); err != nil {
			return 0, http.StatusBadRequest, err
		}
		updater, ok := ib.(tuicUserUpdater)
		if !ok {
			return 0, http.StatusBadRequest, E.New("inbound does not support tuic user hot-reload")
		}
		if err := updater.UpdateUsers(users); err != nil {
			return 0, http.StatusInternalServerError, err
		}
		return len(users), http.StatusOK, nil
	case C.TypeShadowsocks:
		var users []option.ShadowsocksUser
		if err := json.Unmarshal(raw, &users); err != nil {
			return 0, http.StatusBadRequest, err
		}
		updater, ok := ib.(shadowsocksUserUpdater)
		if !ok {
			return 0, http.StatusBadRequest, E.New("inbound does not support shadowsocks user hot-reload")
		}
		if err := updater.UpdateUsers(
			common.Map(users, func(it option.ShadowsocksUser) string {
				return it.Name
			}),
			common.Map(users, func(it option.ShadowsocksUser) string {
				return it.Password
			}),
		); err != nil {
			return 0, http.StatusInternalServerError, err
		}
		return len(users), http.StatusOK, nil
	default:
		return 0, http.StatusBadRequest, E.New("unsupported inbound type: " + typ)
	}
}
