package clashapi

import (
	"net/http"

	"github.com/sagernet/sing-box/option"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// hysteria2UserUpdater is implemented by the Hysteria2 inbound. It lets the
// panel swap a Hysteria2 inbound's user set at runtime, instead of restarting
// the whole sing-box core on every user add/remove (which drops all live
// connections). This is the sing-box equivalent of Xray's HandlerService.
type hysteria2UserUpdater interface {
	UpdateUsers(users []option.Hysteria2User) error
}

type updateHysteria2UsersRequest struct {
	Tag   string                 `json:"tag"`
	Users []option.Hysteria2User `json:"users"`
}

func hysteria2UserRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Put("/users", updateHysteria2Users(server))
	return r
}

// PUT /hysteria2/users  {"tag":"Hysteria2","users":[{"name":"...","password":"..."}]}
func updateHysteria2Users(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req updateHysteria2UsersRequest
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if req.Tag == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("missing inbound tag"))
			return
		}
		if server.inbound == nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError("inbound manager unavailable"))
			return
		}
		ib, found := server.inbound.Get(req.Tag)
		if !found {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError("inbound not found: "+req.Tag))
			return
		}
		updater, ok := ib.(hysteria2UserUpdater)
		if !ok {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("inbound does not support user hot-reload: "+req.Tag))
			return
		}
		if err := updater.UpdateUsers(req.Users); err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.Status(r, http.StatusOK)
		render.JSON(w, r, render.M{"count": len(req.Users)})
	}
}
