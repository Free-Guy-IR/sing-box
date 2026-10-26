package clashapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/trojan"

	"github.com/stretchr/testify/require"
)

type singleInboundManager struct {
	adapter.InboundManager
	inbound adapter.Inbound
}

func (m *singleInboundManager) Get(tag string) (adapter.Inbound, bool) {
	if tag != m.inbound.Tag() {
		return nil, false
	}
	return m.inbound, true
}

func putInboundUsers(t *testing.T, server *Server, tag string, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/"+tag+"/users", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	require.NotPanics(t, func() {
		inboundUsersRouter(server).ServeHTTP(recorder, request)
	})
	return recorder
}

func TestTrojanUsersHotReloadRejectsSharedPasswordWithoutPanic(t *testing.T) {
	inbound, err := trojan.NewInbound(context.Background(), nil, log.NewNOPFactory().Logger(), "trojan-in", option.TrojanInboundOptions{
		Users: []option.TrojanUser{{Name: "alice", Password: "pw-a"}},
	})
	require.NoError(t, err)
	server := &Server{inbound: &singleInboundManager{inbound: inbound}}

	recorder := putInboundUsers(t, server, "trojan-in", `{"type":"trojan","users":[{"name":"alice","password":"shared"},{"name":"bob","password":"shared"}]}`)
	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Contains(t, recorder.Body.String(), "user already exists: password used by alice")

	recorder = putInboundUsers(t, server, "trojan-in", `{"type":"trojan","users":[{"name":"alice","password":"pw-a"},{"name":"bob","password":"pw-b"}]}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.JSONEq(t, `{"count":2}`, recorder.Body.String())
}
