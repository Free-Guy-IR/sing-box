package v2rayhttp_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type earlyDataRecorder struct {
	earlyData chan []byte
}

func (h *earlyDataRecorder) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	payload := make([]byte, 4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		payload = nil
	}
	h.earlyData <- payload
}

func postWithContentLength(t *testing.T, recorder *earlyDataRecorder, contentLength int, body string) *http.Response {
	t.Helper()
	server, err := v2rayhttp.NewServer(context.Background(), logger.NOP(), option.V2RayHTTPOptions{}, nil, recorder)
	require.NoError(t, err)
	httpServer := httptest.NewServer(server)
	t.Cleanup(httpServer.Close)
	conn, err := net.Dial("tcp", httpServer.Listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
	})
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: %d\r\n\r\n%s", contentLength, body)
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	return response
}

func TestServerPassesASmallRequestBodyThrough(t *testing.T) {
	t.Parallel()
	recorder := &earlyDataRecorder{earlyData: make(chan []byte, 1)}
	response := postWithContentLength(t, recorder, 4, "ping")
	require.Equal(t, http.StatusOK, response.StatusCode)
	select {
	case earlyData := <-recorder.earlyData:
		require.Equal(t, []byte("ping"), earlyData)
	case <-time.After(3 * time.Second):
		t.Fatal("the request body never reached the handler")
	}
}

func TestServerRefusesAnOversizedRequestBody(t *testing.T) {
	t.Parallel()
	response := postWithContentLength(t, &earlyDataRecorder{earlyData: make(chan []byte, 1)}, 16<<20, "")
	require.Equal(t, http.StatusRequestEntityTooLarge, response.StatusCode)
}
