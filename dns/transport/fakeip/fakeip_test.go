package fakeip_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func startTransport(t *testing.T) adapter.DNSTransport {
	t.Helper()
	inet4Range := badoption.Prefix(netip.MustParsePrefix("10.200.0.0/16"))
	transport, err := fakeip.NewTransport(context.Background(), log.NewNOPFactory().Logger(), "fakeip", option.FakeIPDNSServerOptions{Inet4Range: &inet4Range})
	require.NoError(t, err)
	require.NoError(t, transport.Start(adapter.StartStateStart))
	t.Cleanup(func() {
		_ = transport.Close()
	})
	return transport
}

func receivedQuery(t *testing.T, name string) *mDNS.Msg {
	t.Helper()
	query := new(mDNS.Msg)
	query.SetQuestion(name, mDNS.TypeA)
	packed, err := query.Pack()
	require.NoError(t, err)
	received := new(mDNS.Msg)
	require.NoError(t, received.Unpack(packed))
	return received
}

func TestFakeIPAnswersAnOrdinaryName(t *testing.T) {
	t.Parallel()
	response, err := startTransport(t).Exchange(context.Background(), receivedQuery(t, "www.example.com."))
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
}

func TestFakeIPRefusesANameLongerThanADomain(t *testing.T) {
	t.Parallel()
	label := strings.Repeat("\\000", 63)
	query := receivedQuery(t, strings.Join([]string{label, label, label, "example"}, ".")+".")
	require.Greater(t, len(query.Question[0].Name), 255)
	_, err := startTransport(t).Exchange(context.Background(), query)
	require.ErrorContains(t, err, "domain name too long for fakeip")
}
