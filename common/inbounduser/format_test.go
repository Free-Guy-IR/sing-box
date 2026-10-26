package inbounduser_test

import (
	"testing"

	"github.com/sagernet/sing-box/common/inbounduser"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"

	"github.com/stretchr/testify/require"
)

func TestIdentityFormatsAsLabel(t *testing.T) {
	t.Parallel()
	named := inbounduser.Identity{Name: "alice", Index: 4}
	unnamed := inbounduser.Identity{Index: 2}
	require.NotPanics(t, func() {
		require.Equal(t, "alice", F.ToString(named))
		require.Equal(t, "2", F.ToString(unnamed))
		require.EqualError(t, E.Extend(E.New("base"), "used by ", named), "base: used by alice")
		require.EqualError(t, E.Cause(E.New("base"), "user ", unnamed), "user 2: base")
	})
}
