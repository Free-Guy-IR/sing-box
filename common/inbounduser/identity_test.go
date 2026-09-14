package inbounduser_test

import (
	"testing"

	"github.com/sagernet/sing-box/common/inbounduser"

	"github.com/stretchr/testify/require"
)

func TestNamesCarryNameAndIndex(t *testing.T) {
	t.Parallel()
	require.Equal(t, []inbounduser.Identity{
		{Name: "alice", Index: 0},
		{Name: "bob", Index: 1},
		{Name: "carol", Index: 2},
	}, inbounduser.Names([]string{"alice", "bob", "carol"}))
}

func TestLabelFallsBackToIndex(t *testing.T) {
	t.Parallel()
	require.Equal(t, "bob", inbounduser.Identity{Name: "bob", Index: 1}.Label())
	require.Equal(t, "2", inbounduser.Identity{Index: 2}.Label())
}

func TestUnnamedIdentitiesStayDistinct(t *testing.T) {
	t.Parallel()
	identities := inbounduser.Names([]string{"", ""})
	require.NotEqual(t, identities[0], identities[1])
}

func TestDuplicateNamesStayDistinct(t *testing.T) {
	t.Parallel()
	identities := inbounduser.Names([]string{"same", "same"})
	require.NotEqual(t, identities[0], identities[1])
	require.Equal(t, "same", identities[0].Label())
	require.Equal(t, "same", identities[1].Label())
}
