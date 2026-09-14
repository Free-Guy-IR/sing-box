package inbounduser

import (
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
)

type Identity struct {
	Name  string
	Index int
}

func (i Identity) Label() string {
	if i.Name != "" {
		return i.Name
	}
	return F.ToString(i.Index)
}

func Identities[T any](users []T, nameOf func(T) string) []Identity {
	return common.MapIndexed(users, func(index int, user T) Identity {
		return Identity{Name: nameOf(user), Index: index}
	})
}

func Names(names []string) []Identity {
	return Identities(names, func(name string) string {
		return name
	})
}
