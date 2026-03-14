package mapping

import "strings"

type NetworkName = string

const (
	Eth NetworkName = "eth"
	Vsc NetworkName = "vsc"
)

type Network interface {
	Name() NetworkName
	ValidateAddress(address string) bool
}

// EthNetwork validates Ethereum addresses (0x-prefixed, 40 hex chars).
type EthNetwork struct{}

func (n EthNetwork) Name() NetworkName {
	return Eth
}

func (n EthNetwork) ValidateAddress(address string) bool {
	if !strings.HasPrefix(address, "0x") {
		return false
	}
	addr := address[2:]
	if len(addr) != 40 {
		return false
	}
	for _, c := range addr {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// VscNetwork validates VSC addresses (hive: or did: prefixed).
type VscNetwork struct{}

func (n VscNetwork) Name() NetworkName {
	return Vsc
}

func (n VscNetwork) ValidateAddress(address string) bool {
	return strings.HasPrefix(address, "hive:") || strings.HasPrefix(address, "did:")
}
