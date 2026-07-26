//go:build with_awg

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/awg"
)

func registerAwgOutbound(registry *outbound.Registry) {
	awg.RegisterOutbound(registry)
}

func registerAwgEndpoint(registry *endpoint.Registry) {
	awg.RegisterEndpoint(registry)
}
