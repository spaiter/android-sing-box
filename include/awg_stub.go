//go:build !with_awg

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerAwgOutbound(registry *outbound.Registry) {
	outbound.Register[option.AwgEndpointOptions](registry, C.TypeAwg, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AwgEndpointOptions) (adapter.Outbound, error) {
		return nil, E.New(`AmneziaWG is not included in this build, rebuild with -tags with_awg`)
	})
}

func registerAwgEndpoint(registry *endpoint.Registry) {
	endpoint.Register(registry, C.TypeAwg, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AwgEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New(`AmneziaWG is not included in this build, rebuild with -tags with_awg`)
	})
}
