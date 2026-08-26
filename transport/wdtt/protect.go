// protect.go — TUN-protection for the bridge's bootstrap sockets on Android.
//
// When the native wdtt outbound runs inside sing-box's TUN on a phone, the box
// captures every socket the app opens. But bringing up the VK-TURN tunnel first
// needs DIRECT connections to VK's auth API, DNS and the TURN servers — if those
// go through our own (not-yet-ready) TUN they loop and time out (observed as
// "dial ... i/o timeout" / "lookup ...: i/o timeout" before GETCONF). sing-box
// hands us a control.Func (bind-to-underlying-interface + VpnService.protect);
// applying it to every bootstrap dialer makes those sockets bypass our TUN.
// On the server/CLI there is no platform control (nil) → plain sockets.

package wdtt

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/control"
)

var boxControl atomic.Pointer[control.Func]

// setBoxControl installs the platform socket-protect control (called once from
// RunClientBridge). A nil func is ignored so server/CLI keeps plain dialing.
func setBoxControl(f control.Func) {
	if f != nil {
		boxControl.Store(&f)
	}
}

func boxCtl() control.Func {
	if p := boxControl.Load(); p != nil {
		return *p
	}
	return nil
}

// protectedDialer returns a net.Dialer whose sockets bypass our TUN on Android
// (via the platform control) and are plain everywhere else.
func protectedDialer() net.Dialer {
	d := net.Dialer{Timeout: 15 * time.Second}
	if c := boxCtl(); c != nil {
		d.Control = c // control.Func is a type alias of net.Dialer.Control's type
	}
	return d
}
