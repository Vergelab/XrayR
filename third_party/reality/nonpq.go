// Copyright 2026 Vergelab.
//
// This file is a modification of github.com/xtls/reality at 83f621788ca8
// (MPL-2.0, see LICENSE).

package reality

import "sync/atomic"

// allowNonPQProcess is the process-wide switch. xray-core builds reality.Config
// from a protobuf message that has no AllowNonPQClients field, so a panel
// cannot set the struct field per inbound without forking xray-core.
// Server reads this on every handshake.
var allowNonPQProcess atomic.Bool

// SetAllowNonPQClients sets the process-wide acceptance of X25519-only
// ClientHellos. A Config with AllowNonPQClients true also accepts them for
// that listener. The value is read when the ClientHello arrives, so it can
// change while listeners are running. XrayR updates it before a hot-reloaded
// instance starts accepting.
func SetAllowNonPQClients(allow bool) {
	allowNonPQProcess.Store(allow)
}

// ProcessAllowsNonPQClients reports the process-wide setting.
func ProcessAllowsNonPQClients() bool {
	return allowNonPQProcess.Load()
}

func allowNonPQClients(config *Config) bool {
	if config != nil && config.AllowNonPQClients {
		return true
	}
	return allowNonPQProcess.Load()
}
