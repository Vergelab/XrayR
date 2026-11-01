// Copyright 2026 Vergelab.
//
// This file is a modification of github.com/xtls/reality at 83f621788ca8
// (MPL-2.0, see LICENSE). It isolates the ClientHello key-share choice that
// upstream commit 8cdf7bf inlined in Server.

package reality

import "crypto/mlkem"

// selectREALITYPeerPub returns the X25519 public key used for REALITY
// authentication.
//
// Upstream rejects a ClientHello that does not contain exactly one
// X25519MLKEM768 share before the optional X25519 share. When allowNonPQ
// is set, an X25519-only hello is accepted and that share is used. A hello
// that includes X25519MLKEM768 keeps the previous choice: the standalone
// X25519 share when present, otherwise the X25519 half of the hybrid.
// The TLS key exchange is not decided here; dest still selects the group.
func selectREALITYPeerPub(keyShares []keyShare, allowNonPQ bool) (peerPub []byte, ok bool) {
	var peerPub2 []byte
	for _, keyShare := range keyShares {
		if keyShare.group == X25519MLKEM768 && len(keyShare.data) == mlkem.EncapsulationKeySize768+32 {
			if peerPub2 != nil {
				peerPub2 = nil // ensure fail
				break          // ensure once
			}
			peerPub2 = keyShare.data[mlkem.EncapsulationKeySize768:]
			continue // fast continue
		}
		if keyShare.group == X25519 && len(keyShare.data) == 32 {
			if peerPub != nil {
				peerPub2 = nil // ensure fail
				break          // ensure once
			}
			peerPub = keyShare.data
			break // ensure order
		}
	}
	if peerPub2 == nil && !allowNonPQ {
		return nil, false
	}
	if peerPub == nil && peerPub2 == nil {
		for _, keyShare := range keyShares {
			if keyShare.group == X25519 && len(keyShare.data) == 32 {
				peerPub = keyShare.data
				break
			}
		}
	}
	if peerPub == nil {
		peerPub = peerPub2 // secondary choice: X25519 in X25519MLKEM768
	}
	if peerPub == nil {
		return nil, false
	}
	return peerPub, true
}
