package reality

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

func hybridShare(tail []byte) keyShare {
	data := make([]byte, mlkem.EncapsulationKeySize768+32)
	copy(data[mlkem.EncapsulationKeySize768:], tail)
	return keyShare{group: X25519MLKEM768, data: data}
}

func xShare(b []byte) keyShare {
	return keyShare{group: X25519, data: append([]byte(nil), b...)}
}

func pub(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, 32)
}

func TestSelectREALITYPeerPub(t *testing.T) {
	hybridTail := pub(0x11)
	standalone := pub(0x22)
	other := pub(0x33)

	hybrid := hybridShare(hybridTail)
	x25519 := xShare(standalone)

	cases := []struct {
		name   string
		shares []keyShare
		allow  bool
		want   []byte
		wantOK bool
	}{
		{
			name:   "hybrid then x25519 rejected off uses standalone",
			shares: []keyShare{hybrid, x25519},
			allow:  false,
			want:   standalone,
			wantOK: true,
		},
		{
			name:   "hybrid then x25519 allowed still uses standalone",
			shares: []keyShare{hybrid, x25519},
			allow:  true,
			want:   standalone,
			wantOK: true,
		},
		{
			name:   "hybrid only uses the x25519 half",
			shares: []keyShare{hybrid},
			allow:  false,
			want:   hybridTail,
			wantOK: true,
		},
		{
			name:   "hybrid only allowed uses the same half",
			shares: []keyShare{hybrid},
			allow:  true,
			want:   hybridTail,
			wantOK: true,
		},
		{
			name:   "x25519 only rejected",
			shares: []keyShare{x25519},
			allow:  false,
		},
		{
			name:   "x25519 only accepted",
			shares: []keyShare{x25519},
			allow:  true,
			want:   standalone,
			wantOK: true,
		},
		{
			name:   "x25519 before hybrid rejected because hybrid was not seen",
			shares: []keyShare{x25519, hybrid},
			allow:  false,
		},
		{
			name:   "x25519 before hybrid allowed uses standalone",
			shares: []keyShare{x25519, hybrid},
			allow:  true,
			want:   standalone,
			wantOK: true,
		},
		{
			name:  "no shares rejected",
			allow: true,
		},
		{
			name:   "short x25519 ignored",
			shares: []keyShare{{group: X25519, data: pub(1)[:31]}},
			allow:  true,
		},
		{
			name:   "p256 only rejected",
			shares: []keyShare{{group: CurveP256, data: pub(1)}},
			allow:  true,
		},
		{
			name:   "duplicate x25519 rejected when strict",
			shares: []keyShare{x25519, xShare(other)},
			allow:  false,
		},
		{
			name:   "duplicate x25519 allowed keeps the first share",
			shares: []keyShare{x25519, xShare(other)},
			allow:  true,
			want:   standalone,
			wantOK: true,
		},
		{
			name:   "duplicate hybrid then x25519 rejected when strict",
			shares: []keyShare{hybrid, hybridShare(other), xShare(other)},
			allow:  false,
		},
		{
			name:   "duplicate hybrid then x25519 allowed recovers x25519",
			shares: []keyShare{hybrid, hybridShare(pub(0x44)), xShare(other)},
			allow:  true,
			want:   other,
			wantOK: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := selectREALITYPeerPub(tc.shares, tc.allow)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (pub %x)", ok, tc.wantOK, got)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("pub = %x, want %x", got, tc.want)
			}
		})
	}
}

func TestAllowNonPQClientsFieldOrProcess(t *testing.T) {
	SetAllowNonPQClients(false)
	t.Cleanup(func() { SetAllowNonPQClients(false) })

	if allowNonPQClients(nil) || allowNonPQClients(&Config{}) {
		t.Fatal("zero value must keep the upstream rejection")
	}
	if !allowNonPQClients(&Config{AllowNonPQClients: true}) {
		t.Fatal("config field did not allow non-PQ clients")
	}
	SetAllowNonPQClients(true)
	if !ProcessAllowsNonPQClients() || !allowNonPQClients(&Config{}) {
		t.Fatal("process setting did not allow non-PQ clients")
	}
	only := pub(9)
	got, ok := selectREALITYPeerPub([]keyShare{xShare(only)}, allowNonPQClients(&Config{}))
	if !ok || !bytes.Equal(got, only) {
		t.Fatalf("process flag did not reach selection: ok=%v pub=%x", ok, got)
	}
}
