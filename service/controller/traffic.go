package controller

import "github.com/xtls/xray-core/features/stats"

// snapshotCounter atomically swaps the counter to 0 and returns the previous
// value. Bytes added after the swap stay on the counter. xray Counter.Set is
// atomic.SwapInt64.
func snapshotCounter(counter stats.Counter) int64 {
	if counter == nil {
		return 0
	}
	return counter.Set(0)
}

// restoreCounter adds a failed push back onto the counter. It does not
// replace the value, so bytes counted during the push stay included.
func restoreCounter(counter stats.Counter, n int64) {
	if counter == nil || n == 0 {
		return
	}
	counter.Add(n)
}
