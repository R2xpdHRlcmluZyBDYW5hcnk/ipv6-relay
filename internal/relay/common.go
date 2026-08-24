package relay

import "golang.org/x/sys/unix"

// nowMono returns a monotonic clock reading in seconds (CLOCK_MONOTONIC_COARSE).
// All address/route lifetimes are stored and compared in this same time base.
func nowMono() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_COARSE, &ts); err != nil {
		_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	}
	return ts.Sec
}
