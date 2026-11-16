package canon

import (
	"runtime"
	"testing"
	"time"
)

// A header that announces a huge array, map or string costs nothing when the
// data is not there: the limit of 2^24 array elements, which a large roll
// needs, is not a way to make the decoder allocate.
func TestHugeArrayHeaderIsCheap(t *testing.T) {
	for _, in := range [][]byte{
		{0x9a, 0x00, 0xff, 0xff, 0xff},       // array of about 16.7 million items, no data
		{0x9a, 0x00, 0xff, 0xff, 0xff, 0x00}, // and one item
		{0xba, 0x00, 0xff, 0xff, 0xff},       // map of the same size
		{0x5a, 0x7f, 0xff, 0xff, 0xff},       // byte string of 2 GB, no data
		{0x7a, 0x7f, 0xff, 0xff, 0xff},       // text string of 2 GB, no data
	} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		err := Check(in)
		took := time.Since(start)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Errorf("% x accepted", in)
		}
		if took > 2*time.Second || after.TotalAlloc-before.TotalAlloc > 1<<20 {
			t.Errorf("% x took %v and allocated %d bytes", in, took, after.TotalAlloc-before.TotalAlloc)
		}
	}
}
