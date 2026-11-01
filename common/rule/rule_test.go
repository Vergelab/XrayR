package rule

import (
	"sync"
	"testing"

	"github.com/Vergelab/XrayR/api"
)

func TestDetectConcurrent(t *testing.T) {
	m := New()
	re, ok := api.CompileRule(1, `evil\.example`)
	if !ok {
		t.Fatal("rule")
	}
	if err := m.UpdateRule("tag", []api.DetectRule{re}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m.Detect("tag", "evil.example", "tag|u@x|"+itoa(i%4))
		}(i)
	}
	wg.Wait()
	got, err := m.GetDetectResult("tag")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(*got) == 0 {
		t.Fatal("expected hits")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
