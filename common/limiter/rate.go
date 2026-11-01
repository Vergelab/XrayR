package limiter

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
}

func (l *Limiter) RateWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: limiter,
	}
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := waitN(context.Background(), w.limiter, int(mb.Len())); err != nil {
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}

// Reader limits how fast bytes are read. VLESS Vision hands the dispatcher a
// reader rather than a pipe writer, so upload limiting cannot use RateWriter.
type Reader struct {
	reader  buf.Reader
	limiter *rate.Limiter
}

func (l *Limiter) RateReader(reader buf.Reader, limiter *rate.Limiter) buf.Reader {
	return &Reader{
		reader:  reader,
		limiter: limiter,
	}
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if mb.IsEmpty() {
		return mb, err
	}
	if waitErr := waitN(context.Background(), r.limiter, int(mb.Len())); waitErr != nil {
		buf.ReleaseMulti(mb)
		return nil, waitErr
	}
	return mb, err
}

// waitN waits until n bytes are allowed. WaitN fails when n is larger than
// the burst, which is one second of allowance, so a 64KB buffer is split
// into burst-sized chunks. A wait error is returned and the caller must not
// write the buffer unthrottled.
func waitN(ctx context.Context, limiter *rate.Limiter, n int) error {
	if n <= 0 || limiter == nil {
		return nil
	}
	burst := limiter.Burst()
	if burst <= 0 {
		return fmt.Errorf("rate limiter burst is %d", burst)
	}
	for n > 0 {
		chunk := n
		if chunk > burst {
			chunk = burst
		}
		if err := limiter.WaitN(ctx, chunk); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}
