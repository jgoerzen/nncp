// This is a fork of github.com/gosuri/uilive for NNCP project
// * It does not buffer all the writes, but resets the buffer
//   just only for single latest line. Some terminals have
//   huge CPU usage if so much data (as copied files progress)
//   is printed
// * By default it uses stderr
// * By default it uses 10ms refresh period
// * defer-s are removed for less CPU usage
// * By default it uses stderr
// * By default it uses stderr
// * By default it uses stderr
// * Removed newline/bypass related code. No Windows support

package uilive

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// ESC is the ASCII code for escape character
const ESC = 27

// RefreshInterval is the default refresh interval to update the ui
var RefreshInterval = 10 * time.Millisecond

var overFlowHandled bool

var termWidth int

// Out is the default output writer for the Writer
var Out = os.Stdout

// FdWriter is a writer with a file descriptor.
type FdWriter interface {
	io.Writer
	Fd() uintptr
}

// Writer is a buffered the writer that updates the terminal. The contents of writer will be flushed on a timed interval or when Flush is called.
type Writer struct {
	// Out is the writer to write to
	Out io.Writer

	// RefreshInterval is the time the UI sould refresh
	RefreshInterval time.Duration

	ticker *time.Ticker
	tdone  chan struct{}

	buf bytes.Buffer
	mtx *sync.Mutex
}

// New returns a new Writer with defaults
func New() *Writer {
	termWidth, _ = getTermSize()
	if termWidth != 0 {
		overFlowHandled = true
	}
	return &Writer{
		Out:             Out,
		RefreshInterval: RefreshInterval,
		mtx:             &sync.Mutex{},
	}
}

// clear the line and move the cursor up
var clear = fmt.Sprintf("%c[%dA%c[2K", ESC, 1, ESC)

func (w *Writer) clearLines() {
	fmt.Fprint(w.Out, clear)
}

// Flush writes to the out and resets the buffer. It should be called after the last call to Write to ensure that any data buffered in the Writer is written to output.
// Any incomplete escape sequence at the end is considered complete for formatting purposes.
// An error is returned if the contents of the buffer cannot be written to the underlying output stream
func (w *Writer) Flush() (err error) {
	w.mtx.Lock()
	// do nothing if buffer is empty
	if len(w.buf.Bytes()) == 0 {
		w.mtx.Unlock()
		return
	}
	w.clearLines()
	var currentLine bytes.Buffer
	for _, b := range w.buf.Bytes() {
		if b == '\n' {
			currentLine.Reset()
		} else {
			currentLine.Write([]byte{b})
			if overFlowHandled && currentLine.Len() > termWidth {
				currentLine.Reset()
			}
		}
	}
	_, err = w.Out.Write(w.buf.Bytes())
	w.mtx.Unlock()
	return
}

// Start starts the listener in a non-blocking manner
func (w *Writer) Start() {
	w.ticker = time.NewTicker(w.RefreshInterval)
	w.tdone = make(chan struct{}, 0)
	w.Out.Write([]byte("\n"))
	go w.Listen()
}

// Stop stops the listener that updates the terminal
func (w *Writer) Stop() {
	w.Flush()
	close(w.tdone)
}

// Listen listens for updates to the writer's buffer and flushes to the out provided. It blocks the runtime.
func (w *Writer) Listen() {
	for {
		select {
		case <-w.ticker.C:
			if w.ticker != nil {
				w.Flush()
			}
		case <-w.tdone:
			w.mtx.Lock()
			w.ticker.Stop()
			w.mtx.Unlock()
			return
		}
	}
}

// Write save the contents of buf to the writer b. The only errors returned are ones encountered while writing to the underlying buffer.
func (w *Writer) Write(buf []byte) (n int, err error) {
	w.mtx.Lock()
	w.buf.Reset()
	n, err = w.buf.Write(buf)
	w.mtx.Unlock()
	return
}
