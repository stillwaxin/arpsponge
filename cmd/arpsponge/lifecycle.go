package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"arpsponge/internal/packet"
)

type captureRunner interface {
	Run(context.Context, func(packet.Packet)) error
	Close()
}

type captureWorker struct {
	errors     chan error
	done       chan struct{}
	cancel     context.CancelFunc
	ctx        context.Context
	stopEngine func()
	capture    captureRunner
	handler    func(packet.Packet)
	mu         sync.Mutex
	started    bool
	stopped    bool
	once       sync.Once
}

func newCaptureWorker(capture captureRunner, handler func(packet.Packet), stopEngine func()) *captureWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &captureWorker{errors: make(chan error, 1), done: make(chan struct{}), cancel: cancel, stopEngine: stopEngine, capture: capture, handler: handler, ctx: ctx}
}

func (w *captureWorker) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started || w.stopped {
		return
	}
	w.started = true
	go func() {
		defer close(w.done)
		w.errors <- w.capture.Run(w.ctx, w.handler)
	}()
}

func (w *captureWorker) Stop() {
	w.once.Do(func() {
		w.mu.Lock()
		w.stopped = true
		started := w.started
		w.cancel()
		w.mu.Unlock()
		w.stopEngine()
		if started {
			<-w.done
		}
		w.capture.Close()
	})
}

func superviseDaemon(ticks <-chan time.Time, serverErrors, captureErrors <-chan error, signals <-chan os.Signal, tick func(time.Time), dump func()) error {
	for {
		select {
		case now := <-ticks:
			tick(now)
		case err := <-captureErrors:
			if err == nil {
				return errors.New("capture stopped unexpectedly")
			}
			return fmt.Errorf("capture stopped: %w", err)
		case err := <-serverErrors:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("control server: %w", err)
			}
			return nil
		case sig := <-signals:
			if isDumpSignal(sig) {
				dump()
				continue
			}
			return nil
		}
	}
}

const (
	controlReadHeaderTimeout = 5 * time.Second
	controlReadTimeout       = 15 * time.Second
	controlWriteTimeout      = 15 * time.Second
	controlIdleTimeout       = 60 * time.Second
	controlShutdownTimeout   = 5 * time.Second
)

func newControlHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: controlReadHeaderTimeout,
		ReadTimeout:       controlReadTimeout,
		WriteTimeout:      controlWriteTimeout,
		IdleTimeout:       controlIdleTimeout,
	}
}

func shutdownControlHTTPServer(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), controlShutdownTimeout)
	defer cancel()

	err := server.Shutdown(ctx)
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	if ctx.Err() == context.DeadlineExceeded {
		if closeErr := server.Close(); closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
			return fmt.Errorf("force-close control server: %w", closeErr)
		}
		return nil
	}
	return fmt.Errorf("shutdown control server: %w", err)
}
