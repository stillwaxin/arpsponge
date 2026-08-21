package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

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
