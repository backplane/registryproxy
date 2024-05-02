package main

import (
	"context"
	"log"
	"net/http"
)

// CaptureHostHeader is a middleware to capture Host header in a context key.
func CaptureHostHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), ctxKeyOriginalHost, req.Host)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

// PanicLogger intends to log something when an http handler panics
func PanicLogger(next http.Handler) http.Handler {
	// Note: this needs testing/validation, the entire concept of this middleware
	// may be the result of several wrong assumptions
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("PanicLogger recovered in HTTP handler: %v", err)
				http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(rw, req)
	})
}
