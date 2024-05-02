package main

import (
	"fmt"
	"net/http"
)

// ServeV2SentinelEndpoint serves the `/v2/` endpoint with some special handling
func ServeV2SentinelEndpoint(w http.ResponseWriter, r *http.Request) {
	logRequest("ServeV2SentinelEndpoint: received the following request", r)

	// Set JSON content type and WWW-Authenticate header
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/_token",service="%s"`, r.Host, r.Host))

	// Return unauthorized response with JSON error
	http.Error(w, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":null}]}`, http.StatusUnauthorized)
}
