package main

import (
	"fmt"
	"log"
	"net/http"
)

// ServeServiceDiscoveryEndpoint serves the `/v2/` endpoint with some special handling
func ServeServiceDiscoveryEndpoint(w http.ResponseWriter, r *http.Request) {
	LogRequest("ServeServiceDiscoveryEndpoint: received the following request", r)

	// Set JSON content type and WWW-Authenticate header
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/_token",service="%s"`, r.Host, r.Host))

	// Return unauthorized response with JSON error
	http.Error(w, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":null}]}`, http.StatusUnauthorized)
}

// DiscoverTokenEndpoint attempts to get the URL of the remote token service for the given registry;
// for example with docker hub the result is "https://auth.docker.io/token"
func DiscoverTokenEndpoint(registryHost string) (*WWWAuthenticateData, error) {
	url := fmt.Sprintf("https://%s/v2/", registryHost)
	log.Printf("DiscoverTokenEndpoint: making request to %s", url)
	resp, err := http.Get(url)
	LogResponse("DiscoverTokenEndpoint: received the following response", resp)
	if err != nil {
		return nil, fmt.Errorf("DiscoverTokenEndpoint: failed to query the registry host %s: %+v", registryHost, err)
	}

	authHeader := resp.Header.Get("www-authenticate")
	if authHeader == "" {
		return nil, fmt.Errorf("DiscoverTokenEndpoint: www-authenticate header not returned from %s, cannot locate token endpoint", url)
	}
	authHeaderFields, ok := ParseWWWAuthenticate(authHeader)
	if !ok {
		return nil, fmt.Errorf("DiscoverTokenEndpoint: www-authenticate header could not be parsed; header: %s", authHeader)
	}

	log.Printf("DiscoverTokenEndpoint: DEBUG: parsed www-authenticate header %+v", authHeaderFields)
	log.Printf("DiscoverTokenEndpoint: registry %s: discovered token endpoint at %s", registryHost, authHeaderFields.Realm)
	return &authHeaderFields, nil
}
