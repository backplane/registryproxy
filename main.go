/*
Copyright 2024 Backplane BV
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"aidanwoods.dev/go-paseto"
)

type originalHostContextKey string

const (
	ctxKeyOriginalHost           = originalHostContextKey("original-host")
	proxyConfigHeader     string = "X-Proxy-Config"
	tokenKeyUpstreamToken string = "upstream-token"
)

var (
	tokenEndpoints = map[string]*WWWAuthFields{} // mapping of registryHosts to token endpoint URLs
)

func main() {
	// load the yaml config file
	config, err := LoadConfig()
	if err != nil {
		log.Fatalf("config loading error: %s", err)
	}
	config.Log()

	// the secret key is used to process the PASETO tokens we issue to clients
	if config.SecretKey == "" {
		log.Fatal("SecretKey not found in config")
	}
	pasetoSecretKey, err := paseto.V4SymmetricKeyFromHex(config.SecretKey)
	if err != nil {
		log.Fatalf("Failed to parse PASETO symmetric key; err: %s", err)
	}

	// set up http handlers for each proxy
	mux := http.NewServeMux()
	mux.Handle("/_token", NewTokenProxy(config, pasetoSecretKey))
	mux.HandleFunc("/v2/", ServeServiceDiscoveryEndpoint) // handles exactly "/v2/" (nothing under it)

	for _, proxy := range config.Proxies {
		if _, ok := tokenEndpoints[proxy.RegistryHost]; !ok {
			// if the token endpoint for the given RegistryHost isn't in
			// tokenEndpoints we look it up, then add it
			endpoint, err := DiscoverTokenEndpoint(proxy.RegistryHost)
			if err != nil {
				log.Fatalf("unable to discover token endpoint corresponding to the registry:%s; err:%s", proxy.RegistryHost, err)
			}
			tokenEndpoints[proxy.RegistryHost] = endpoint
		}

		proxyPath := fmt.Sprintf("/v2/%s/", strings.Trim(proxy.LocalPrefix, "/"))
		log.Printf("setup handler for path:%s pointing to proxy: %s", proxyPath, proxy.LocalPrefix)
		mux.Handle(proxyPath, NewRegistryProxy(proxy, pasetoSecretKey))
	}

	// serve
	hostport := fmt.Sprintf("%s:%s", config.ListenAddr, config.ListenPort)
	log.Printf("starting to listen on %s", hostport)

	if err := http.ListenAndServe(hostport, PanicLogger(CaptureHostHeader(mux))); err != http.ErrServerClosed {
		log.Fatalf("listen error: %+v", err)
	}

	log.Printf("server shutdown successfully")
}

// DiscoverTokenEndpoint runs at startup and attempts to get the URL of the remote token service for the given registry;
// for example with docker hub the result is "https://auth.docker.io/token"
func DiscoverTokenEndpoint(registryHost string) (*WWWAuthFields, error) {
	url := fmt.Sprintf("https://%s/v2/", registryHost)
	log.Printf("discoverTokenEndpoint: making request to %s", url)
	resp, err := http.Get(url)
	LogResponse("discoverTokenEndpoint: received the following response", resp)
	if err != nil {
		return nil, fmt.Errorf("discoverTokenEndpoint: failed to query the registry host %s: %+v", registryHost, err)
	}

	authHeader := resp.Header.Get("www-authenticate")
	if authHeader == "" {
		return nil, fmt.Errorf("discoverTokenEndpoint: www-authenticate header not returned from %s, cannot locate token endpoint", url)
	}
	authHeaderFields, ok := ParseWWWAuthenticateHeader(authHeader)
	if !ok {
		return nil, fmt.Errorf("discoverTokenEndpoint: www-authenticate header could not be parsed; header: %s", authHeader)
	}

	log.Printf("discoverTokenEndpoint: DEBUG: parsed www-authenticate header %+v", authHeaderFields)
	log.Printf("discoverTokenEndpoint: registry %s: discovered token endpoint at %s", registryHost, authHeaderFields.Realm)
	return &authHeaderFields, nil
}

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
				log.Printf("Recovered in HTTP handler: %v", err)
				http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(rw, req)
	})
}
