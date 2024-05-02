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
	tokenEndpoints = map[string]*WWWAuthenticateData{} // mapping of registryHosts to token endpoint URLs
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
