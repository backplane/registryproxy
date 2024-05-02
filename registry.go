package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"aidanwoods.dev/go-paseto"
)

type registryRoundtripper struct {
	proxyConfig ProxyItem
	secretKey   paseto.V4SymmetricKey
}

// registryAPIProxy returns a reverse proxy to the specified registry.
func registryAPIProxy(cfg ProxyItem, secretKey paseto.V4SymmetricKey) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director:      rewriteRegistryV2URL(cfg),
		Transport: &registryRoundtripper{
			proxyConfig: cfg,
			secretKey:   secretKey,
		},
	}).ServeHTTP
}

// rewriteRegistryV2URL rewrites request.URL like /v2/* that come into the server
// into https://[GCR_HOST]/v2/[PROJECT_ID]/*. (It the full path "/v2/" as-is.)
func rewriteRegistryV2URL(cfg ProxyItem) func(*http.Request) {
	return func(req *http.Request) {
		u := req.URL.String()
		req.Host = cfg.RegistryHost
		req.URL.Host = cfg.RegistryHost
		req.URL.Scheme = "https"

		localPath := fmt.Sprintf("/v2/%s/", strings.TrimRight(cfg.LocalPrefix, "/"))
		remotePath := fmt.Sprintf("/v2/%s/", cfg.RemotePrefix)

		if req.URL.Path != "/v2/" {
			if strings.HasPrefix(req.URL.Path, localPath) {
				req.URL.Path = strings.Replace(req.URL.Path, localPath, remotePath, 1)
			}
		}

		req.RequestURI = "" // clearing this to avoid conflicts
		log.Printf("rewriteRegistryV2URL: rewrote url: %s into %s", u, req.URL.String())
	}
}

func (rrt *registryRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("registryRoundtripper.RoundTrip: request received with url=%s", req.URL)
	origHost := req.Host

	// Retrieve the proxy config context value
	proxy := rrt.proxyConfig

	// replace the outgoing "Authorization: Bearer abcdeg..." header with one we embedded in the token
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		log.Printf("registryRoundtripper.RoundTrip: have auth header: %s", authHeader)
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return nil, fmt.Errorf("registryRoundtripper.RoundTrip: Authorization header in unknown format: %s", authHeader)
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		parser := paseto.NewParserForValidNow()
		token, err := parser.ParseV4Local(rrt.secretKey, tokenString, []byte{})
		if err != nil {
			return nil, fmt.Errorf("registryRoundtripper.RoundTrip: unable to parse token from auth header; token:%s; error:%s", tokenString, err)
		}

		upstreamToken, err := token.GetString(tokenKeyUpstreamToken)
		if err != nil {
			log.Printf("claims found in token: %s", token.ClaimsJSON())
			return nil, fmt.Errorf("registryRoundtripper.RoundTrip: unable to parse upstreamToken string from token; error:%s", err)
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", upstreamToken))
		log.Printf("registryRoundtripper.RoundTrip: set Authorization header: %s", req.Header.Get("Authorization"))
	}

	SetUserAgent(req)
	cleanHeaders(req)

	logRequest("registryRoundtripper.RoundTrip: about to make the following request to upstream", req)

	resp, err := http.DefaultTransport.RoundTrip(req)
	logResponse("registryRoundtripper.RoundTrip: response from upstream", resp)
	if err != nil {
		log.Printf("registryRoundtripper.RoundTrip: upstream request failed with error: %+v", err)
		return nil, err
	}
	log.Printf("registryRoundtripper.RoundTrip: upstream request completed (status=%d) url=%s", resp.StatusCode, req.URL)

	// Google Artifact Registry sends a "location: /artifacts-downloads/..." URL
	// to download blobs. We don't want these routed to the proxy itself.
	if locHdr := resp.Header.Get("location"); req.Method == http.MethodGet &&
		resp.StatusCode == http.StatusFound && strings.HasPrefix(locHdr, "/") {
		log.Printf("registryRoundtripper.RoundTrip: applying Google Artifact Registry location header")
		resp.Header.Set("location", req.URL.Scheme+"://"+req.URL.Host+locHdr)
	}

	// If the response included a WWW-Authenticate header we replace it with
	// our own adjusted header that points to our own token endpoint
	// see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate
	// and: https://distribution.github.io/distribution/spec/auth/token/
	if authHeader := resp.Header.Get("www-authenticate"); authHeader != "" {
		log.Printf("registryRoundtripper.RoundTrip: have www-authenticate header:%s", authHeader)
		authHeaderFields, ok := parseWWWAuthenticateHeader(authHeader)
		if !ok {
			return nil, fmt.Errorf("registryRoundtripper.RoundTrip: parsing WWW-Authenticate header failed; header: %s", authHeader)
		}
		log.Printf("registryRoundtripper.RoundTrip: parsed www-authenticate header: %+v", authHeaderFields)

		authHeaderFields.Realm = fmt.Sprintf(`https://%s/_token`, origHost)
		authHeaderFields.Service = fmt.Sprintf(`https://%s`, origHost)
		headerScope, err := ParseResourceScope(authHeaderFields.Scope)
		if err != nil {
			return nil, fmt.Errorf("failed to parse scope in www-authenticate header; error:%s", err)
		}
		headerScope.ResourceName = slashJoin(proxy.LocalPrefix, strings.TrimPrefix(headerScope.ResourceName, proxy.RemotePrefix))
		authHeaderFields.Scope = headerScope.String()

		newAuthHeader := authHeaderFields.String()
		resp.Header.Set("www-authenticate", newAuthHeader)
		log.Printf("registryRoundtripper.RoundTrip: rewrote www-authenticate header;\n  from: %s\n    to: %s", authHeader, newAuthHeader)
	}

	return resp, nil
}
