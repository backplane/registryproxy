package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"time"
)

// MatchMap returns a map of named capture groups and a boolean "matched" value
func MatchMap(needle *regexp.Regexp, haystack string) (map[string]string, bool) {
	match_indexes := needle.FindStringSubmatchIndex(haystack)
	if match_indexes == nil {
		return nil, false
	}
	names := needle.SubexpNames()
	if names == nil {
		return nil, false
	}
	result := make(map[string]string)
	for i, name := range names {
		if i == 0 || name == "" {
			continue
		}
		idx_start := match_indexes[i*2]
		idx_end := match_indexes[(i*2)+1]
		if idx_start != -1 && idx_end != -1 { // Check if the indexes are valid
			result[name] = haystack[idx_start:idx_end]
		}
	}

	// fmt.Println("returning match map:")
	// for k, v := range result {
	// 	fmt.Printf("%s: %s\n", k, v)
	// }

	return result, true
}
func SetUserAgent(req *http.Request, fqdn string) bool {
	version := "0.1.0" // fixme: implement auto updates

	if userAgent := req.Header.Get("user-agent"); userAgent != "" {
		req.Header.Set("user-agent", fmt.Sprintf("registryproxy/%s customDomain/%s %s", version, fqdn, userAgent))
		return true
	}
	return false
}

type TokenResponse struct {
	Token     string    `json:"token"`      // matches "token" in the JSON
	ExpiresIn uint      `json:"expires_in"` // matches "expires_in" in the JSON
	IssuedAt  time.Time `json:"issued_at"`  // matches "issued_at" in the JSON
	Error     string    `json:"error"`      // just in case
}

// ParseTokenRequestResponse takes an *http.Response, checks if the content type is application/json,
// and returns a map[string]string parsed from the JSON body
func ParseTokenRequestResponse(resp *http.Response) (*TokenResponse, error) {
	// Check that the response Content-Type header is application/json
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		return nil, fmt.Errorf("parseTokenRequestResponse: expected content type application/json, got %s", contentType)
	}

	// Read the body of the response
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parseTokenRequestResponse: failed to read response body: %w", err)
	}

	// Unmarshal JSON data into a map
	var response TokenResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("parseTokenRequestResponse: failed to unmarshal JSON: %w, body: %s", err, body)
	}

	return &response, nil
}

// ReplaceResponseBody takes an *http.Response and a map[string]string, then replaces
// the response's body with a JSON-encoded version of the map.
func ReplaceResponseBody(resp *http.Response, data *TokenResponse) error {
	// Marshal the map into JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Replace the body with the new JSON data
	resp.Body = io.NopCloser(bytes.NewReader(jsonData))

	// update the Content-Length header
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(jsonData)))

	// Set the Content-Type header to application/json
	resp.Header.Set("Content-Type", "application/json")

	return nil
}

type WWWAuthenticateData struct {
	Realm   string
	Service string
	Scope   string
	Error   string
}

// String returns a value useable as Www-Authenticate header
func (authFields WWWAuthenticateData) String() string {
	return fmt.Sprintf(`Bearer realm="%s",service="%s",scope="%s"`, authFields.Realm, authFields.Service, authFields.Scope)
}

// ParseWWWAuthenticate parses the given header contents and returns a struct
// containing the parsed values; returns a WWWAuthFields struct and a boolean OK value
func ParseWWWAuthenticate(headerValue string) (WWWAuthenticateData, bool) {
	fieldRegex := regexp.MustCompile(`(realm|service|scope|error)="([^"]+)"`)
	matches := fieldRegex.FindAllStringSubmatch(headerValue, -1)

	result := WWWAuthenticateData{}
	ok := false

	for _, match := range matches {
		if len(match) == 3 {
			ok = true
			switch match[1] {
			case "realm":
				result.Realm = match[2]
			case "service":
				result.Service = match[2]
			case "scope":
				result.Scope = match[2]
			case "error":
				result.Error = match[2]
			}
		}
	}

	return result, ok
}

// LogRequest logs the contents of an http.Request object
func LogRequest(preamble string, req *http.Request) {
	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		logger.Debug("logRequest: Error dumping request: %v", err)
		return
	}
	if preamble != "" {
		preamble = preamble + ":\n"
	}
	logger.Debug(preamble, "request", dump)

}

// LogResponse logs the contents of an http.Response object
func LogResponse(preamble string, resp *http.Response) {
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		logger.Debug("logResponse: Error dumping response", "error", err)
		return
	}
	if preamble != "" {
		preamble = preamble + ":\n"
	}
	logger.Debug(preamble, "response", dump)
}

// CleanHeaders removes all headers from the request that start with "X-"
func CleanHeaders(req *http.Request) {
	for key := range req.Header {
		if strings.HasPrefix(key, "X-") && key != proxyConfigHeader {
			req.Header.Del(key)
		}
	}
}

// SlashJoin joins the two given strings with a slash (ensuring exactly one slash)
func SlashJoin(a, b string) string {
	return fmt.Sprintf("%s/%s", strings.TrimRight(a, "/"), strings.TrimLeft(b, "/"))
}
