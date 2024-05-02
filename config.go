package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type ProxyItem struct {
	RegistryHost string `yaml:"registry"`
	RemotePrefix string `yaml:"remote"`
	LocalPrefix  string `yaml:"-"` // this is set from the item name
	AuthHeader   string `yaml:"auth"`
}

type Config struct {
	ListenAddr string               `yaml:"listen_addr"`
	ListenPort string               `yaml:"listen_port"`
	Proxies    map[string]ProxyItem `yaml:"proxies"`
	SecretKey  string               `yaml:"secretkey"`
}

func LoadConfig() (Config, error) {
	configPath := GetEnvDefault("CONFIG_PATH", "./config.yaml")

	var config Config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, err
	}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, err
	}

	if config.ListenAddr == "" {
		config.ListenAddr = GetEnvDefault("LISTEN_ADDR", "0.0.0.0")
	}
	if config.ListenPort == "" {
		config.ListenPort = GetEnvDefault("LISTEN_PORT", "5000")
	}

	// set LocalPrefix from ProxyItem names
	for proxyName, proxyItem := range config.Proxies {
		proxyItem.LocalPrefix = proxyName
		config.Proxies[proxyName] = proxyItem
	}

	return config, nil
}

// Log writes a pretty-printed version of the configuration
func (cfg Config) Log() {
	// log the fully-parsed config data
	configJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatalf("problem printing config: +%v", err)
	}
	log.Printf("starting up with the following configuration:\n%s", configJSON)

}

// BestMatch searches through the configured proxies and tries to find the best
// match for the given auth token resource scope based on the LocalPrefix values
func (cfg Config) BestMatch(scope *ResourceScope) (ProxyItem, error) {
	if exactMatch, ok := cfg.Proxies[scope.ResourceName]; ok {
		return exactMatch, nil
	}

	// we allow partial matches if the LocalPrefix ends in a slash
	var matches []ProxyItem
	for _, proxy := range cfg.Proxies {
		if strings.HasSuffix(proxy.LocalPrefix, "/") && strings.HasPrefix(scope.ResourceName, proxy.LocalPrefix) {
			matches = append(matches, proxy)
		}
	}

	if len(matches) == 0 {
		return ProxyItem{}, fmt.Errorf("no matching proxy configuration was found")
	}

	return matches[0], nil
}

// GetEnvDefault retrieves the value of the environment variable named by key.
// If the key is not present, it returns the defaultValue.
func GetEnvDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
