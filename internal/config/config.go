// Package config parses and stores the plugin's configurable settings (the
// plugins.configs.kiro sub-tree delivered by the host on register/reconfigure).
package config

import (
	"encoding/json"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config holds the plugin's configurable settings. LoginMethod is the explicit
// interactive-login target chosen in the management UI; when empty the plugin
// falls back to the legacy heuristic (StartURL set => org IdC, otherwise AWS
// Builder ID).
type Config struct {
	LoginMethod string `yaml:"login_method"`
	Region      string `yaml:"region"`
	StartURL    string `yaml:"start_url"`
	IDCRegion   string `yaml:"idc_region"`
	BaseURL     string `yaml:"base_url"`
}

var (
	mu      sync.RWMutex
	current Config
)

// pluginConfigRequest is the subset of the register/reconfigure RPC we read: the
// host delivers the plugin's config sub-tree as YAML bytes (base64 in JSON).
type pluginConfigRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

// Apply parses the config_yaml carried by a register/reconfigure request and
// stores it. Missing or malformed config leaves an empty config (interactive
// login then defaults to Builder ID).
func Apply(request []byte) {
	var req pluginConfigRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return
	}
	var cfg Config
	if len(req.ConfigYAML) > 0 {
		if errYAML := yaml.Unmarshal(req.ConfigYAML, &cfg); errYAML != nil {
			return
		}
	}
	cfg.LoginMethod = strings.TrimSpace(cfg.LoginMethod)
	cfg.Region = strings.TrimSpace(cfg.Region)
	cfg.StartURL = strings.TrimSpace(cfg.StartURL)
	cfg.IDCRegion = strings.TrimSpace(cfg.IDCRegion)
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)

	mu.Lock()
	current = cfg
	mu.Unlock()
}

// Get returns a copy of the current plugin config.
func Get() Config {
	mu.RLock()
	defer mu.RUnlock()
	return current
}
