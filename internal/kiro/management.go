package kiro

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

// usageRoutePath is the Management API path (under /v0/management/) that reports
// Kiro usage limits. Relative form; the host resolves it under the base prefix.
const usageRoutePath = "kiro-usage"

// managementRoute mirrors pluginapi.ManagementRoute on the wire (PascalCase, no
// Handler — the host attaches its own adapter and calls back via management.handle).
type managementRoute struct {
	Method      string
	Path        string
	Menu        string
	Description string
}

// managementRegistrationResult mirrors the host's rpcManagementRegistrationResponse.
type managementRegistrationResult struct {
	Routes []managementRoute `json:"routes,omitempty"`
}

// managementHandleRequest mirrors the host's rpcManagementRequest: the embedded
// ManagementRequest plus host_callback_id (host.http.do is available during handling).
type managementHandleRequest struct {
	pluginapi.ManagementRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

// registerManagement declares the plugin's Management API routes.
func registerManagement() ([]byte, error) {
	return wire.OK(managementRegistrationResult{
		Routes: []managementRoute{
			{
				Method:      http.MethodGet,
				Path:        usageRoutePath,
				Description: "Report Kiro getUsageLimits for all kiro credentials (optional ?auth=<auth_index|name>).",
			},
		},
	})
}

// handleManagement dispatches an authenticated Management API request to the
// matching plugin route handler.
func handleManagement(request []byte) ([]byte, error) {
	var req managementHandleRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	// Match by path suffix so both the relative and fully-resolved forms work.
	if strings.EqualFold(req.Method, http.MethodGet) && strings.HasSuffix(strings.TrimRight(req.Path, "/"), usageRoutePath) {
		return wire.OK(handleUsageLimits(req.HostCallbackID, req.Query))
	}

	return wire.OK(pluginapi.ManagementResponse{
		StatusCode: http.StatusNotFound,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       []byte(`{"error":"unknown kiro management route"}`),
	})
}
