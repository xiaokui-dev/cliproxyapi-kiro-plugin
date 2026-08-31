package kiro

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

const (
	defaultKiroRegion        = "us-east-1"
	socialRefreshURLTemplate = "https://prod.%s.auth.desktop.kiro.dev/refreshToken"
	idcRefreshURLTemplate    = "https://oidc.%s.amazonaws.com/token"
	refreshLeadTime          = 5 * time.Minute
	defaultExpiresInSeconds  = 3600
	// refreshIntervalSeconds is advertised to the host via metadata so its
	// auto-refresh scheduler treats the auth as having a preferred refresh cadence.
	refreshIntervalSeconds = 300
)

// authRefreshRequest mirrors the host's rpcAuthRefreshRequest: the embedded
// AuthRefreshRequest fields (PascalCase) plus host_callback_id.
type authRefreshRequest struct {
	pluginapi.AuthRefreshRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

// kiroRefreshResponse is the token payload returned by both refresh endpoints.
type kiroRefreshResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ProfileArn   string `json:"profileArn"`
	ExpiresIn    int    `json:"expiresIn"`
}

// refreshKiroAuth refreshes a Kiro access token using the stored refresh token.
// The endpoint and body depend on authMethod: social uses the Kiro auth service,
// builder-id/IDC uses AWS SSO OIDC token exchange.
func refreshKiroAuth(request []byte) ([]byte, error) {
	var req authRefreshRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	var cred kiroCredential
	if errUnmarshal := json.Unmarshal(req.StorageJSON, &cred); errUnmarshal != nil {
		return nil, fmt.Errorf("decode kiro credential: %w", errUnmarshal)
	}
	if strings.TrimSpace(cred.RefreshToken) == "" {
		return wire.ErrorStatus("invalid_credential", "kiro credential has no refreshToken", http.StatusUnauthorized), nil
	}

	tokenResp, status, errRefresh := performKiroRefresh(req.HostCallbackID, cred)
	if errRefresh != nil {
		if status == 0 {
			status = http.StatusBadGateway
		}
		return wire.ErrorStatus("refresh_failed", errRefresh.Error(), status), nil
	}

	cred.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		cred.RefreshToken = tokenResp.RefreshToken
	}
	if tokenResp.ProfileArn != "" {
		cred.ProfileArn = tokenResp.ProfileArn
	}
	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = defaultExpiresInSeconds
	}
	expiresAt := time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)
	cred.ExpiresAt = expiresAt.Format(time.RFC3339)

	newStorage, errMarshal := json.Marshal(cred)
	if errMarshal != nil {
		return nil, fmt.Errorf("encode kiro credential: %w", errMarshal)
	}

	metadata := req.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["type"] = providerKiro
	metadata["expiresAt"] = cred.ExpiresAt
	metadata["refresh_interval_seconds"] = refreshIntervalSeconds
	if cred.AuthMethod != "" {
		metadata["authMethod"] = cred.AuthMethod
	}

	return wire.OK(pluginapi.AuthRefreshResponse{
		Auth: pluginapi.AuthData{
			Provider:    providerKiro,
			StorageJSON: newStorage,
			Metadata:    metadata,
		},
		NextRefreshAfter: expiresAt.Add(-refreshLeadTime),
	})
}

// performKiroRefresh sends the refresh request to the correct endpoint and
// returns the token payload, the upstream HTTP status, and any error.
func performKiroRefresh(callbackID string, cred kiroCredential) (*kiroRefreshResponse, int, error) {
	isSocial := strings.EqualFold(strings.TrimSpace(cred.AuthMethod), "social")

	var url string
	var bodyObj map[string]string
	if isSocial {
		region := firstNonEmptyStr(cred.Region, defaultKiroRegion)
		url = fmt.Sprintf(socialRefreshURLTemplate, region)
		bodyObj = map[string]string{"refreshToken": cred.RefreshToken}
	} else {
		region := firstNonEmptyStr(cred.IDCRegion, cred.Region, defaultKiroRegion)
		url = fmt.Sprintf(idcRefreshURLTemplate, region)
		bodyObj = map[string]string{
			"refreshToken": cred.RefreshToken,
			"clientId":     cred.ClientID,
			"clientSecret": cred.ClientSecret,
			"grantType":    "refresh_token",
		}
	}

	bodyBytes, errMarshal := json.Marshal(bodyObj)
	if errMarshal != nil {
		return nil, 0, fmt.Errorf("encode refresh body: %w", errMarshal)
	}

	resp, errDo := kiroHTTPDo(hostapi.HTTPRequest{
		HostCallbackID: callbackID,
		Method:         http.MethodPost,
		URL:            url,
		Headers:        map[string][]string{"Content-Type": {"application/json"}},
		Body:           bodyBytes,
	})
	if errDo != nil {
		return nil, 0, errDo
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("kiro refresh HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 200))
	}

	var tokenResp kiroRefreshResponse
	if errUnmarshal := json.Unmarshal(resp.Body, &tokenResp); errUnmarshal != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode kiro refresh response: %w", errUnmarshal)
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return nil, resp.StatusCode, fmt.Errorf("kiro refresh response missing accessToken")
	}
	return &tokenResp, resp.StatusCode, nil
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
