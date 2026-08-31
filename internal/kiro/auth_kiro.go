package kiro

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/config"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

// parseKiroAuth recognizes Kiro credential files and converts them into AuthData.
// The raw credential JSON is preserved verbatim as StorageJSON so no field is lost.
func parseKiroAuth(request []byte) ([]byte, error) {
	var req pluginapi.AuthParseRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	var cred kiroCredential
	if errUnmarshal := json.Unmarshal(req.RawJSON, &cred); errUnmarshal != nil {
		// Not JSON we understand: report unhandled so other providers can try.
		return wire.OK(pluginapi.AuthParseResponse{Handled: false})
	}
	if !looksLikeKiro(cred) {
		return wire.OK(pluginapi.AuthParseResponse{Handled: false})
	}

	metadata := map[string]any{
		"type": providerKiro,
		// Drives the host's auto-refresh scheduler for plugin providers: with a
		// preferred interval set, the scheduler keeps the auth queued and refreshes
		// it as expiresAt approaches (plugins cannot register a RefreshLead).
		"refresh_interval_seconds": refreshIntervalSeconds,
	}
	if cred.AuthMethod != "" {
		metadata["authMethod"] = cred.AuthMethod
	}
	if cred.Region != "" {
		metadata["region"] = cred.Region
	}
	if cred.ExpiresAt != "" {
		metadata["expiresAt"] = cred.ExpiresAt
	}

	label := "Kiro"
	if cred.AuthMethod != "" {
		label = "Kiro (" + cred.AuthMethod + ")"
	}

	// ID and FileName are filled in by the host from req.Path / req.FileName.
	authData := pluginapi.AuthData{
		Provider:    providerKiro,
		Label:       label,
		StorageJSON: req.RawJSON,
		Metadata:    metadata,
	}

	// Plugin providers cannot register a RefreshLead with the host, so the host's
	// auto-refresh loop only reschedules a plugin auth through NextRefreshAfter.
	// Derive it from expiresAt (with lead) so the token is refreshed BEFORE it
	// expires; if already (near) expired, schedule a refresh shortly after load.
	// The value must be in the future to be picked up by the refresh scheduler.
	if exp, ok := parseKiroTime(cred.ExpiresAt); ok {
		next := exp.Add(-refreshLeadTime)
		soon := time.Now().Add(30 * time.Second)
		if next.Before(soon) {
			next = soon
		}
		authData.NextRefreshAfter = next
	}

	return wire.OK(pluginapi.AuthParseResponse{Handled: true, Auth: authData})
}

// looksLikeKiro decides whether the credential material belongs to Kiro.
func looksLikeKiro(cred kiroCredential) bool {
	if strings.EqualFold(strings.TrimSpace(cred.Type), providerKiro) {
		return true
	}
	// Heuristic for files without an explicit type: Kiro credentials always
	// carry a refresh token together with an auth method (social / builder-id).
	return cred.RefreshToken != "" && cred.AuthMethod != ""
}

// authLoginStartRequest / authLoginPollRequest mirror the host's login RPC
// wire schema: the embedded pluginapi request (PascalCase) plus host_callback_id,
// which binds host.http.do calls to the host transport for this login flow.
type authLoginStartRequest struct {
	pluginapi.AuthLoginStartRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type authLoginPollRequest struct {
	pluginapi.AuthLoginPollRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

// startKiroLogin begins an AWS Builder ID device-code login. It registers an OIDC
// client and starts device authorization, then returns the user-facing
// verification URL plus an opaque State and the device-code context in Metadata.
// The host persists Metadata against State and hands it back on each poll (the
// plugin is stateless across calls, so all flow state travels through Metadata).
func startKiroLogin(request []byte) ([]byte, error) {
	var req authLoginStartRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	// Choose the login target from the explicit login_method config; when unset,
	// fall back to the legacy heuristic (start_url set => org IdC, else Builder ID).
	cfg := config.Get()
	target := resolveLoginTarget(cfg.LoginMethod, cfg.StartURL)
	switch target {
	case loginTargetSocial:
		return wire.ErrorStatus("login_unsupported",
			"Google / GitHub 暂不支持交互登录：请在 Kiro 桌面应用登录后，导出凭据 JSON（含 accessToken/refreshToken/profileArn/authMethod=social/region）放入宿主 auth-dir 导入。",
			http.StatusNotImplemented), nil
	case loginTargetIDC:
		if strings.TrimSpace(cfg.StartURL) == "" {
			return wire.ErrorStatus("login_config_missing",
				"IDC 登录需要先在插件配置里填写 start_url（组织 IAM Identity Center 门户 URL）后再发起登录。",
				http.StatusBadRequest), nil
		}
	}

	// Only the IDC path uses start_url; Builder ID always uses its default portal
	// even if a stale start_url lingers in the config.
	startURL := ""
	authMethod := builderIDAuthMethod
	region := firstNonEmptyStr(cfg.Region, defaultKiroRegion)
	if target == loginTargetIDC {
		startURL = cfg.StartURL
		authMethod = idcAuthMethod
		region = firstNonEmptyStr(cfg.IDCRegion, cfg.Region, defaultKiroRegion)
	}

	reg, errRegister := builderIDRegisterClient(req.HostCallbackID, region)
	if errRegister != nil {
		return wire.ErrorStatus("login_register_failed", errRegister.Error(), http.StatusBadGateway), nil
	}
	device, errDevice := builderIDStartDeviceAuth(req.HostCallbackID, region, reg.ClientID, reg.ClientSecret, startURL)
	if errDevice != nil {
		return wire.ErrorStatus("login_device_failed", errDevice.Error(), http.StatusBadGateway), nil
	}

	expiresIn := device.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = defaultDeviceExpiresIn
	}
	interval := device.Interval
	if interval <= 0 {
		interval = defaultDeviceInterval
	}
	url := firstNonEmptyStr(device.VerificationURIComplete, device.VerificationURI)

	metadata := map[string]any{
		"authMethod":   authMethod,
		"clientId":     reg.ClientID,
		"clientSecret": reg.ClientSecret,
		"deviceCode":   device.DeviceCode,
		"region":       region,
		"interval":     interval,
	}
	if device.UserCode != "" {
		metadata["userCode"] = device.UserCode
	}

	return wire.OK(pluginapi.AuthLoginStartResponse{
		Provider:  providerKiro,
		URL:       url,
		State:     "kiro-" + randomHexN(16),
		ExpiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second),
		Metadata:  metadata,
	})
}

// pollKiroLogin performs a single token poll for a Builder ID device-code login.
// It reads the device-code context from Metadata (round-tripped by the host from
// StartLogin) and returns pending until the user approves, then success with the
// completed Kiro credential as AuthData.
func pollKiroLogin(request []byte) ([]byte, error) {
	var req authLoginPollRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	metadata := req.Metadata
	clientID := metaString(metadata, "clientId")
	clientSecret := metaString(metadata, "clientSecret")
	deviceCode := metaString(metadata, "deviceCode")
	region := firstNonEmptyStr(metaString(metadata, "region"), defaultKiroRegion)
	authMethod := firstNonEmptyStr(metaString(metadata, "authMethod"), builderIDAuthMethod)
	if clientID == "" || clientSecret == "" || deviceCode == "" {
		return wire.OK(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "login session is missing device-code context",
		})
	}

	token, errPoll := builderIDPollToken(req.HostCallbackID, region, clientID, clientSecret, deviceCode)
	if errPoll != nil {
		return wire.OK(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: errPoll.Error(),
		})
	}

	if token.AccessToken != "" {
		return wire.OK(buildLoginSuccess(token, clientID, clientSecret, region, authMethod))
	}

	switch token.Error {
	case "", "authorization_pending", "slow_down":
		return wire.OK(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "waiting for user authorization",
		})
	default:
		return wire.OK(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "authorization failed: " + token.Error,
		})
	}
}

// buildLoginSuccess assembles the AuthData for a completed device-code login,
// matching what parseKiroAuth / refreshKiroAuth expect (type + authMethod +
// expiresAt + refresh_interval_seconds, and NextRefreshAfter for proactive
// refresh). authMethod distinguishes AWS Builder ID from org IdC; both refresh
// through the same SSO OIDC token endpoint.
func buildLoginSuccess(token *oidcTokenResponse, clientID, clientSecret, region, authMethod string) pluginapi.AuthLoginPollResponse {
	if authMethod == "" {
		authMethod = builderIDAuthMethod
	}
	expiresIn := token.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = defaultExpiresInSeconds
	}
	expiresAt := time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)

	cred := kiroCredential{
		Type:         providerKiro,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		AuthMethod:   authMethod,
		Region:       region,
		IDCRegion:    region,
	}
	storage, errMarshal := json.Marshal(cred)
	if errMarshal != nil {
		return pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "encode credential: " + errMarshal.Error(),
		}
	}

	fileName := "kiro-" + randomHexN(6) + ".json"
	metadata := map[string]any{
		"type":                     providerKiro,
		"authMethod":               authMethod,
		"expiresAt":                cred.ExpiresAt,
		"region":                   region,
		"refresh_interval_seconds": refreshIntervalSeconds,
	}

	return pluginapi.AuthLoginPollResponse{
		Status: pluginapi.AuthLoginStatusSuccess,
		Auth: pluginapi.AuthData{
			Provider:         providerKiro,
			ID:               fileName,
			FileName:         fileName,
			Label:            "Kiro (" + authMethod + ")",
			StorageJSON:      storage,
			Metadata:         metadata,
			NextRefreshAfter: expiresAt.Add(-refreshLeadTime),
		},
	}
}

// loginTarget is the resolved interactive-login path.
type loginTarget int

const (
	loginTargetBuilderID loginTarget = iota
	loginTargetIDC
	loginTargetSocial
)

// resolveLoginTarget maps the config's login_method (with the legacy start_url
// heuristic as fallback) to a concrete login path. Matching is case-insensitive
// and tolerant of the "(...)" annotations shown in the dropdown.
func resolveLoginTarget(loginMethod, startURL string) loginTarget {
	switch normalizeLoginMethod(loginMethod) {
	case "aws builder id", "builder id", "builder-id", "builderid":
		return loginTargetBuilderID
	case "idc", "iam identity center", "your organization":
		return loginTargetIDC
	case "google", "github", "social":
		return loginTargetSocial
	case "":
		// No explicit choice: preserve the historical behavior.
		if strings.TrimSpace(startURL) != "" {
			return loginTargetIDC
		}
		return loginTargetBuilderID
	default:
		return loginTargetBuilderID
	}
}

// normalizeLoginMethod lowercases and strips any parenthetical annotation from a
// login_method value (e.g. "Google (导入)" -> "google").
func normalizeLoginMethod(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	if i := strings.IndexByte(s, '('); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// metaString reads a string value from a login metadata map, tolerating the
// value being absent or a non-string.
func metaString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
