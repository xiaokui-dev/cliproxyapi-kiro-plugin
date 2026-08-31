package kiro

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"
)

// AWS Builder ID / IAM Identity Center device-code login constants.
// The flow is: register an OIDC client, start device authorization (which yields
// a user-facing verification URL), then poll the token endpoint until the user
// approves.
const (
	ssoOIDCEndpointTemplate = "https://oidc.%s.amazonaws.com"
	builderIDStartURL       = "https://view.awsapps.com/start"
	builderIDClientName     = "Kiro IDE"
	builderIDClientType     = "public"
	builderIDGrantType      = "urn:ietf:params:oauth:grant-type:device_code"
	builderIDAuthMethod     = "builder-id"
	// idcAuthMethod marks credentials obtained via an organization's IAM Identity
	// Center portal ("Your organization" login). Both builder-id and IdC refresh
	// through the same SSO OIDC token endpoint.
	idcAuthMethod = "IdC"
	// loginMethod* are the enum values exposed in the config UI's login_method
	// dropdown. They select the interactive-login target at login.start time.
	loginMethodBuilderID = "AWS Builder ID"
	loginMethodIDC       = "IDC"
	loginMethodGoogle    = "Google"
	loginMethodGitHub    = "GitHub"
	// defaultDeviceExpiresIn / defaultDeviceInterval are fallbacks when the
	// device_authorization response omits expiresIn / interval.
	defaultDeviceExpiresIn = 600
	defaultDeviceInterval  = 5
)

// builderIDScopes are the CodeWhisperer scopes requested for the OIDC client.
var builderIDScopes = []string{
	"codewhisperer:completions",
	"codewhisperer:analysis",
	"codewhisperer:conversations",
}

// oidcRegisterResponse is the client/register result.
type oidcRegisterResponse struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// oidcDeviceAuthResponse is the device_authorization result.
type oidcDeviceAuthResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
}

// oidcTokenResponse is the token result. On success AccessToken is set; while the
// user has not approved yet, Error carries "authorization_pending" / "slow_down".
type oidcTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
	Error        string `json:"error"`
}

// builderIDRegisterClient registers a public OIDC client and returns its
// credentials. Uses the host transport via the login callback context.
func builderIDRegisterClient(callbackID, region string) (*oidcRegisterResponse, error) {
	body, errMarshal := json.Marshal(map[string]any{
		"clientName": builderIDClientName,
		"clientType": builderIDClientType,
		"scopes":     builderIDScopes,
	})
	if errMarshal != nil {
		return nil, errMarshal
	}
	resp, errDo := kiroHTTPDo(hostapi.HTTPRequest{
		HostCallbackID: callbackID,
		Method:         http.MethodPost,
		URL:            fmt.Sprintf(ssoOIDCEndpointTemplate, region) + "/client/register",
		Headers:        map[string][]string{"Content-Type": {"application/json"}, "User-Agent": {"KiroIDE"}},
		Body:           body,
	})
	if errDo != nil {
		return nil, errDo
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("client register HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 200))
	}
	var out oidcRegisterResponse
	if errUnmarshal := json.Unmarshal(resp.Body, &out); errUnmarshal != nil {
		return nil, fmt.Errorf("decode client register response: %w", errUnmarshal)
	}
	if out.ClientID == "" || out.ClientSecret == "" {
		return nil, fmt.Errorf("client register response missing clientId/clientSecret")
	}
	return &out, nil
}

// builderIDStartDeviceAuth starts device authorization for the given startUrl
// (the Builder ID portal or an organization's IdC portal) and returns the device
// code plus the user-facing verification URL.
func builderIDStartDeviceAuth(callbackID, region, clientID, clientSecret, startURL string) (*oidcDeviceAuthResponse, error) {
	if strings.TrimSpace(startURL) == "" {
		startURL = builderIDStartURL
	}
	body, errMarshal := json.Marshal(map[string]any{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"startUrl":     startURL,
	})
	if errMarshal != nil {
		return nil, errMarshal
	}
	resp, errDo := kiroHTTPDo(hostapi.HTTPRequest{
		HostCallbackID: callbackID,
		Method:         http.MethodPost,
		URL:            fmt.Sprintf(ssoOIDCEndpointTemplate, region) + "/device_authorization",
		Headers:        map[string][]string{"Content-Type": {"application/json"}},
		Body:           body,
	})
	if errDo != nil {
		return nil, errDo
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("device authorization HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 200))
	}
	var out oidcDeviceAuthResponse
	if errUnmarshal := json.Unmarshal(resp.Body, &out); errUnmarshal != nil {
		return nil, fmt.Errorf("decode device authorization response: %w", errUnmarshal)
	}
	if out.DeviceCode == "" {
		return nil, fmt.Errorf("device authorization response missing deviceCode")
	}
	return &out, nil
}

// builderIDPollToken performs a single token poll. A transport error is returned
// as err; an authorization_pending / slow_down state is returned in the response
// Error field (not as an error) so the caller can keep polling.
func builderIDPollToken(callbackID, region, clientID, clientSecret, deviceCode string) (*oidcTokenResponse, error) {
	body, errMarshal := json.Marshal(map[string]any{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"deviceCode":   deviceCode,
		"grantType":    builderIDGrantType,
	})
	if errMarshal != nil {
		return nil, errMarshal
	}
	resp, errDo := kiroHTTPDo(hostapi.HTTPRequest{
		HostCallbackID: callbackID,
		Method:         http.MethodPost,
		URL:            fmt.Sprintf(ssoOIDCEndpointTemplate, region) + "/token",
		Headers:        map[string][]string{"Content-Type": {"application/json"}, "User-Agent": {"KiroIDE"}},
		Body:           body,
	})
	if errDo != nil {
		return nil, errDo
	}
	var out oidcTokenResponse
	// The token endpoint returns the pending/slow_down state as a JSON error body
	// with a non-2xx status; parse the body regardless of status code.
	if len(resp.Body) > 0 {
		if errUnmarshal := json.Unmarshal(resp.Body, &out); errUnmarshal != nil {
			return nil, fmt.Errorf("decode token response HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 200))
		}
	}
	if out.AccessToken == "" && out.Error == "" && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return nil, fmt.Errorf("token HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 200))
	}
	return &out, nil
}
