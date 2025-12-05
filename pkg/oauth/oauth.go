package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rubenszinho/go-auth-service/internal/config"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

// Provider represents an OAuth provider
type Provider string

const (
	ProviderGoogle    Provider = "google"
	ProviderGitHub    Provider = "github"
	ProviderMicrosoft Provider = "microsoft"
)

// UserInfo represents user information from OAuth provider
type UserInfo struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Avatar   string `json:"avatar"`
	Provider string `json:"provider"`
}

// OAuthManager manages OAuth operations
type oauthManager struct {
	configs map[Provider]*oauth2.Config
}

type Manager = oauthManager

func OAuthManager(cfg *config.Config) *Manager {
	configs := make(map[Provider]*oauth2.Config)

	if cfg.OAuth.Google.ClientID != "" {
		configs[ProviderGoogle] = &oauth2.Config{
			ClientID:     cfg.OAuth.Google.ClientID,
			ClientSecret: cfg.OAuth.Google.ClientSecret,
			RedirectURL:  cfg.OAuth.Google.RedirectURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     google.Endpoint,
		}
	}

	if cfg.OAuth.GitHub.ClientID != "" {
		configs[ProviderGitHub] = &oauth2.Config{
			ClientID:     cfg.OAuth.GitHub.ClientID,
			ClientSecret: cfg.OAuth.GitHub.ClientSecret,
			RedirectURL:  cfg.OAuth.GitHub.RedirectURL,
			Scopes:       []string{"user:email"},
			Endpoint:     github.Endpoint,
		}
	}

	if cfg.OAuth.Microsoft.ClientID != "" {
		configs[ProviderMicrosoft] = &oauth2.Config{
			ClientID:     cfg.OAuth.Microsoft.ClientID,
			ClientSecret: cfg.OAuth.Microsoft.ClientSecret,
			RedirectURL:  cfg.OAuth.Microsoft.RedirectURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     microsoft.AzureADEndpoint("common"),
		}
	}

	return &oauthManager{
		configs: configs,
	}
}

// GetAuthURL returns the authorization URL for the specified provider
func (o *oauthManager) GetAuthURL(provider Provider, state string) (string, error) {
	config, exists := o.configs[provider]
	if !exists {
		return "", fmt.Errorf("provider %s not configured", provider)
	}

	return config.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

// ExchangeCode exchanges authorization code for access token and user info
func (o *oauthManager) ExchangeCode(ctx context.Context, provider Provider, code string) (*UserInfo, error) {
	config, exists := o.configs[provider]
	if !exists {
		return nil, fmt.Errorf("provider %s not configured", provider)
	}

	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	switch provider {
	case ProviderGoogle:
		return o.getGoogleUserInfo(ctx, config, token)
	case ProviderGitHub:
		return o.getGitHubUserInfo(ctx, config, token)
	case ProviderMicrosoft:
		return o.getMicrosoftUserInfo(ctx, config, token)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

// getGoogleUserInfo retrieves user info from Google
func (o *oauthManager) getGoogleUserInfo(ctx context.Context, config *oauth2.Config, token *oauth2.Token) (*UserInfo, error) {
	client := config.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var googleUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}

	if err := json.Unmarshal(body, &googleUser); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info: %w", err)
	}

	return &UserInfo{
		ID:       googleUser.ID,
		Email:    googleUser.Email,
		Name:     googleUser.Name,
		Avatar:   googleUser.Picture,
		Provider: string(ProviderGoogle),
	}, nil
}

// getGitHubUserInfo retrieves user info from GitHub
func (o *oauthManager) getGitHubUserInfo(ctx context.Context, config *oauth2.Config, token *oauth2.Token) (*UserInfo, error) {
	client := config.Client(ctx, token)

	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var githubUser struct {
		ID     int    `json:"id"`
		Login  string `json:"login"`
		Name   string `json:"name"`
		Email  string `json:"email"`
		Avatar string `json:"avatar_url"`
	}

	if err := json.Unmarshal(body, &githubUser); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info: %w", err)
	}

	email := githubUser.Email
	if email == "" {
		email, _ = o.getGitHubUserEmail(ctx, client)
	}

	name := githubUser.Name
	if name == "" {
		name = githubUser.Login
	}

	return &UserInfo{
		ID:       fmt.Sprintf("%d", githubUser.ID),
		Email:    email,
		Name:     name,
		Avatar:   githubUser.Avatar,
		Provider: string(ProviderGitHub),
	}, nil
}

// getGitHubUserEmail retrieves primary email from GitHub
func (o *oauthManager) getGitHubUserEmail(ctx context.Context, client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary {
			return email.Email, nil
		}
	}

	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", fmt.Errorf("no email found")
}

// getMicrosoftUserInfo retrieves user info from Microsoft
func (o *oauthManager) getMicrosoftUserInfo(ctx context.Context, config *oauth2.Config, token *oauth2.Token) (*UserInfo, error) {
	client := config.Client(ctx, token)
	resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var microsoftUser struct {
		ID                string `json:"id"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
		DisplayName       string `json:"displayName"`
	}

	if err := json.Unmarshal(body, &microsoftUser); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info: %w", err)
	}

	email := microsoftUser.Mail
	if email == "" {
		email = microsoftUser.UserPrincipalName
	}

	return &UserInfo{
		ID:       microsoftUser.ID,
		Email:    email,
		Name:     microsoftUser.DisplayName,
		Avatar:   "",
		Provider: string(ProviderMicrosoft),
	}, nil
}

// IsProviderSupported checks if a provider is supported
func (o *oauthManager) IsProviderSupported(provider Provider) bool {
	_, exists := o.configs[provider]
	return exists
}

// GetSupportedProviders returns list of configured providers
func (o *oauthManager) GetSupportedProviders() []Provider {
	providers := make([]Provider, 0, len(o.configs))
	for provider := range o.configs {
		providers = append(providers, provider)
	}
	return providers
}
