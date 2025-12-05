package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/rubenszinho/go-auth-service/internal/models"
	"github.com/rubenszinho/go-auth-service/pkg/jwt"
	"github.com/rubenszinho/go-auth-service/pkg/oauth"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type authService struct {
	db                      *gorm.DB
	jwtManager              *jwt.Manager
	oauthManager            *oauth.Manager
	bcryptCost              int
	enableEmailDomainFilter bool
	allowedEmailDomains     []string
}

type Service = authService

func AuthService(db *gorm.DB, jwtManager *jwt.Manager, oauthManager *oauth.Manager, bcryptCost int, enableEmailDomainFilter bool, allowedEmailDomains []string) *Service {
	return &authService{
		db:                      db,
		jwtManager:              jwtManager,
		oauthManager:            oauthManager,
		bcryptCost:              bcryptCost,
		enableEmailDomainFilter: enableEmailDomainFilter,
		allowedEmailDomains:     allowedEmailDomains,
	}
}

type RegisterRequest struct {
	Email       string `json:"email" validate:"required,email"`
	Username    string `json:"username" validate:"required,min=3,max=50"`
	Password    string `json:"password" validate:"required,min=8"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type AuthResponse struct {
	User   *models.User   `json:"user"`
	Tokens *jwt.TokenPair `json:"tokens"`
}

func (s *authService) Register(ctx context.Context, req *RegisterRequest) (*AuthResponse, error) {
	if err := s.validateEmailDomain(req.Email); err != nil {
		return nil, err
	}

	var existingUser models.User
	if err := s.db.Where("email = ? OR username = ?", req.Email, req.Username).First(&existingUser).Error; err == nil {
		return nil, fmt.Errorf("user with this email or username already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		Email:       req.Email,
		Username:    req.Username,
		Password:    string(hashedPassword),
		DisplayName: req.DisplayName,
		Role:        string(models.RoleUser),
	}

	if err := s.db.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	tokens, err := s.jwtManager.GenerateTokenPair(user.ID, user.Email, user.Username, user.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	if err := s.storeRefreshToken(user.ID, tokens.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	now := time.Now().UTC()
	user.LastSignInAt = &now
	s.db.Save(user)

	return &AuthResponse{
		User:   user,
		Tokens: tokens,
	}, nil
}

func (s *authService) Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error) {
	if err := s.validateEmailDomain(req.Email); err != nil {
		return nil, err
	}

	var user models.User
	if err := s.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if user.BannedUntil != nil && user.BannedUntil.After(time.Now().UTC()) {
		return nil, fmt.Errorf("account is temporarily banned")
	}

	if user.DeletedAt != nil {
		return nil, fmt.Errorf("account is deactivated")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	tokens, err := s.jwtManager.GenerateTokenPair(user.ID, user.Email, user.Username, user.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	if err := s.storeRefreshToken(user.ID, tokens.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	now := time.Now().UTC()
	user.LastSignInAt = &now
	s.db.Save(&user)

	return &AuthResponse{
		User:   &user,
		Tokens: tokens,
	}, nil
}

func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*jwt.TokenPair, error) {
	userID, err := s.jwtManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	var storedToken models.RefreshToken
	if err := s.db.Where("user_id = ? AND token = ? AND is_revoked = false AND expires_at > ?",
		userID, refreshToken, time.Now().UTC()).First(&storedToken).Error; err != nil {
		return nil, fmt.Errorf("refresh token not found or expired")
	}

	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return nil, fmt.Errorf("user not found")
	}

	if user.DeletedAt != nil {
		return nil, fmt.Errorf("account is deactivated")
	}

	tokens, err := s.jwtManager.GenerateTokenPair(user.ID, user.Email, user.Username, user.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.db.Model(&storedToken).Update("is_revoked", true)
	if err := s.storeRefreshToken(user.ID, tokens.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return tokens, nil
}

// GetOAuthURL returns the OAuth authorization URL for a provider
func (s *authService) GetOAuthURL(provider oauth.Provider, state string) (string, error) {
	return s.oauthManager.GetAuthURL(provider, state)
}

// OAuthLogin handles OAuth login
func (s *authService) OAuthLogin(ctx context.Context, provider oauth.Provider, code string) (*AuthResponse, error) {
	userInfo, err := s.oauthManager.ExchangeCode(ctx, provider, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange OAuth code: %w", err)
	}

	if err := s.validateEmailDomain(userInfo.Email); err != nil {
		return nil, err
	}

	var user models.User

	// Google OAuth uses the existing google_id field
	if provider == oauth.ProviderGoogle {
		if err := s.db.Where("google_id = ?", userInfo.ID).First(&user).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				if err := s.db.Where("email = ?", userInfo.Email).First(&user).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						user = models.User{
							Email:       userInfo.Email,
							Username:    s.generateUsername(userInfo.Name, userInfo.Email),
							DisplayName: userInfo.Name,
							AvatarURL:   userInfo.Avatar,
							GoogleID:    userInfo.ID,
							Role:        string(models.RoleUser),
						}

						if err := s.db.Create(&user).Error; err != nil {
							return nil, fmt.Errorf("failed to create user: %w", err)
						}
					} else {
						return nil, fmt.Errorf("failed to find user: %w", err)
					}
				} else {
					user.GoogleID = userInfo.ID
					if user.AvatarURL == "" {
						user.AvatarURL = userInfo.Avatar
					}
					s.db.Save(&user)
				}
			} else {
				return nil, fmt.Errorf("failed to find user: %w", err)
			}
		}
	} else {
		// Other providers use the OAuth accounts table
		var oauthAccount models.OAuthAccount

		if err := s.db.Where("provider = ? AND provider_id = ?", userInfo.Provider, userInfo.ID).
			First(&oauthAccount).Error; err == nil {
			if err := s.db.First(&user, oauthAccount.UserID).Error; err != nil {
				return nil, fmt.Errorf("failed to find user: %w", err)
			}
		} else {
			if err := s.db.Where("email = ?", userInfo.Email).First(&user).Error; err != nil {
				if err == gorm.ErrRecordNotFound {
					user = models.User{
						Email:       userInfo.Email,
						Username:    s.generateUsername(userInfo.Name, userInfo.Email),
						DisplayName: userInfo.Name,
						AvatarURL:   userInfo.Avatar,
						Role:        string(models.RoleUser),
					}

					if err := s.db.Create(&user).Error; err != nil {
						return nil, fmt.Errorf("failed to create user: %w", err)
					}
				} else {
					return nil, fmt.Errorf("failed to find user: %w", err)
				}
			}

			oauthAccount = models.OAuthAccount{
				UserID:     user.ID,
				Provider:   userInfo.Provider,
				ProviderID: userInfo.ID,
				Email:      userInfo.Email,
				Name:       userInfo.Name,
				Avatar:     userInfo.Avatar,
			}

			if err := s.db.Create(&oauthAccount).Error; err != nil {
				return nil, fmt.Errorf("failed to create OAuth account: %w", err)
			}
		}
	}

	if user.DeletedAt != nil {
		return nil, fmt.Errorf("account is deactivated")
	}

	tokens, err := s.jwtManager.GenerateTokenPair(user.ID, user.Email, user.Username, user.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	if err := s.storeRefreshToken(user.ID, tokens.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	now := time.Now().UTC()
	user.LastSignInAt = &now
	s.db.Save(&user)

	return &AuthResponse{
		User:   &user,
		Tokens: tokens,
	}, nil
}

// Logout revokes refresh tokens
func (s *authService) Logout(ctx context.Context, userID uuid.UUID) error {
	return s.db.Model(&models.RefreshToken{}).
		Where("user_id = ? AND is_revoked = false", userID).
		Update("is_revoked", true).Error
}

func (s *authService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// Helper methods
func (s *authService) storeRefreshToken(userID uuid.UUID, token string) error {
	refreshToken := &models.RefreshToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour), // 7 days
	}
	return s.db.Create(refreshToken).Error
}

func (s *authService) generateUsername(name, email string) string {
	var baseUsername string

	if name != "" {
		// Use name as base, remove spaces and make lowercase
		username := ""
		for _, r := range name {
			if r != ' ' {
				username += string(r)
			}
		}
		if len(username) >= 3 {
			baseUsername = username[:min(len(username), 15)] // Leave room for suffix
		}
	}

	// If no valid name, use email prefix
	if baseUsername == "" {
		for i, r := range email {
			if r == '@' {
				baseUsername = email[:min(i, 15)]
				break
			}
		}
	}

	// If still no username, use random
	if baseUsername == "" {
		return s.generateRandomString(8)
	}

	// Check if username already exists, if so, add random suffix
	var existingUser models.User
	if err := s.db.Where("username = ?", baseUsername).First(&existingUser).Error; err == nil {
		// Username exists, add random suffix
		suffix := s.generateRandomString(5)
		return baseUsername + suffix
	}

	return baseUsername
}

func (s *authService) extractFirstName(fullName string) string {
	if fullName == "" {
		return "User"
	}

	for i, r := range fullName {
		if r == ' ' {
			return fullName[:i]
		}
	}
	return fullName
}

func (s *authService) extractLastName(fullName string) string {
	if fullName == "" {
		return ""
	}

	lastSpace := -1
	for i, r := range fullName {
		if r == ' ' {
			lastSpace = i
		}
	}

	if lastSpace > 0 && lastSpace < len(fullName)-1 {
		return fullName[lastSpace+1:]
	}
	return ""
}

func (s *authService) generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// validateEmailDomain checks if email domain is allowed (when filter is enabled)
// Supports:
// - Exact domain matching: "example.com"
// - Wildcard domain matching: "*@example.com"
// - Individual email addresses: "user@gmail.com"
func (s *authService) validateEmailDomain(email string) error {
	// If filter is disabled, allow all emails
	if !s.enableEmailDomainFilter {
		return nil
	}

	// If no allowed domains configured, allow all emails
	if len(s.allowedEmailDomains) == 0 {
		return nil
	}

	// Extract domain from email
	atIndex := -1
	for i, r := range email {
		if r == '@' {
			atIndex = i
			break
		}
	}

	if atIndex == -1 {
		return fmt.Errorf("invalid email format")
	}

	emailDomain := email[atIndex+1:]

	// Check if email or domain is in allowed list
	for _, allowed := range s.allowedEmailDomains {
		// Case 1: Exact email match (e.g., "user@gmail.com")
		if allowed == email {
			return nil
		}

		// Case 2: Wildcard domain match (e.g., "*@example.com")
		if len(allowed) > 2 && allowed[0] == '*' && allowed[1] == '@' {
			allowedDomain := allowed[2:]
			if emailDomain == allowedDomain {
				return nil
			}
		}

		// Case 3: Plain domain match (e.g., "example.com")
		if allowed == emailDomain {
			return nil
		}
	}

	return fmt.Errorf("access restricted: only emails from authorized domains are allowed during testing phase")
}
