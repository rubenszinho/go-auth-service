package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rubenszinho/go-auth-service/internal/services"
	"github.com/rubenszinho/go-auth-service/pkg/jwt"
	"github.com/rubenszinho/go-auth-service/pkg/oauth"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type authHandler struct {
	authService     *services.Service
	validator       *validator.Validate
	logger          *zap.Logger
	authFrontendURL string
}

type Handler = authHandler

func AuthHandler(authService *services.Service, logger *zap.Logger, authFrontendURL string) *Handler {
	return &authHandler{
		authService:     authService,
		validator:       validator.New(),
		logger:          logger,
		authFrontendURL: authFrontendURL,
	}
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type SuccessResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

func (h *authHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req services.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	response, err := h.authService.Register(r.Context(), &req)
	if err != nil {
		h.logger.Error("Registration failed", zap.Error(err))
		h.writeErrorResponse(w, http.StatusBadRequest, "Registration failed", err.Error())
		return
	}

	h.writeSuccessResponse(w, http.StatusCreated, response, "User registered successfully")
}

func (h *authHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req services.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	response, err := h.authService.Login(r.Context(), &req)
	if err != nil {
		h.logger.Error("Login failed", zap.Error(err))
		h.writeErrorResponse(w, http.StatusUnauthorized, "Login failed", err.Error())
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, response, "Login successful")
}

func (h *authHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	tokens, err := h.authService.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		h.logger.Error("Token refresh failed", zap.Error(err))
		h.writeErrorResponse(w, http.StatusUnauthorized, "Token refresh failed", err.Error())
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, tokens, "Token refreshed successfully")
}

func (h *authHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("user_claims").(*jwt.Claims)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "No user claims found", "")
		return
	}

	if err := h.authService.Logout(r.Context(), claims.UserID); err != nil {
		h.logger.Error("Logout failed", zap.Error(err))
		h.writeErrorResponse(w, http.StatusInternalServerError, "Logout failed", err.Error())
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, nil, "Logout successful")
}

func (h *authHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("user_claims").(*jwt.Claims)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "No user claims found", "")
		return
	}

	user, err := h.authService.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		h.logger.Error("Failed to get user profile", zap.Error(err))
		h.writeErrorResponse(w, http.StatusNotFound, "User not found", err.Error())
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, user, "Profile retrieved successfully")
}

func (h *authHandler) OAuthLogin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerStr := vars["provider"]
	provider := oauth.Provider(providerStr)

	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = h.authFrontendURL
	}

	stateUUID := uuid.New().String()
	encodedRedirectURI := base64.URLEncoding.EncodeToString([]byte(redirectURI))
	state := fmt.Sprintf("%s|%s", stateUUID, encodedRedirectURI)

	authURL, err := h.authService.GetOAuthURL(provider, state)
	if err != nil {
		h.logger.Error("Failed to get OAuth URL", zap.Error(err), zap.String("provider", providerStr))
		h.writeErrorResponse(w, http.StatusBadRequest, "Provider not supported", err.Error())
		return
	}

	response := map[string]string{
		"auth_url": authURL,
		"state":    state,
		"provider": providerStr,
	}

	h.writeSuccessResponse(w, http.StatusOK, response, "OAuth URL generated")
}

func (h *authHandler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerStr := vars["provider"]

	provider := oauth.Provider(providerStr)
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	var redirectURI string
	stateParts := strings.Split(state, "|")
	if len(stateParts) == 2 {
		decodedBytes, err := base64.URLEncoding.DecodeString(stateParts[1])
		if err == nil {
			redirectURI = string(decodedBytes)
		}
	}
	if redirectURI == "" {
		redirectURI = h.authFrontendURL
	}

	if code == "" {
		errorURL := h.authFrontendURL + "/login?error=missing_code"
		if redirectURI != "" && redirectURI != h.authFrontendURL {
			errorURL += fmt.Sprintf("&returnUrl=%s", redirectURI)
		}
		http.Redirect(w, r, errorURL, http.StatusTemporaryRedirect)
		return
	}

	if state == "" {
		errorURL := h.authFrontendURL + "/login?error=missing_state"
		if redirectURI != "" && redirectURI != h.authFrontendURL {
			errorURL += fmt.Sprintf("&returnUrl=%s", redirectURI)
		}
		http.Redirect(w, r, errorURL, http.StatusTemporaryRedirect)
		return
	}

	authResponse, err := h.authService.OAuthLogin(r.Context(), provider, code)
	if err != nil {
		h.logger.Error("OAuth login failed", zap.Error(err), zap.String("provider", providerStr))

		acceptHeader := r.Header.Get("Accept")
		wantsJSON := strings.Contains(acceptHeader, "application/json")

		errorType := "oauth_failed"
		errorMsg := err.Error()

		if strings.Contains(errorMsg, "access restricted") || strings.Contains(errorMsg, "authorized domains") {
			errorType = "domain_restricted"
		} else if strings.Contains(errorMsg, "duplicate key") || strings.Contains(errorMsg, "already exists") {
			errorType = "user_exists"
			errorMsg = "User account already exists"
		}

		if wantsJSON {
			h.writeErrorResponse(w, http.StatusUnauthorized, "OAuth authentication failed", errorMsg)
		} else {
			errorURL := fmt.Sprintf("%s/login?error=%s&error_description=%s",
				h.authFrontendURL,
				errorType,
				url.QueryEscape(errorMsg))
			if redirectURI != "" && redirectURI != h.authFrontendURL {
				errorURL += fmt.Sprintf("&returnUrl=%s", url.QueryEscape(redirectURI))
			}
			http.Redirect(w, r, errorURL, http.StatusTemporaryRedirect)
		}
		return
	}

	acceptHeader := r.Header.Get("Accept")
	wantsJSON := strings.Contains(acceptHeader, "application/json")

	if wantsJSON {
		h.logger.Info("OAuth callback successful, returning JSON response",
			zap.String("provider", providerStr),
			zap.String("user_id", authResponse.User.ID.String()))

		h.writeSuccessResponse(w, http.StatusOK, authResponse, "OAuth authentication successful")
	} else {
		callbackURL := fmt.Sprintf("%s/auth/callback/%s?success=true&access_token=%s&refresh_token=%s",
			h.authFrontendURL,
			providerStr,
			authResponse.Tokens.AccessToken,
			authResponse.Tokens.RefreshToken)

		if redirectURI != "" && redirectURI != h.authFrontendURL {
			callbackURL += fmt.Sprintf("&returnUrl=%s", redirectURI)
		}

		h.logger.Info("OAuth callback successful, redirecting to auth frontend",
			zap.String("provider", providerStr),
			zap.String("user_id", authResponse.User.ID.String()),
			zap.String("decoded_redirect_uri", redirectURI),
			zap.String("callback_url", callbackURL))

		http.Redirect(w, r, callbackURL, http.StatusFound)
	}
}

func (h *authHandler) Health(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"service":   "auth-service",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	h.writeSuccessResponse(w, http.StatusOK, response, "Service is healthy")
}

func (h *authHandler) writeSuccessResponse(w http.ResponseWriter, statusCode int, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := SuccessResponse{
		Success: true,
		Data:    data,
		Message: message,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *authHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, error, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error:   error,
		Message: message,
	}

	json.NewEncoder(w).Encode(response)
}
