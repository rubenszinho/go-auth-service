package middleware

import (
	"context"
	"net/http"

	"github.com/rubenszinho/go-auth-service/pkg/jwt"
)

type authMiddleware struct {
	jwtManager *jwt.Manager
}

type Auth = authMiddleware

func AuthMiddleware(jwtManager *jwt.Manager) *Auth {
	return &authMiddleware{
		jwtManager: jwtManager,
	}
}

func (m *authMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.writeJSONError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		token := jwt.ExtractTokenFromHeader(authHeader)
		if token == "" {
			m.writeJSONError(w, http.StatusUnauthorized, "Invalid authorization header format")
			return
		}

		claims, err := m.jwtManager.ValidateAccessToken(token)
		if err != nil {
			m.writeJSONError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		ctx := context.WithValue(r.Context(), "user_claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *authMiddleware) writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write([]byte(`{"error":"` + message + `","message":"` + message + `"}`))
}

func (m *authMiddleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value("user_claims").(*jwt.Claims)
			if !ok {
				m.writeJSONError(w, http.StatusUnauthorized, "No user claims found")
				return
			}

			if claims.Role != role {
				m.writeJSONError(w, http.StatusForbidden, "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *authMiddleware) RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value("user_claims").(*jwt.Claims)
			if !ok {
				m.writeJSONError(w, http.StatusUnauthorized, "No user claims found")
				return
			}

			hasRole := false
			for _, role := range roles {
				if claims.Role == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				m.writeJSONError(w, http.StatusForbidden, "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// OptionalAuth middleware that extracts user info if token is present but doesn't require it
func (m *authMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			token := jwt.ExtractTokenFromHeader(authHeader)
			if token != "" {
				if claims, err := m.jwtManager.ValidateAccessToken(token); err == nil {
					ctx := context.WithValue(r.Context(), "user_claims", claims)
					r = r.WithContext(ctx)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
