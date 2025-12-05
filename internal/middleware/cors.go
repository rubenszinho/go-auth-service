package middleware

import (
	"net/http"
	"strings"
)

type corsMiddleware struct {
	allowedOrigins []string
}

type CORS = corsMiddleware

func CORSMiddleware(allowedOrigins []string) *CORS {
	return &corsMiddleware{
		allowedOrigins: allowedOrigins,
	}
}

func (m *corsMiddleware) EnableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if m.isOriginAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *corsMiddleware) isOriginAllowed(origin string) bool {
	if len(m.allowedOrigins) == 0 {
		return false
	}

	for _, allowedOrigin := range m.allowedOrigins {
		if allowedOrigin == "*" || allowedOrigin == origin {
			return true
		}
		if strings.HasPrefix(allowedOrigin, "*.") {
			domain := allowedOrigin[2:] // Remove "*."
			if strings.HasSuffix(origin, "."+domain) {
				return true
			}
		}
	}

	return false
}
