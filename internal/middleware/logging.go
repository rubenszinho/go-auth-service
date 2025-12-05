package middleware

import (
	"net/http"
	"time"

	"github.com/rubenszinho/go-auth-service/pkg/jwt"

	"go.uber.org/zap"
)

type loggingMiddleware struct {
	logger *zap.Logger
}

type Logging = loggingMiddleware

func LoggingMiddleware(logger *zap.Logger) *Logging {
	return &loggingMiddleware{
		logger: logger,
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

func (m *loggingMiddleware) LogRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		fields := []zap.Field{
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("query", r.URL.RawQuery),
			zap.Int("status", wrapped.statusCode),
			zap.Int("size", wrapped.size),
			zap.Duration("duration", duration),
			zap.String("user_agent", r.UserAgent()),
			zap.String("remote_addr", r.RemoteAddr),
		}

		if claims, ok := r.Context().Value("user_claims").(*jwt.Claims); ok {
			fields = append(fields, zap.String("user_id", claims.UserID.String()))
		}

		if wrapped.statusCode >= 500 {
			m.logger.Error("HTTP request", fields...)
		} else if wrapped.statusCode >= 400 {
			m.logger.Warn("HTTP request", fields...)
		} else {
			m.logger.Info("HTTP request", fields...)
		}
	})
}

type Claims struct {
	UserID interface{} `json:"user_id"`
}
