package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rubenszinho/go-auth-service/internal/config"
	"github.com/rubenszinho/go-auth-service/internal/database"
	"github.com/rubenszinho/go-auth-service/internal/handlers"
	"github.com/rubenszinho/go-auth-service/internal/middleware"
	"github.com/rubenszinho/go-auth-service/internal/services"
	"github.com/rubenszinho/go-auth-service/pkg/jwt"
	"github.com/rubenszinho/go-auth-service/pkg/oauth"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	logger, err := initLogger(cfg.Logging.Level, cfg.Logging.Format)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	logger.Info("Starting auth service",
		zap.String("env", cfg.Server.Env),
		zap.String("port", cfg.Server.Port))

	db, err := database.New(cfg)
	if err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer db.Close()

	logger.Info("Running database migrations...")
	if err := db.Migrate(); err != nil {
		logger.Fatal("Failed to run database migrations", zap.Error(err))
	}
	logger.Info("Database migrations completed successfully")

	jwtManager := jwt.JWTManager(
		cfg.JWT.Secret,
		cfg.JWT.Expiry,
		cfg.JWT.RefreshExpiry,
	)

	oauthManager := oauth.OAuthManager(cfg)

	authService := services.AuthService(
		db.DB,
		jwtManager,
		oauthManager,
		cfg.Security.BcryptCost,
		cfg.Security.EnableEmailDomainFilter,
		cfg.Security.AllowedEmailDomains,
	)

	if cfg.Security.EnableEmailDomainFilter {
		logger.Info("Email domain filter ENABLED - only allowing specific domains",
			zap.Strings("allowed_domains", cfg.Security.AllowedEmailDomains))
	} else {
		logger.Info("Email domain filter DISABLED - accepting all email domains")
	}

	userQueryService := services.UserQueryService(db.DB)

	authHandler := handlers.AuthHandler(authService, logger, cfg.Server.AuthFrontendURL)
	queryHandler := handlers.QueryHandler(userQueryService, logger)

	authMiddleware := middleware.AuthMiddleware(jwtManager)

	logger.Info("CORS Configuration",
		zap.Strings("allowed_origins", cfg.Security.CorsAllowedOrigins),
		zap.Int("origins_count", len(cfg.Security.CorsAllowedOrigins)))

	corsMiddleware := middleware.CORSMiddleware(cfg.Security.CorsAllowedOrigins)
	loggingMiddleware := middleware.LoggingMiddleware(logger)

	router := setupRoutes(authHandler, queryHandler, authMiddleware, corsMiddleware, loggingMiddleware)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("Server starting", zap.String("address", server.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed to start", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Server shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Server exited")
}

func setupRoutes(
	authHandler *handlers.Handler,
	queryHandler *handlers.Query,
	authMiddleware *middleware.Auth,
	corsMiddleware *middleware.CORS,
	loggingMiddleware *middleware.Logging,
) *mux.Router {
	router := mux.NewRouter()
	router.Use(corsMiddleware.EnableCORS)
	router.Use(loggingMiddleware.LogRequests)

	api := router.PathPrefix("/api/v1").Subrouter()

	public := api.PathPrefix("/auth").Subrouter()
	public.HandleFunc("/register", authHandler.Register).Methods("POST", "OPTIONS")
	public.HandleFunc("/login", authHandler.Login).Methods("POST", "OPTIONS")
	public.HandleFunc("/refresh", authHandler.RefreshToken).Methods("POST", "OPTIONS")
	public.HandleFunc("/oauth/{provider}/login", authHandler.OAuthLogin).Methods("GET", "OPTIONS")
	public.HandleFunc("/oauth/{provider}/callback", authHandler.OAuthCallback).Methods("GET", "OPTIONS")

	protected := api.PathPrefix("/auth").Subrouter()
	protected.Use(authMiddleware.RequireAuth)
	protected.HandleFunc("/logout", authHandler.Logout).Methods("POST", "OPTIONS")
	protected.HandleFunc("/profile", authHandler.GetProfile).Methods("GET", "OPTIONS")

	query := api.PathPrefix("/query").Subrouter()
	query.HandleFunc("/users/{id}", queryHandler.GetUserBasicInfo).Methods("GET", "OPTIONS")
	query.HandleFunc("/users/{id}/exists", queryHandler.CheckUserExists).Methods("GET", "OPTIONS")
	query.HandleFunc("/users/validate", queryHandler.ValidateMultipleUsers).Methods("POST", "OPTIONS")
	query.HandleFunc("/users/batch-info", queryHandler.GetUsersBatchInfo).Methods("POST", "OPTIONS")
	query.HandleFunc("/users/by-email", queryHandler.GetUserByEmail).Methods("GET", "OPTIONS")
	query.HandleFunc("/users/stats", queryHandler.GetUserStats).Methods("GET", "OPTIONS")

	router.HandleFunc("/health", authHandler.Health).Methods("GET", "OPTIONS")

	return router
}

func initLogger(level, format string) (*zap.Logger, error) {
	var zapCfg zap.Config

	if format == "json" {
		zapCfg = zap.NewProductionConfig()
	} else {
		zapCfg = zap.NewDevelopmentConfig()
	}

	switch level {
	case "debug":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	return zapCfg.Build()
}
