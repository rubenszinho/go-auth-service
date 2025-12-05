package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	OAuth    OAuthConfig
	Security SecurityConfig
	Redis    RedisConfig
	Logging  LoggingConfig
}

type ServerConfig struct {
	Port            string
	Host            string
	Env             string
	AuthFrontendURL string
}

type DatabaseConfig struct {
	URL string
}

type JWTConfig struct {
	Secret        string
	Expiry        time.Duration
	RefreshExpiry time.Duration
}

type OAuthConfig struct {
	Google    OAuthProvider
	GitHub    OAuthProvider
	Microsoft OAuthProvider
}

type OAuthProvider struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type SecurityConfig struct {
	BcryptCost              int
	CorsAllowedOrigins      []string
	RateLimitRequests       int
	RateLimitWindow         time.Duration
	EnableEmailDomainFilter bool
	AllowedEmailDomains     []string
}

type RedisConfig struct {
	URL string
}

type LoggingConfig struct {
	Level  string
	Format string
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found, using environment variables")
	}

	config := &Config{
		Server: ServerConfig{
			Port:            getEnvRequired("PORT", "Server port"),
			Host:            getEnvRequired("HOST", "Server host"),
			Env:             getEnvRequired("ENV", "Environment (development/production)"),
			AuthFrontendURL: getEnvWithDefault("AUTH_FRONTEND_URL", "https://your-auth-frontend-url.com"),
		},
		Database: DatabaseConfig{
			URL: getEnvRequired("DATABASE_URL", "PostgreSQL connection string (postgresql://user:password@host:port/dbname?sslmode=require)"),
		},
		JWT: JWTConfig{
			Secret:        getEnvRequired("JWT_SECRET", "JWT signing secret - CRITICAL FOR SECURITY"),
			Expiry:        parseDurationRequired(getEnvRequired("JWT_EXPIRY", "JWT token expiry duration (e.g., 24h)")),
			RefreshExpiry: parseDurationRequired(getEnvRequired("JWT_REFRESH_EXPIRY", "JWT refresh token expiry (e.g., 168h)")),
		},
		OAuth: OAuthConfig{
			Google: OAuthProvider{
				ClientID:     getEnv("GOOGLE_CLIENT_ID"),
				ClientSecret: getEnv("GOOGLE_CLIENT_SECRET"),
				RedirectURL:  getEnv("GOOGLE_REDIRECT_URL"),
			},
			GitHub: OAuthProvider{
				ClientID:     getEnv("GITHUB_CLIENT_ID"),
				ClientSecret: getEnv("GITHUB_CLIENT_SECRET"),
				RedirectURL:  getEnv("GITHUB_REDIRECT_URL"),
			},
			Microsoft: OAuthProvider{
				ClientID:     getEnv("MICROSOFT_CLIENT_ID"),
				ClientSecret: getEnv("MICROSOFT_CLIENT_SECRET"),
				RedirectURL:  getEnv("MICROSOFT_REDIRECT_URL"),
			},
		},
		Security: SecurityConfig{
			BcryptCost:              parseIntRequired(getEnvRequired("BCRYPT_COST", "Bcrypt cost factor (e.g., 12)")),
			CorsAllowedOrigins:      parseStringSlice(getEnvRequired("CORS_ORIGINS", "CORS allowed origins - comma separated")),
			RateLimitRequests:       parseIntRequired(getEnvRequired("RATE_LIMIT_REQUESTS", "Rate limit requests per window (e.g., 100)")),
			RateLimitWindow:         parseDurationRequired(getEnvRequired("RATE_LIMIT_WINDOW", "Rate limit window duration (e.g., 1h)")),
			EnableEmailDomainFilter: parseBool(getEnv("ENABLE_EMAIL_DOMAIN_FILTER")),
			AllowedEmailDomains:     parseStringSlice(getEnv("ALLOWED_EMAIL_DOMAINS")),
		},
		Redis: RedisConfig{
			URL: getEnvRequired("REDIS_URL", "Redis connection string (redis://:password@host:port/0)"),
		},
		Logging: LoggingConfig{
			Level:  getEnvRequired("LOG_LEVEL", "Logging level (debug/info/warning/error)"),
			Format: getEnvRequired("LOG_FORMAT", "Log format (json/text)"),
		},
	}

	return config, config.Validate()
}

func (c *Config) Validate() error {
	weakSecrets := []string{"secret", "password", "default", "test", "dev", "change-me"}
	lowerSecret := strings.ToLower(c.JWT.Secret)
	for _, weak := range weakSecrets {
		if strings.Contains(lowerSecret, weak) {
			if c.Server.Env != "development" {
				return fmt.Errorf("SECURITY ERROR: JWT_SECRET contains weak/default value")
			}
			fmt.Println("WARNING: JWT_SECRET appears weak (OK for development only)")
		}
	}

	if len(c.JWT.Secret) < 32 {
		if c.Server.Env != "development" {
			return fmt.Errorf("SECURITY ERROR: JWT_SECRET is too short (%d chars), must be at least 32 characters", len(c.JWT.Secret))
		}
		fmt.Printf("WARNING: JWT_SECRET is short (%d chars) - OK for dev only\n", len(c.JWT.Secret))
	}

	if len(c.Security.CorsAllowedOrigins) == 0 {
		return fmt.Errorf("CORS_ORIGINS cannot be empty")
	}
	if len(c.Security.CorsAllowedOrigins) == 1 && c.Security.CorsAllowedOrigins[0] == "*" {
		if c.Server.Env != "development" {
			return fmt.Errorf("CORS_ORIGINS cannot be '*' in production")
		}
		fmt.Println("WARNING: CORS allows all origins (OK for development only)")
	}

	if c.Security.BcryptCost < 10 || c.Security.BcryptCost > 15 {
		return fmt.Errorf("BCRYPT_COST must be between 10 and 15, got: %d", c.Security.BcryptCost)
	}

	if c.Security.RateLimitRequests <= 0 {
		return fmt.Errorf("RATE_LIMIT_REQUESTS must be > 0, got: %d", c.Security.RateLimitRequests)
	}

	fmt.Println("Configuration validation passed")
	return nil
}

func (c *Config) GetDSN() string {
	return c.Database.URL
}

func getEnv(key string) string {
	return os.Getenv(key)
}

func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvRequired(key, description string) string {
	value := os.Getenv(key)
	if value == "" {
		desc := ""
		if description != "" {
			desc = fmt.Sprintf(" (%s)", description)
		}
		panic(fmt.Sprintf(
			"CRITICAL: Required environment variable '%s' is not set%s.\n"+
				"   Please set it in your .env file or environment variables.\n"+
				"   See env.example for reference.",
			key, desc,
		))
	}
	return value
}

func parseIntRequired(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("Invalid integer value: %s (error: %v)", s, err))
	}
	return i
}

func parseDurationRequired(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(fmt.Sprintf("Invalid duration value: %s (error: %v)", s, err))
	}
	return d
}

func parseStringSlice(s string) []string {
	if s == "" {
		return []string{}
	}

	var result []string
	for i := 0; i < len(s); {
		start := i
		for i < len(s) && s[i] != ',' {
			i++
		}
		if start < i {
			result = append(result, s[start:i])
		}
		if i < len(s) {
			i++ // skip comma
		}
	}
	return result
}

func parseBool(s string) bool {
	if s == "" {
		return false
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false
	}
	return b
}
