package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rubenszinho/go-auth-service/internal/config"

	"github.com/go-redis/redis/v8"
)

type redisClient struct {
	client *redis.Client
	ctx    context.Context
}

func RedisClient(cfg *config.Config) (*redisClient, error) {
	opts, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)
	ctx := context.Background()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &redisClient{
		client: client,
		ctx:    ctx,
	}, nil
}

func (r *redisClient) Set(key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return r.client.Set(r.ctx, key, data, expiration).Err()
}

func (r *redisClient) Get(key string, dest interface{}) error {
	data, err := r.client.Get(r.ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("key not found")
		}
		return fmt.Errorf("failed to get value: %w", err)
	}

	if err := json.Unmarshal([]byte(data), dest); err != nil {
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	return nil
}

func (r *redisClient) Delete(key string) error {
	return r.client.Del(r.ctx, key).Err()
}

func (r *redisClient) Exists(key string) (bool, error) {
	count, err := r.client.Exists(r.ctx, key).Result()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *redisClient) SetNX(key string, value interface{}, expiration time.Duration) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("failed to marshal value: %w", err)
	}

	return r.client.SetNX(r.ctx, key, data, expiration).Result()
}

func (r *redisClient) Increment(key string) (int64, error) {
	return r.client.Incr(r.ctx, key).Result()
}

func (r *redisClient) IncrementWithExpiry(key string, expiry time.Duration) (int64, error) {
	pipe := r.client.TxPipeline()
	incr := pipe.Incr(r.ctx, key)
	pipe.Expire(r.ctx, key, expiry)

	_, err := pipe.Exec(r.ctx)
	if err != nil {
		return 0, err
	}

	return incr.Val(), nil
}

func (r *redisClient) GetTTL(key string) (time.Duration, error) {
	return r.client.TTL(r.ctx, key).Result()
}

func (r *redisClient) Close() error {
	return r.client.Close()
}

func (r *redisClient) Health() error {
	return r.client.Ping(r.ctx).Err()
}

func CacheKey(prefix, key string) string {
	return fmt.Sprintf("auth:%s:%s", prefix, key)
}

func UserCacheKey(userID string) string {
	return CacheKey("user", userID)
}

func SessionCacheKey(sessionID string) string {
	return CacheKey("session", sessionID)
}

func RateLimitKey(identifier string) string {
	return CacheKey("ratelimit", identifier)
}
