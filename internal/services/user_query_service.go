package services

import (
	"context"
	"fmt"

	"github.com/rubenszinho/go-auth-service/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserQueryService provides user data queries for external services
type userQueryService struct {
	db *gorm.DB
}

type QueryService = userQueryService

func UserQueryService(db *gorm.DB) *QueryService {
	return &userQueryService{
		db: db,
	}
}

// GetUserBasicInfo returns basic user information needed by external services
func (s *userQueryService) GetUserBasicInfo(ctx context.Context, userID uuid.UUID) (*models.UserBasicInfo, error) {
	var user models.User

	if err := s.db.First(&user, userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	isActive := true
	if user.BannedUntil != nil && user.BannedUntil.After(user.CreatedAt) {
		isActive = false
	}
	if user.DeletedAt != nil {
		isActive = false
	}

	return &models.UserBasicInfo{
		ID:          user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		Email:       user.Email,
		AvatarURL:   user.AvatarURL,
		PlanType:    user.PlanType,
		IsActive:    isActive,
		CreatedAt:   user.CreatedAt,
	}, nil
}

// CheckUserExists validates if a user exists and is active
func (s *userQueryService) CheckUserExists(ctx context.Context, userID uuid.UUID) (*models.UserExistsResponse, error) {
	var count int64

	err := s.db.Model(&models.User{}).
		Where("id = ? AND deleted_at IS NULL", userID).
		Count(&count).Error

	if err != nil {
		return nil, fmt.Errorf("failed to check user existence: %w", err)
	}

	return &models.UserExistsResponse{
		Exists: count > 0,
		UserID: userID,
	}, nil
}

// ValidateMultipleUsers validates multiple user IDs at once
func (s *userQueryService) ValidateMultipleUsers(ctx context.Context, req *models.ValidateUsersRequest) (*models.ValidateUsersResponse, error) {
	if len(req.UserIDs) == 0 {
		return &models.ValidateUsersResponse{
			ValidUsers:   []uuid.UUID{},
			InvalidUsers: []uuid.UUID{},
			TotalValid:   0,
			TotalInvalid: 0,
		}, nil
	}

	var validUserIDs []uuid.UUID
	err := s.db.Model(&models.User{}).
		Select("id").
		Where("id IN ? AND deleted_at IS NULL", req.UserIDs).
		Pluck("id", &validUserIDs).Error

	if err != nil {
		return nil, fmt.Errorf("failed to validate users: %w", err)
	}

	validMap := make(map[uuid.UUID]bool)
	for _, id := range validUserIDs {
		validMap[id] = true
	}

	var invalidUserIDs []uuid.UUID
	for _, id := range req.UserIDs {
		if !validMap[id] {
			invalidUserIDs = append(invalidUserIDs, id)
		}
	}

	return &models.ValidateUsersResponse{
		ValidUsers:   validUserIDs,
		InvalidUsers: invalidUserIDs,
		TotalValid:   len(validUserIDs),
		TotalInvalid: len(invalidUserIDs),
	}, nil
}

// GetUsersBatchInfo returns basic info for multiple users
func (s *userQueryService) GetUsersBatchInfo(ctx context.Context, req *models.UserBatchInfoRequest) (*models.UserBatchInfoResponse, error) {
	if len(req.UserIDs) == 0 {
		return &models.UserBatchInfoResponse{
			Users:    make(map[uuid.UUID]models.UserBasicInfo),
			NotFound: []uuid.UUID{},
		}, nil
	}

	var users []models.User
	err := s.db.Where("id IN ? AND deleted_at IS NULL", req.UserIDs).Find(&users).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get users batch info: %w", err)
	}

	userMap := make(map[uuid.UUID]models.UserBasicInfo)
	foundIDs := make(map[uuid.UUID]bool)

	for _, user := range users {
		isActive := true
		if user.BannedUntil != nil && user.BannedUntil.After(user.CreatedAt) {
			isActive = false
		}

		userMap[user.ID] = models.UserBasicInfo{
			ID:          user.ID,
			Username:    user.Username,
			DisplayName: user.DisplayName,
			Email:       user.Email,
			AvatarURL:   user.AvatarURL,
			PlanType:    user.PlanType,
			IsActive:    isActive,
			CreatedAt:   user.CreatedAt,
		}
		foundIDs[user.ID] = true
	}

	var notFound []uuid.UUID
	for _, id := range req.UserIDs {
		if !foundIDs[id] {
			notFound = append(notFound, id)
		}
	}

	return &models.UserBatchInfoResponse{
		Users:    userMap,
		NotFound: notFound,
	}, nil
}

// GetUserByEmail returns user basic info by email (for migration/sync purposes)
func (s *userQueryService) GetUserByEmail(ctx context.Context, email string) (*models.UserBasicInfo, error) {
	var user models.User

	err := s.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	isActive := true
	if user.BannedUntil != nil && user.BannedUntil.After(user.CreatedAt) {
		isActive = false
	}

	return &models.UserBasicInfo{
		ID:          user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		Email:       user.Email,
		AvatarURL:   user.AvatarURL,
		PlanType:    user.PlanType,
		IsActive:    isActive,
		CreatedAt:   user.CreatedAt,
	}, nil
}

// GetUserStats returns statistics about users (for monitoring)
func (s *userQueryService) GetUserStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	var totalUsers int64
	if err := s.db.Model(&models.User{}).Count(&totalUsers).Error; err != nil {
		return nil, fmt.Errorf("failed to count total users: %w", err)
	}
	stats["total_users"] = totalUsers

	var activeUsers int64
	if err := s.db.Model(&models.User{}).Where("deleted_at IS NULL").Count(&activeUsers).Error; err != nil {
		return nil, fmt.Errorf("failed to count active users: %w", err)
	}
	stats["active_users"] = activeUsers

	var planStats []struct {
		PlanType string `json:"plan_type"`
		Count    int64  `json:"count"`
	}

	err := s.db.Model(&models.User{}).
		Select("plan_type, COUNT(*) as count").
		Where("deleted_at IS NULL").
		Group("plan_type").
		Scan(&planStats).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get plan statistics: %w", err)
	}

	stats["users_by_plan"] = planStats

	var oauthUsers int64
	if err := s.db.Model(&models.User{}).Where("google_id IS NOT NULL AND google_id != ''").Count(&oauthUsers).Error; err != nil {
		return nil, fmt.Errorf("failed to count OAuth users: %w", err)
	}
	stats["oauth_users"] = oauthUsers

	return stats, nil
}
