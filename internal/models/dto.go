package models

import (
	"time"

	"github.com/google/uuid"
)

type UserBasicInfo struct {
	ID          uuid.UUID `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	AvatarURL   string    `json:"avatar_url"`
	PlanType    string    `json:"plan_type"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
}

type UserExistsResponse struct {
	Exists bool      `json:"exists"`
	UserID uuid.UUID `json:"user_id,omitempty"`
}

type ValidateUsersRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" validate:"required,min=1,max=100"`
}

type ValidateUsersResponse struct {
	ValidUsers   []uuid.UUID `json:"valid_users"`
	InvalidUsers []uuid.UUID `json:"invalid_users"`
	TotalValid   int         `json:"total_valid"`
	TotalInvalid int         `json:"total_invalid"`
}

type UserBatchInfoRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" validate:"required,min=1,max=50"`
}

type UserBatchInfoResponse struct {
	Users    map[uuid.UUID]UserBasicInfo `json:"users"`
	NotFound []uuid.UUID                 `json:"not_found,omitempty"`
}
