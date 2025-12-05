package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key"`
	Username    string    `json:"username" gorm:"uniqueIndex;not null;size:255" validate:"required,min=3,max=50"`
	Password    string    `json:"-" gorm:"size:255"`
	DisplayName string    `json:"display_name" gorm:"not null;size:255" validate:"required,min=1,max=100"`
	Email       string    `json:"email" gorm:"uniqueIndex;not null;size:255" validate:"required,email"`
	AvatarURL   string    `json:"avatar_url" gorm:"size:500"`

	PlanType            string `json:"plan_type" gorm:"size:50"`
	MaxTokensPerLLMCall int    `json:"max_tokens_per_llm_call"`
	GoogleID            string `json:"google_id" gorm:"uniqueIndex;size:255"`

	InstanceID               *uuid.UUID `json:"-" gorm:"type:uuid"`
	Aud                      string     `json:"-" gorm:"size:255"`
	Role                     string     `json:"role" gorm:"size:255"`
	EncryptedPassword        string     `json:"-" gorm:"size:255"`
	EmailConfirmedAt         *time.Time `json:"email_confirmed_at"`
	InvitedAt                *time.Time `json:"invited_at"`
	ConfirmationToken        string     `json:"-" gorm:"size:255"`
	ConfirmationSentAt       *time.Time `json:"-"`
	RecoveryToken            string     `json:"-" gorm:"size:255"`
	RecoverySentAt           *time.Time `json:"-"`
	EmailChangeTokenNew      string     `json:"-" gorm:"size:255"`
	EmailChange              string     `json:"-" gorm:"size:255"`
	EmailChangeSentAt        *time.Time `json:"-"`
	LastSignInAt             *time.Time `json:"last_sign_in_at"`
	RawAppMetaData           string     `json:"-" gorm:"type:jsonb"`
	RawUserMetaData          string     `json:"-" gorm:"type:jsonb"`
	IsSuperAdmin             bool       `json:"is_super_admin"`
	Phone                    string     `json:"-"`
	PhoneConfirmedAt         *time.Time `json:"-"`
	PhoneChange              string     `json:"-"`
	PhoneChangeToken         string     `json:"-" gorm:"size:255"`
	PhoneChangeSentAt        *time.Time `json:"-"`
	ConfirmedAt              *time.Time `json:"confirmed_at"`
	EmailChangeTokenCurrent  string     `json:"-" gorm:"size:255"`
	EmailChangeConfirmStatus int16      `json:"-"`
	BannedUntil              *time.Time `json:"-"`
	ReauthenticationToken    string     `json:"-" gorm:"size:255"`
	ReauthenticationSentAt   *time.Time `json:"-"`
	IsSSOUser                bool       `json:"is_sso_user" gorm:"default:false"`
	DeletedAt                *time.Time `json:"-"`
	IsAnonymous              bool       `json:"is_anonymous" gorm:"default:false"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at"`

	OAuthProviders []OAuthAccount `json:"oauth_providers,omitempty" gorm:"foreignKey:UserID"`
}

type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
	RoleSuper UserRole = "super"
)

type OAuthAccount struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID       uuid.UUID  `json:"user_id" gorm:"type:uuid;not null"`
	Provider     string     `json:"provider" gorm:"not null"`
	ProviderID   string     `json:"provider_id" gorm:"not null"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	Avatar       string     `json:"avatar"`
	AccessToken  string     `json:"-"`
	RefreshToken string     `json:"-"`
	ExpiresAt    *time.Time `json:"expires_at"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

type AuthSession struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
	Data      string    `json:"-" gorm:"type:text;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	User      User      `json:"-" gorm:"foreignKey:UserID"`
}

type RefreshToken struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
	Token     string    `json:"-" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	IsRevoked bool      `json:"is_revoked" gorm:"default:false"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

type PasswordReset struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
	Token     string    `json:"-" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	IsUsed    bool      `json:"is_used" gorm:"default:false"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type EmailVerification struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
	Token     string    `json:"-" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	IsUsed    bool      `json:"is_used" gorm:"default:false"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.PlanType == "" {
		u.PlanType = "free"
	}
	if u.MaxTokensPerLLMCall == 0 {
		u.MaxTokensPerLLMCall = 10000
	}
	if u.Role == "" {
		u.Role = string(RoleUser)
	}
	if u.RawAppMetaData == "" {
		u.RawAppMetaData = "{}"
	}
	if u.RawUserMetaData == "" {
		u.RawUserMetaData = "{}"
	}
	return nil
}

func (o *OAuthAccount) BeforeCreate(tx *gorm.DB) error {
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}
	return nil
}

func (r *RefreshToken) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

func (p *PasswordReset) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

func (e *EmailVerification) BeforeCreate(tx *gorm.DB) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	return nil
}

func (User) TableName() string              { return "users" }
func (AuthSession) TableName() string       { return "auth_sessions" }
func (OAuthAccount) TableName() string      { return "auth_oauth_accounts" }
func (RefreshToken) TableName() string      { return "auth_refresh_tokens" }
func (PasswordReset) TableName() string     { return "auth_password_resets" }
func (EmailVerification) TableName() string { return "auth_email_verifications" }
