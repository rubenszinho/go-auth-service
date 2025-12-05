package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rubenszinho/go-auth-service/internal/models"
	"github.com/rubenszinho/go-auth-service/internal/services"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type queryHandler struct {
	userQueryService *services.QueryService
	validator        *validator.Validate
	logger           *zap.Logger
}

type Query = queryHandler

func QueryHandler(userQueryService *services.QueryService, logger *zap.Logger) *Query {
	return &queryHandler{
		userQueryService: userQueryService,
		validator:        validator.New(),
		logger:           logger,
	}
}

func (h *queryHandler) GetUserBasicInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid user ID format", err.Error())
		return
	}

	userInfo, err := h.userQueryService.GetUserBasicInfo(r.Context(), userID)
	if err != nil {
		if err.Error() == "user not found" {
			h.writeErrorResponse(w, http.StatusNotFound, "User not found", "")
			return
		}
		h.logger.Error("Failed to get user basic info", zap.Error(err), zap.String("user_id", userIDStr))
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get user info", err.Error())
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, userInfo, "User info retrieved successfully")
}

func (h *queryHandler) CheckUserExists(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid user ID format", err.Error())
		return
	}

	exists, err := h.userQueryService.CheckUserExists(r.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to check user existence", zap.Error(err), zap.String("user_id", userIDStr))
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to check user existence", err.Error())
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, exists, "User existence checked")
}

func (h *queryHandler) ValidateMultipleUsers(w http.ResponseWriter, r *http.Request) {
	var req models.ValidateUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	result, err := h.userQueryService.ValidateMultipleUsers(r.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to validate multiple users", zap.Error(err))
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to validate users", err.Error())
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, result, "Users validated successfully")
}

func (h *queryHandler) GetUsersBatchInfo(w http.ResponseWriter, r *http.Request) {
	var req models.UserBatchInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	result, err := h.userQueryService.GetUsersBatchInfo(r.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to get users batch info", zap.Error(err))
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get users info", err.Error())
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, result, "Users info retrieved successfully")
}

func (h *queryHandler) GetUserByEmail(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Email parameter is required", "")
		return
	}

	userInfo, err := h.userQueryService.GetUserByEmail(r.Context(), email)
	if err != nil {
		if err.Error() == "user not found" {
			h.writeErrorResponse(w, http.StatusNotFound, "User not found", "")
			return
		}
		h.logger.Error("Failed to get user by email", zap.Error(err), zap.String("email", email))
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get user info", err.Error())
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, userInfo, "User info retrieved successfully")
}

func (h *queryHandler) GetUserStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.userQueryService.GetUserStats(r.Context())
	if err != nil {
		h.logger.Error("Failed to get user stats", zap.Error(err))
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get user stats", err.Error())
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, stats, "User stats retrieved successfully")
}

func (h *queryHandler) writeSuccessResponse(w http.ResponseWriter, statusCode int, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := SuccessResponse{
		Success: true,
		Data:    data,
		Message: message,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *queryHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, error, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error:   error,
		Message: message,
	}

	json.NewEncoder(w).Encode(response)
}
