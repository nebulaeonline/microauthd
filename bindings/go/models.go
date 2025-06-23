// Package microauthd contains shared model types used by both the auth and admin clients.
package microauthd

import "time"

// TokenResponse represents a response from the /token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	JTI          string `json:"jti,omitempty"`
	Audience     string `json:"audience,omitempty"`
}

// UserObject represents a user record.
type UserObject struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email,omitempty"`
	IsActive  bool   `json:"is_active"`
	CreatedAt string `json:"created_at,omitempty"`
}

// RoleObject represents a role.
type RoleObject struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IsActive    bool   `json:"is_active"`
}

// ScopeObject represents a scope.
type ScopeObject struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"desc,omitempty"`
	IsActive    bool   `json:"is_active"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// PermissionObject represents a permission.
type PermissionObject struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	IsActive bool   `json:"is_active"`
}

// ClientObject represents an OIDC client.
type ClientObject struct {
	ID          string `json:"id"`
	ClientID    string `json:"client_id"`
	DisplayName string `json:"display_name,omitempty"`
	Audience    string `json:"audience,omitempty"`
	IsActive    bool   `json:"is_active"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// SessionResponse represents a token session.
type SessionResponse struct {
	ID               string `json:"id"`
	UserID           string `json:"user_id"`
	ClientIdentifier string `json:"client_identifier"`
	CreatedAt        string `json:"created_at"`
	ExpiresAt        string `json:"expires_at"`
	TokenUse         string `json:"token_use"`
	IsRevoked        bool   `json:"is_revoked"`
}

// RefreshTokenResponse represents a refresh token.
type RefreshTokenResponse struct {
	ID               string `json:"id"`
	UserID           string `json:"user_id"`
	SessionID        string `json:"session_id"`
	ClientIdentifier string `json:"client_identifier"`
	ExpiresAt        string `json:"expires_at"`
	IsRevoked        bool   `json:"is_revoked"`
}

// MessageResponse is a generic success/failure message.
type MessageResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// TotpQrRequest is used to request a QR code.
type TotpQrRequest struct {
	UserID       string `json:"user_id"`
	QROutputPath string `json:"qr_output_path"`
}

// TotpQrResponse is the result of a TOTP QR generation.
type TotpQrResponse struct {
	QRCodeFilename string `json:"qr_code_filename"`
}

// VerifyTotpRequest is used to verify a TOTP code.
type VerifyTotpRequest struct {
	UserID string `json:"user_id"`
	Code   string `json:"code"`
}

// AuditLogResponse represents a single audit log entry.
type AuditLogResponse struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id,omitempty"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// MeResponse is returned from /me endpoint.
type MeResponse struct {
	Sub    string   `json:"sub"`
	Email  string   `json:"email,omitempty"`
	Roles  []string `json:"roles"`
	Scopes []string `json:"scopes"`
}

// PurgeTokensRequest is used to bulk delete expired & revoked tokens.
type PurgeTokensRequest struct {
	OlderThanSeconds int  `json:"older_than_seconds"`
	PurgeExpired     bool `json:"purge_expired"`
	PurgeRevoked     bool `json:"purge_revoked"`
}

// PurgeAuditLogRequest is used to prune audit logs.
type PurgeAuditLogRequest struct {
	OlderThanDays int `json:"older_than_days"`
}

// Role DTOs for bulk API operations on Roles
type RoleDto struct {
	ID string `json:"id"`
}

type RoleAssignmentDto struct {
	UserID string    `json:"userId"`
	Roles  []RoleDto `json:"roles"`
}

// Scope DTOs for bulk API operations on Scopes
type ScopeAssignmentRequest struct {
	ScopeIds []string `json:"scopeIds"`
}

type ScopeAssignmentDto struct {
	ClientID string   `json:"clientId"`
	ScopeIds []string `json:"scopeIds"`
}
