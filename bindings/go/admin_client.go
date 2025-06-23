// Package microauthd provides Go bindings for interacting with the microauthd admin API.
package microauthd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AdminClient allows interaction with the microauthd admin API.
type AdminClient struct {
	BaseURL string
	Token   string
	client  *http.Client
}

// NewAdminClient creates a new AdminClient using a pre-obtained admin token.
func NewAdminClient(baseURL, token string) *AdminClient {
	return &AdminClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *AdminClient) authHeader(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
}

func (a *AdminClient) doJSON(method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}

	req, err := http.NewRequest(method, a.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, string(b))
	}

	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}

// SYSTEM DIAGNOSTICS

func (c *AdminClient) Ping() error {
	return c.doJSON("GET", "/ping", nil, nil)
}

func (c *AdminClient) GetVersion() (map[string]any, error) {
	var out map[string]any
	err := c.doJSON("GET", "/version", nil, &out)
	return out, err
}

// Users
func (c *AdminClient) CreateUser(username, password, email string) (*UserObject, error) {
	payload := map[string]string{
		"username":      username,
		"user_password": password,
		"user_email":    email,
	}
	buf, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", c.BaseURL+"/users", bytes.NewBuffer(buf))
	req.Header.Set("Content-Type", "application/json")
	c.authHeader(req)
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("CreateUser failed: %s\n%s", res.Status, string(b))
	}
	var u UserObject
	err = json.NewDecoder(res.Body).Decode(&u)
	return &u, err
}

func (c *AdminClient) GetUser(id string) (*UserObject, error) {
	req, _ := http.NewRequest("GET", c.BaseURL+"/users/"+id, nil)
	c.authHeader(req)
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("GetUser failed: %s\n%s", res.Status, string(b))
	}
	var u UserObject
	err = json.NewDecoder(res.Body).Decode(&u)
	return &u, err
}

func (c *AdminClient) GetUserIdByUsername(username string) (string, error) {
	var out struct {
		Result string `json:"result"`
	}
	err := c.doJSON("GET", "/users/id-by-name/"+url.PathEscape(username), nil, &out)
	if err != nil {
		return "", err
	}
	return out.Result, nil
}

func (c *AdminClient) UpdateUser(id string, email string, isActive bool) (*UserObject, error) {
	payload := map[string]any{
		"email":     email,
		"is_active": isActive,
	}
	buf, _ := json.Marshal(payload)
	req, _ := http.NewRequest("PUT", c.BaseURL+"/users/"+id, bytes.NewBuffer(buf))
	c.authHeader(req)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("UpdateUser failed: %s\n%s", res.Status, string(b))
	}
	var u UserObject
	err = json.NewDecoder(res.Body).Decode(&u)
	return &u, err
}

func (c *AdminClient) DeleteUser(id string) error {
	req, _ := http.NewRequest("DELETE", c.BaseURL+"/users/"+id, nil)
	c.authHeader(req)
	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("DeleteUser failed: %s\n%s", res.Status, string(b))
	}
	return nil
}

func (c *AdminClient) DeactivateUser(id string) error {
	return c.doJSON("POST", "/users/deactivate/"+id, nil, nil)
}

func (c *AdminClient) ActivateUser(id string) error {
	return c.doJSON("POST", "/users/"+id+"/activate", nil, nil)
}

func (c *AdminClient) ResetUserPassword(id, newPassword string) error {
	return c.doJSON("POST", "/users/"+id+"/reset", map[string]string{"password": newPassword}, nil)
}

func (c *AdminClient) ListUsers() ([]UserObject, error) {
	req, _ := http.NewRequest("GET", c.BaseURL+"/users", nil)
	c.authHeader(req)
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("ListUsers failed: %s\n%s", res.Status, string(b))
	}
	var list []UserObject
	err = json.NewDecoder(res.Body).Decode(&list)
	return list, err
}

// SESSION METHODS

func (c *AdminClient) ListSessions() ([]SessionResponse, error) {
	var out []SessionResponse
	err := c.doJSON("GET", "/sessions", nil, &out)
	return out, err
}

func (c *AdminClient) GetSession(jti string) (*SessionResponse, error) {
	var out SessionResponse
	err := c.doJSON("GET", "/sessions/"+jti, nil, &out)
	return &out, err
}

func (c *AdminClient) DeleteSession(jti string) error {
	return c.doJSON("DELETE", "/sessions/"+jti, nil, nil)
}

func (c *AdminClient) ListSessionsForUser(userID string) ([]SessionResponse, error) {
	var out []SessionResponse
	err := c.doJSON("GET", "/sessions/user/"+userID, nil, &out)
	return out, err
}

func (c *AdminClient) PurgeSessions(req PurgeTokensRequest) error {
	return c.doJSON("POST", "/sessions/purge", req, nil)
}

// REVOCATION METHODS

func (c *AdminClient) RevokeByJti(jti string) error {
	return c.doJSON("DELETE", "/sessions/"+jti, nil, nil)
}

func (c *AdminClient) RevokeByToken(token string) error {
	body := map[string]string{"token": token}
	return c.doJSON("POST", "/revoke", body, nil)
}

// REFRESH TOKEN METHODS

func (c *AdminClient) ListRefreshTokens() ([]RefreshTokenResponse, error) {
	var out []RefreshTokenResponse
	err := c.doJSON("GET", "/refresh-tokens", nil, &out)
	return out, err
}

func (c *AdminClient) GetRefreshToken(id string) (*RefreshTokenResponse, error) {
	var out RefreshTokenResponse
	err := c.doJSON("GET", "/refresh-tokens/"+id, nil, &out)
	return &out, err
}

func (c *AdminClient) ListRefreshTokensForUser(userID string) ([]RefreshTokenResponse, error) {
	var out []RefreshTokenResponse
	err := c.doJSON("GET", "/refresh-tokens/user/"+userID, nil, &out)
	return out, err
}

func (c *AdminClient) PurgeRefreshTokens(req PurgeTokensRequest) error {
	return c.doJSON("POST", "/refresh-tokens/purge", req, nil)
}

// ROLE METHODS

func (c *AdminClient) CreateRole(name, description string) (*RoleObject, error) {
	body := map[string]string{
		"name":        name,
		"description": description,
	}
	var out RoleObject
	err := c.doJSON("POST", "/roles", body, &out)
	return &out, err
}

func (c *AdminClient) UpdateRole(id, description string) (*RoleObject, error) {
	body := map[string]string{"description": description}
	var out RoleObject
	err := c.doJSON("PUT", "/roles/"+id, body, &out)
	return &out, err
}

func (c *AdminClient) GetRole(id string) (*RoleObject, error) {
	var out RoleObject
	err := c.doJSON("GET", "/roles/"+id, nil, &out)
	return &out, err
}

func (c *AdminClient) GetRoleIdByName(name string) (string, error) {
	var out struct {
		Result string `json:"result"`
	}
	err := c.doJSON("GET", "/roles/id-by-name/"+url.PathEscape(name), nil, &out)
	if err != nil {
		return "", err
	}
	return out.Result, nil
}

func (c *AdminClient) ListRoles() ([]RoleObject, error) {
	var out []RoleObject
	err := c.doJSON("GET", "/roles", nil, &out)
	return out, err
}

func (c *AdminClient) DeleteRole(id string) error {
	return c.doJSON("DELETE", "/roles/"+id, nil, nil)
}

func (c *AdminClient) AssignRoleToUser(userID, roleID string) error {
	body := map[string]string{
		"user_id": userID,
		"role_id": roleID,
	}
	return c.doJSON("POST", "/roles/assign", body, nil)
}

func (c *AdminClient) ReplaceUserRoles(userID string, roleIDs []string) error {
	roles := make([]RoleDto, len(roleIDs))
	for i, rid := range roleIDs {
		roles[i] = RoleDto{ID: rid}
	}
	body := RoleAssignmentDto{
		UserID: userID,
		Roles:  roles,
	}
	return c.doJSON("PUT", "/users/"+userID+"/roles", body, nil)
}

func (c *AdminClient) UnassignRoleFromUser(userID, roleID string) error {
	body := map[string]string{
		"user_id": userID,
		"role_id": roleID,
	}
	return c.doJSON("POST", "/roles/unassign", body, nil)
}

func (c *AdminClient) ListRolesForUser(userID string) ([]RoleObject, error) {
	var out []RoleObject
	err := c.doJSON("GET", "/roles/user/"+userID, nil, &out)
	return out, err
}

func (c *AdminClient) ListPermissionsForRole(roleID string) ([]PermissionObject, error) {
	var out []PermissionObject
	err := c.doJSON("GET", "/roles/"+roleID+"/permissions", nil, &out)
	return out, err
}

// PERMISSION METHODS

func (c *AdminClient) CreatePermission(name string) (*PermissionObject, error) {
	body := map[string]string{"name": name}
	var out PermissionObject
	err := c.doJSON("POST", "/permissions", body, &out)
	return &out, err
}

func (c *AdminClient) UpdatePermission(id, name string) (*PermissionObject, error) {
	body := map[string]string{"name": name}
	var out PermissionObject
	err := c.doJSON("PUT", "/permissions/"+id, body, &out)
	return &out, err
}

func (c *AdminClient) GetPermission(id string) (*PermissionObject, error) {
	var out PermissionObject
	err := c.doJSON("GET", "/permissions/"+id, nil, &out)
	return &out, err
}

func (c *AdminClient) GetPermissionIdByName(name string) (string, error) {
	var out struct {
		Result string `json:"result"`
	}
	err := c.doJSON("GET", "/permissions/id-by-name/"+url.PathEscape(name), nil, &out)
	if err != nil {
		return "", err
	}
	return out.Result, nil
}

func (c *AdminClient) ListPermissions() ([]PermissionObject, error) {
	var out []PermissionObject
	err := c.doJSON("GET", "/permissions", nil, &out)
	return out, err
}

func (c *AdminClient) DeletePermission(id string) error {
	return c.doJSON("DELETE", "/permissions/"+id, nil, nil)
}

func (c *AdminClient) AssignPermissionToRole(roleID, permissionID string) error {
	return c.doJSON("POST", "/roles/"+roleID+"/permissions", map[string]string{"permission_id": permissionID}, nil)
}

func (c *AdminClient) RemovePermissionFromRole(roleID, permissionID string) error {
	return c.doJSON("DELETE", "/roles/"+roleID+"/permissions/"+permissionID, nil, nil)
}

func (c *AdminClient) ListPermissionsForUser(userID string) ([]PermissionObject, error) {
	var out []PermissionObject
	err := c.doJSON("GET", "/permissions/user/"+userID, nil, &out)
	return out, err
}

// SCOPE METHODS

func (c *AdminClient) CreateScope(name, desc string) (*ScopeObject, error) {
	body := map[string]string{
		"name":        name,
		"description": desc,
	}
	var out ScopeObject
	err := c.doJSON("POST", "/scopes", body, &out)
	return &out, err
}

func (c *AdminClient) UpdateScope(id, desc string) (*ScopeObject, error) {
	body := map[string]string{"description": desc}
	var out ScopeObject
	err := c.doJSON("PUT", "/scopes/"+id, body, &out)
	return &out, err
}

func (c *AdminClient) GetScope(id string) (*ScopeObject, error) {
	var out ScopeObject
	err := c.doJSON("GET", "/scopes/"+id, nil, &out)
	return &out, err
}

func (c *AdminClient) GetScopeIdByName(name string) (string, error) {
	var out struct {
		Result string `json:"result"`
	}
	err := c.doJSON("GET", "/scopes/id-by-name/"+url.PathEscape(name), nil, &out)
	if err != nil {
		return "", err
	}
	return out.Result, nil
}

func (c *AdminClient) ListScopes() ([]ScopeObject, error) {
	var out []ScopeObject
	err := c.doJSON("GET", "/scopes", nil, &out)
	return out, err
}

func (c *AdminClient) DeleteScope(id string) error {
	return c.doJSON("DELETE", "/scopes/"+id, nil, nil)
}

func (c *AdminClient) AssignScopeToUser(userID, scopeID string) error {
	body := map[string]string{
		"user_id":  userID,
		"scope_id": scopeID,
	}
	return c.doJSON("POST", "/users/"+userID+"/scopes", body, nil)
}

func (c *AdminClient) AssignScopesToUser(userID string, scopeIDs []string) error {
	body := map[string][]string{
		"scopeIds": scopeIDs,
	}
	return c.doJSON("POST", "/users/"+userID+"/scopes", body, nil)
}

func (c *AdminClient) ListScopesForUser(userID string) ([]ScopeObject, error) {
	var out []ScopeObject
	err := c.doJSON("GET", "/users/"+userID+"/scopes", nil, &out)
	return out, err
}

func (c *AdminClient) RemoveScopeFromUser(userID, scopeID string) error {
	return c.doJSON("DELETE", "/users/"+userID+"/scopes/"+scopeID, nil, nil)
}

func (c *AdminClient) AssignScopeToClient(clientID, scopeID string) error {
	body := map[string]string{
		"client_id": clientID,
		"scope_id":  scopeID,
	}
	return c.doJSON("POST", "/clients/"+clientID+"/scopes", body, nil)
}

func (c *AdminClient) AssignScopesToClient(clientID string, scopeIDs []string) error {
	body := map[string][]string{
		"scopeIds": scopeIDs,
	}
	return c.doJSON("POST", "/clients/"+clientID+"/scopes", body, nil)
}

func (c *AdminClient) ListScopesForClient(clientID string) ([]ScopeObject, error) {
	var out []ScopeObject
	err := c.doJSON("GET", "/clients/"+clientID+"/scopes", nil, &out)
	return out, err
}

func (c *AdminClient) RemoveScopeFromClient(clientID, scopeID string) error {
	return c.doJSON("DELETE", "/clients/"+clientID+"/scopes/"+scopeID, nil, nil)
}

// CLIENT METHODS

func (c *AdminClient) CreateClient(clientID, secret, displayName, audience string) (*ClientObject, error) {
	body := map[string]string{
		"client_id":    clientID,
		"secret":       secret,
		"display_name": displayName,
		"audience":     audience,
	}
	var out ClientObject
	err := c.doJSON("POST", "/clients", body, &out)
	return &out, err
}

func (c *AdminClient) UpdateClient(id, displayName, audience string) (*ClientObject, error) {
	body := map[string]string{
		"display_name": displayName,
		"audience":     audience,
	}
	var out ClientObject
	err := c.doJSON("PUT", "/clients/"+id, body, &out)
	return &out, err
}

func (c *AdminClient) GetClient(id string) (*ClientObject, error) {
	var out ClientObject
	err := c.doJSON("GET", "/clients/"+id, nil, &out)
	return &out, err
}

func (c *AdminClient) GetClientIdByClientIdentifier(clientID string) (string, error) {
	var out struct {
		Result string `json:"result"`
	}
	err := c.doJSON("GET", "/clients/id-by-name/"+url.PathEscape(clientID), nil, &out)
	if err != nil {
		return "", err
	}
	return out.Result, nil
}

func (c *AdminClient) ListClients() ([]ClientObject, error) {
	var out []ClientObject
	err := c.doJSON("GET", "/clients", nil, &out)
	return out, err
}

func (c *AdminClient) DeleteClient(id string) error {
	return c.doJSON("DELETE", "/clients/"+id, nil, nil)
}

// audit logs

func (c *AdminClient) ListAuditLogs() ([]AuditLogResponse, error) {
	var out []AuditLogResponse
	err := c.doJSON("GET", "/audit-logs", nil, &out)
	return out, err
}

func (c *AdminClient) GetAuditLogByID(id string) (*AuditLogResponse, error) {
	var out AuditLogResponse
	err := c.doJSON("GET", "/audit-logs/"+id, nil, &out)
	return &out, err
}

func (c *AdminClient) PurgeAuditLogs(days int) error {
	body := map[string]int{"older_than_days": days}
	return c.doJSON("POST", "/audit-logs/purge", body, nil)
}

// introspection
func (c *AdminClient) Introspect(token string) (map[string]any, error) {
	body := map[string]string{"token": token}
	var out map[string]any
	err := c.doJSON("POST", "/introspect", body, &out)
	return out, err
}

// TOTP methods
func (c *AdminClient) GenerateTotp(userID string, outputPath string) (*TotpQrResponse, error) {
	body := map[string]string{
		"user_id":        userID,
		"qr_output_path": outputPath,
	}
	var out TotpQrResponse
	err := c.doJSON("POST", "/users/"+userID+"/totp/generate", body, &out)
	return &out, err
}

func (c *AdminClient) VerifyTotp(userID string, code string) (bool, error) {
	body := map[string]string{
		"user_id": userID,
		"code":    code,
	}
	r := c.BaseURL + "/users/totp/verify"
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", r, bytes.NewReader(buf))
	c.authHeader(req)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode == 200 {
		return true, nil
	} else if res.StatusCode == 403 {
		return false, nil
	}
	return false, fmt.Errorf("unexpected status: %s", res.Status)
}

func (c *AdminClient) DisableTotp(userID string) error {
	return c.doJSON("POST", "/users/"+userID+"/disable-totp", nil, nil)
}

// check permission
func (c *AdminClient) CheckPermission(userID, permission string) (bool, error) {
	body := map[string]string{
		"user_id":    userID,
		"permission": permission,
	}
	var out map[string]bool
	err := c.doJSON("POST", "/check-access", body, &out)
	return out["access"], err
}

func (c *AdminClient) CheckScope(userID, scope string) (bool, error) {
	body := map[string]string{
		"user_id": userID,
		"scope":   scope,
	}
	var out map[string]bool
	err := c.doJSON("POST", "/check-access", body, &out)
	return out["access"], err
}

// verify password
func (c *AdminClient) VerifyPassword(userID, password string) (bool, error) {
	body := map[string]string{
		"user_id":  userID,
		"password": password,
	}
	r := c.BaseURL + "/users/verify-password"
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", r, bytes.NewReader(buf))
	c.authHeader(req)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode == 200 {
		return true, nil
	} else if res.StatusCode == 403 {
		return false, nil
	}
	return false, fmt.Errorf("unexpected status: %s", res.Status)
}
