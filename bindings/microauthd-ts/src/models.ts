// Shared model types for microauthd clients.

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  jti?: string;
  audience?: string;
}

export interface MeResponse {
  sub: string;
  email?: string;
  roles: string[];
  scopes: string[];
}

export interface UserObject {
  id: string;
  username: string;
  email?: string;
  is_active: boolean;
  created_at?: string;
}

export interface RoleObject {
  id: string;
  name: string;
  description?: string;
  is_active: boolean;
}

export interface ScopeObject {
  id: string;
  name: string;
  desc?: string;
  is_active: boolean;
  created_at?: string;
}

export interface PermissionObject {
  id: string;
  name: string;
  is_active: boolean;
}

export interface ClientObject {
  id: string;
  client_id: string;
  display_name?: string;
  audience?: string;
  is_active: boolean;
  created_at?: string;
}

export interface SessionResponse {
  id: string;
  user_id: string;
  client_identifier: string;
  created_at: string;
  expires_at: string;
  token_use: string;
  is_revoked: boolean;
}

export interface RefreshTokenResponse {
  id: string;
  user_id: string;
  session_id: string;
  client_identifier: string;
  expires_at: string;
  is_revoked: boolean;
}

export interface AuditLogResponse {
  id: string;
  user_id?: string;
  action: string;
  target: string;
  ip?: string;
  user_agent?: string;
  timestamp: string; // ISO 8601 string (convert to Date as needed)
}

export interface TotpQrRequest {
  user_id: string;
  qr_output_path: string;
}

export interface TotpQrResponse {
  qr_code_filename: string;
}

export interface VerifyTotpRequest {
  user_id: string;
  code: string;
}

export interface MessageResponse {
  success: boolean;
  message: string;
}

export interface PurgeTokensRequest {
  older_than_seconds: number;
  purge_expired: boolean;
  purge_revoked: boolean;
}

export interface PurgeAuditLogRequest {
  older_than_days: number;
}
