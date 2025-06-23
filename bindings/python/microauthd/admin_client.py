from typing import Optional, List
from dataclasses import asdict
import requests

from .models import *

class AdminClient:
    def __init__(self, admin_url: str, admin_token: str, auth_url: Optional[str] = None) -> None:
        self.admin_url = admin_url.rstrip("/")
        self.admin_token = admin_token
        self.auth_url = auth_url.rstrip("/") if auth_url else "http://localhost:9040"

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.admin_token:
            headers["Authorization"] = f"Bearer {self.admin_token}"
        return headers

    def create_user(self, username: str, password: str, email: Optional[str] = None) -> UserObject:
        url = f"{self.admin_url}/users"
        payload = {
            "username": username,
            "user_password": password,
            "user_email": email
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return UserObject.from_dict(resp.json())

    def get_user(self, user_id: str) -> Optional[UserObject]:
        url = f"{self.admin_url}/users/{user_id}"
        resp = requests.get(url, headers=self._headers())
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return UserObject.from_dict(resp.json())
    
    def get_user_id_by_username(self, username: str) -> Optional[str]:
        url = f"{self.admin_url}/users/id-by-name/{username}"
        res = requests.get(url, headers=self._headers())
        if res.status_code == 404:
            return None
        res.raise_for_status()
        return res.json().get("result")

    def update_user(self, user_id: str, email: Optional[str] = None, is_active: Optional[bool] = None) -> UserObject:
        url = f"{self.admin_url}/users/{user_id}"
        payload = {}
        if email is not None:
            payload["email"] = email
        if is_active is not None:
            payload["is_active"] = is_active
        resp = requests.put(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return UserObject.from_dict(resp.json())

    def delete_user(self, user_id: str) -> bool:
        url = f"{self.admin_url}/users/{user_id}"
        resp = requests.delete(url, headers=self._headers())
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True

    def list_users(self) -> list[UserObject]:
        url = f"{self.admin_url}/users"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [UserObject.from_dict(u) for u in resp.json()]
    
    # Role operations
    def create_role(self, name: str, description: Optional[str] = None) -> RoleObject:
        url = f"{self.admin_url}/roles"
        payload = {
            "name": name,
            "description": description
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return RoleObject.from_dict(resp.json())

    def get_role(self, role_id: str) -> Optional[RoleObject]:
        url = f"{self.admin_url}/roles/{role_id}"
        resp = requests.get(url, headers=self._headers())
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return RoleObject.from_dict(resp.json())

    def get_role_id_by_name(self, name: str) -> Optional[str]:
        url = f"{self.admin_url}/roles/id-by-name/{name}"
        res = requests.get(url, headers=self._headers())
        if res.status_code == 404:
            return None
        res.raise_for_status()
        return res.json().get("result")

    def update_role(self, role_id: str, description: Optional[str] = None) -> RoleObject:
        url = f"{self.admin_url}/roles/{role_id}"
        payload = {"description": description} if description is not None else {}
        resp = requests.put(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return RoleObject.from_dict(resp.json())

    def delete_role(self, role_id: str) -> bool:
        url = f"{self.admin_url}/roles/{role_id}"
        resp = requests.delete(url, headers=self._headers())
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True

    def list_roles(self) -> list[RoleObject]:
        url = f"{self.admin_url}/roles"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [RoleObject.from_dict(r) for r in resp.json()]
    
    def assign_role_to_user(self, user_id: str, role_id: str) -> bool:
        url = f"{self.admin_url}/roles/assign"
        payload = {
            "user_id": user_id,
            "role_id": role_id
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("success", False)

    def replace_user_roles(self, user_id: str, role_ids: list[str]) -> bool:
        url = f"{self.admin_url}/users/{user_id}/roles"
        dto = {
            "userId": user_id,
            "roles": [{"id": rid} for rid in role_ids]
        }
        resp = requests.put(url, json=dto, headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("success", True)

    def remove_role_from_user(self, user_id: str, role_id: str) -> bool:
        url = f"{self.admin_url}/roles/remove"
        payload = {
            "user_id": user_id,
            "role_id": role_id
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("success", False)
    
    # Permission operations
    def create_permission(self, name: str) -> PermissionObject:
        url = f"{self.admin_url}/permissions"
        payload = {"name": name}
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return PermissionObject.from_dict(resp.json())

    def get_permission(self, perm_id: str) -> Optional[PermissionObject]:
        url = f"{self.admin_url}/permissions/{perm_id}"
        resp = requests.get(url, headers=self._headers())
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return PermissionObject.from_dict(resp.json())

    def get_permission_id_by_name(self, name: str) -> Optional[str]:
        url = f"{self.admin_url}/permissions/id-by-name/{name}"
        res = requests.get(url, headers=self._headers())
        if res.status_code == 404:
            return None
        res.raise_for_status()
        return res.json().get("result")

    def update_permission(self, perm_id: str, name: str) -> PermissionObject:
        url = f"{self.admin_url}/permissions/{perm_id}"
        payload = {"name": name}
        resp = requests.put(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return PermissionObject.from_dict(resp.json())

    def delete_permission(self, perm_id: str) -> bool:
        url = f"{self.admin_url}/permissions/{perm_id}"
        resp = requests.delete(url, headers=self._headers())
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True

    def list_permissions(self) -> list[PermissionObject]:
        url = f"{self.admin_url}/permissions"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [PermissionObject.from_dict(p) for p in resp.json()]
    
    def assign_permission_to_role(self, role_id: str, permission_id: str) -> bool:
        url = f"{self.admin_url}/permissions/assign"
        payload = {
            "role_id": role_id,
            "permission_id": permission_id
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("success", False)

    def remove_permission_from_role(self, role_id: str, permission_id: str) -> bool:
        url = f"{self.admin_url}/permissions/remove"
        payload = {
            "role_id": role_id,
            "permission_id": permission_id
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("success", False)
    
    def list_permissions_for_user(self, user_id: str) -> list[PermissionObject]:
        url = f"{self.admin_url}/permissions/user/{user_id}"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [PermissionObject.from_dict(p) for p in resp.json()]
    
    # Scope operations
    def create_scope(self, name: str, description: Optional[str] = None) -> ScopeObject:
        url = f"{self.admin_url}/scopes"
        payload = {
            "name": name,
            "description": description
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return ScopeObject.from_dict(resp.json())

    def get_scope(self, scope_id: str) -> Optional[ScopeObject]:
        url = f"{self.admin_url}/scopes/{scope_id}"
        resp = requests.get(url, headers=self._headers())
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return ScopeObject.from_dict(resp.json())

    def get_scope_id_by_name(self, name: str) -> Optional[str]:
        url = f"{self.admin_url}/scopes/id-by-name/{name}"
        res = requests.get(url, headers=self._headers())
        if res.status_code == 404:
            return None
        res.raise_for_status()
        return res.json().get("result")

    def update_scope(self, scope_id: str, description: Optional[str] = None) -> ScopeObject:
        url = f"{self.admin_url}/scopes/{scope_id}"
        payload = {"description": description} if description is not None else {}
        resp = requests.put(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return ScopeObject.from_dict(resp.json())

    def delete_scope(self, scope_id: str) -> bool:
        url = f"{self.admin_url}/scopes/{scope_id}"
        resp = requests.delete(url, headers=self._headers())
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True

    def list_scopes(self) -> list[ScopeObject]:
        url = f"{self.admin_url}/scopes"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [ScopeObject.from_dict(s) for s in resp.json()]
    
    def assign_scope_to_user(self, user_id: str, scope_id: str) -> bool:
        url = f"{self.admin_url}/scopes/assign-to-user"
        payload = {
            "user_id": user_id,
            "scope_id": scope_id
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("success", False)

    def assign_scopes_to_user(self, user_id: str, scope_ids: list[str]) -> bool:
        url = f"{self.admin_url}/users/{user_id}/scopes"
        payload = {"scopeIds": scope_ids}
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("success", True)

    def list_scopes_for_user(self, user_id: str) -> list[ScopeObject]:
        url = f"{self.admin_url}/scopes/user/{user_id}"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [ScopeObject.from_dict(s) for s in resp.json()]
    
    def remove_scope_from_user(self, user_id: str, scope_id: str) -> bool:
        url = f"{self.admin_url}/scopes/remove-from-user"
        payload = {
            "user_id": user_id,
            "scope_id": scope_id
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("success", False)
    
    def assign_scope_to_client(self, client_id: str, scope_id: str) -> bool:
        url = f"{self.admin_url}/scopes/assign-to-client"
        payload = {
            "client_id": client_id,
            "scope_id": scope_id
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("success", False)

    def assign_scopes_to_client(self, client_id: str, scope_ids: list[str]) -> bool:
        url = f"{self.admin_url}/clients/{client_id}/scopes"
        payload = {"scopeIds": scope_ids}
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("success", True)

    def list_scopes_for_client(self, client_id: str) -> list[ScopeObject]:
        url = f"{self.admin_url}/scopes/client/{client_id}"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [ScopeObject.from_dict(s) for s in resp.json()]
    
    def remove_scope_from_client(self, client_id: str, scope_id: str) -> bool:
        url = f"{self.admin_url}/scopes/remove-from-client"
        payload = {
            "client_id": client_id,
            "scope_id": scope_id
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return resp.json().get("success", False)
    
    # Client operations
    def create_client(self, client_id: str, secret: str, display_name: Optional[str] = None, audience: Optional[str] = None) -> ClientObject:
        url = f"{self.admin_url}/clients"
        payload = {
            "client_id": client_id,
            "secret": secret,
            "display_name": display_name,
            "audience": audience
        }
        resp = requests.post(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return ClientObject.from_dict(resp.json())

    def get_client(self, client_id: str) -> Optional[ClientObject]:
        url = f"{self.admin_url}/clients/{client_id}"
        resp = requests.get(url, headers=self._headers())
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return ClientObject.from_dict(resp.json())

    def get_client_id_by_name(self, client_id: str) -> Optional[str]:
        url = f"{self.admin_url}/clients/id-by-name/{client_id}"
        res = requests.get(url, headers=self._headers())
        if res.status_code == 404:
            return None
        res.raise_for_status()
        return res.json().get("result")

    def update_client(self, client_id: str, display_name: Optional[str] = None, audience: Optional[str] = None) -> ClientObject:
        url = f"{self.admin_url}/clients/{client_id}"
        payload = {}
        if display_name is not None:
            payload["display_name"] = display_name
        if audience is not None:
            payload["audience"] = audience
        resp = requests.put(url, json=payload, headers=self._headers())
        resp.raise_for_status()
        return ClientObject.from_dict(resp.json())

    def delete_client(self, client_id: str) -> bool:
        url = f"{self.admin_url}/clients/{client_id}"
        resp = requests.delete(url, headers=self._headers())
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True

    def list_clients(self) -> list[ClientObject]:
        url = f"{self.admin_url}/clients"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [ClientObject.from_dict(c) for c in resp.json()]
    
    # Session management
    def list_sessions_for_user(self, user_id: str) -> list[SessionResponse]:
        url = f"{self.admin_url}/sessions/user/{user_id}"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [SessionResponse.from_dict(s) for s in resp.json()]

    def get_session(self, session_id: str) -> Optional[SessionResponse]:
        url = f"{self.admin_url}/sessions/{session_id}"
        resp = requests.get(url, headers=self._headers())
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return SessionResponse.from_dict(resp.json())

    def list_all_sessions(self) -> list[SessionResponse]:
        url = f"{self.admin_url}/sessions"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [SessionResponse.from_dict(s) for s in resp.json()]
    
    # Refresh token management
    def list_refresh_tokens_for_user(self, user_id: str) -> list[RefreshTokenResponse]:
        url = f"{self.admin_url}/refresh-tokens/user/{user_id}"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [RefreshTokenResponse.from_dict(t) for t in resp.json()]

    def list_all_refresh_tokens(self) -> list[RefreshTokenResponse]:
        url = f"{self.admin_url}/refresh-tokens"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return [RefreshTokenResponse.from_dict(t) for t in resp.json()]
    
    def delete_refresh_token(self, token_id: str) -> bool:
        url = f"{self.admin_url}/refresh-tokens/{token_id}"
        resp = requests.delete(url, headers=self._headers())
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True
    
    def delete_session(self, session_id: str) -> bool:
        url = f"{self.admin_url}/sessions/{session_id}"
        resp = requests.delete(url, headers=self._headers())
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True
    
    # Tokens
    def issue_token_password(self, username: str, password: str, client_id: str) -> TokenResponse:
        url = f"{self.auth_url}/token"
        data = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": client_id
        }
        resp = requests.post(url, data=data)
        resp.raise_for_status()
        return TokenResponse.from_dict(resp.json())
    
    def issue_token_refresh(self, refresh_token: str) -> TokenResponse:
        url = f"{self.auth_url}/token"
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
        resp = requests.post(url, data=data)
        resp.raise_for_status()
        return TokenResponse.from_dict(resp.json())
    
    def issue_token_client_credentials(self, client_id: str, client_secret: str) -> TokenResponse:
        url = f"{self.auth_url}/oidc/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret
        }
        resp = requests.post(url, data=data)
        resp.raise_for_status()
        return TokenResponse.from_dict(resp.json())
    
    def revoke_token(self, token: str, client_id: str, client_secret: str) -> bool:
        url = f"{self.auth_url}/revoke"
        data = {
            "token": token,
            "client_id": client_id,
            "client_secret": client_secret
        }
        resp = requests.post(url, data=data)
        resp.raise_for_status()
        return resp.json().get("success", False)
    
    def introspect_token(self, token: str, client_id: str, client_secret: str) -> dict:
        url = f"{self.auth_url}/introspect"
        data = {
            "token": token,
            "client_id": client_id,
            "client_secret": client_secret
        }
        resp = requests.post(url, data=data)
        resp.raise_for_status()
        return resp.json()
    
    def introspect_token_admin(self, token: str) -> dict:
        url = f"{self.admin_url}/introspect"
        headers = self._headers()
        payload = {
            "token": token
        }
        resp = requests.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()
    
    def purge_all_tokens(self, req: PurgeTokensRequest) -> MessageResponse:
        url = f"{self.admin_url}/tokens/purge"
        res = requests.post(url, json=asdict(req), headers=self._headers())
        res.raise_for_status()
        return MessageResponse(**res.json())
        
    def purge_all_refresh_tokens(self, req: PurgeTokensRequest) -> MessageResponse:
        url = f"{self.admin_url}/refresh-tokens/purge"
        res = requests.post(url, json=asdict(req), headers=self._headers())
        res.raise_for_status()
        return MessageResponse(**res.json())

    # Audit Logs
    def get_audit_logs(self) -> List[AuditLogResponse]:
        res = requests.get(f"{self.admin_url}/audit-logs")
        res.raise_for_status()
        return [AuditLogResponse(**log) for log in res.json()]

    def get_audit_log_by_id(self, audit_id: str) -> AuditLogResponse:
        url = f"{self.admin_url}/audit-logs/{audit_id}"
        res = requests.get(url, headers=self._headers())
        res.raise_for_status()
        return AuditLogResponse(**res.json())

    def purge_audit_logs(self, older_than_days: int) -> MessageResponse:
        body = {"older_than_days": older_than_days}
        res = requests.post(f"{self.admin_url}/audit-logs/purge", json=body)
        res.raise_for_status()
        return MessageResponse(**res.json())

    # TOTP
    def generate_totp_for_user(self, user_id: str, output_path: str) -> TotpQrResponse:
        url = f"{self.admin_url}/users/{user_id}/totp/generate"
        payload = TotpQrRequest(user_id=user_id, qr_output_path=output_path)
        res = requests.post(url, json=asdict(payload), headers=self._headers())
        res.raise_for_status()
        return TotpQrResponse(**res.json())

    def verify_totp_code(self, user_id: str, code: str) -> bool:
        url = f"{self.admin_url}/users/totp/verify"
        payload = VerifyTotpRequest(user_id=user_id, code=code)
        res = requests.post(url, json=asdict(payload), headers=self._headers())
        if res.status_code == 200:
            return True
        if res.status_code == 403:
            return False
        res.raise_for_status()
        return False

    def disable_totp_for_user(self, user_id: str) -> MessageResponse:
        url = f"{self.admin_url}/users/{user_id}/disable-totp"
        res = requests.post(url, headers=self._headers())
        res.raise_for_status()
        return MessageResponse(**res.json())

    @staticmethod
    def login_admin(admin_url: str, username: str, password: str, client_id: str = "app") -> "AdminClient":
        url = admin_url.rstrip("/") + "/token"
        data = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": client_id
        }

        resp = requests.post(url, data=data, headers={"Accept": "application/json"})
        resp.raise_for_status()
        token_data = TokenResponse.from_dict(resp.json())
        return AdminClient(admin_url, token_data.access_token)
