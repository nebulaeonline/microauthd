from dataclasses import dataclass
from typing import Optional, Any
from datetime import datetime

@dataclass
class UserObject:
    id: str
    username: str
    email: Optional[str] = None
    is_active: bool = True

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "UserObject":
        return UserObject(
            id=data["id"],
            username=data["username"],
            email=data.get("email"),
            is_active=data.get("is_active", True)
        )

@dataclass
class RoleObject:
    id: str
    name: str
    description: Optional[str] = None
    is_active: bool = True

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "RoleObject":
        return RoleObject(
            id=data["id"],
            name=data["name"],
            description=data.get("description"),
            is_active=data.get("is_active", True)
        )


@dataclass
class ScopeObject:
    id: str
    name: str
    description: Optional[str] = None
    is_active: bool = True

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ScopeObject":
        return ScopeObject(
            id=data["id"],
            name=data["name"],
            description=data.get("description"),
            is_active=data.get("is_active", True)
        )


@dataclass
class PermissionObject:
    id: str
    name: str
    is_active: bool = True

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "PermissionObject":
        return PermissionObject(
            id=data["id"],
            name=data["name"],
            is_active=data.get("is_active", True)
        )


@dataclass
class ClientObject:
    id: str
    client_id: str
    display_name: Optional[str] = None
    audience: Optional[str] = None
    is_active: bool = True

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ClientObject":
        return ClientObject(
            id=data["id"],
            client_id=data["client_id"],
            display_name=data.get("display_name"),
            audience=data.get("audience"),
            is_active=data.get("is_active", True)
        )
    
@dataclass
class TokenResponse:
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    jti: Optional[str] = None
    audience: Optional[str] = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "TokenResponse":
        return TokenResponse(
            access_token=data["access_token"],
            token_type=data["token_type"],
            expires_in=data["expires_in"],
            refresh_token=data.get("refresh_token"),
            jti=data.get("jti"),
            audience=data.get("audience")
        )

@dataclass
class SessionResponse:
    id: str
    user_id: str
    client_identifier: str
    created_at: str
    expires_at: str
    token_use: str
    is_revoked: bool

    @staticmethod
    def from_dict(data: dict) -> "SessionResponse":
        return SessionResponse(
            id=data["id"],
            user_id=data["user_id"],
            client_identifier=data["client_identifier"],
            created_at=data["created_at"],
            expires_at=data["expires_at"],
            token_use=data["token_use"],
            is_revoked=data["is_revoked"]
        )
    
@dataclass
class RefreshTokenResponse:
    id: str
    user_id: str
    session_id: str
    client_identifier: str
    expires_at: str
    is_revoked: bool

    @staticmethod
    def from_dict(data: dict) -> "RefreshTokenResponse":
        return RefreshTokenResponse(
            id=data["id"],
            user_id=data["user_id"],
            session_id=data["session_id"],
            client_identifier=data["client_identifier"],
            expires_at=data["expires_at"],
            is_revoked=data["is_revoked"]
        )
    
@dataclass
class AuditLogResponse:
    id: str
    user_id: Optional[str]
    action: str
    target: str
    ip: Optional[str]
    user_agent: Optional[str]
    timestamp: datetime


@dataclass
class MessageResponse:
    success: bool
    message: str

@dataclass
class PurgeAuditLogRequest:
    older_than_days: int


@dataclass
class PurgeTokensRequest:
    user_id: str
    client_id: Optional[str] = None

@dataclass
class TotpQrRequest:
    user_id: str
    qr_output_path: str

@dataclass
class VerifyTotpRequest:
    user_id: str
    code: str

@dataclass
class TotpQrResponse:
    qr_code_filename: str