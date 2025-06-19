# bindings/python/microauthd/authclient.py

import requests
from typing import Optional
from microauthd.models import TokenResponse, MessageResponse, MeResponse


class AuthClient:
    def __init__(self, auth_url: str, access_token: str, refresh_token: Optional[str] = None):
        self.auth_url = auth_url.rstrip("/")
        self.access_token = access_token
        self.refresh_token = refresh_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
    
    @staticmethod
    def login_password(auth_url: str, username: str, password: str, client_id: str = "app") -> "AuthClient":
        url = f"{auth_url.rstrip('/')}/token"
        data = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": client_id
        }
        resp = requests.post(url, data=data, headers={"Accept": "application/json"})
        resp.raise_for_status()
        tok = TokenResponse.from_dict(resp.json())
        return AuthClient(auth_url, tok.access_token, tok.refresh_token)

    def refresh(self) -> None:
        if not self.refresh_token:
            raise ValueError("No refresh token available")

        url = f"{self.auth_url}/token"
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token
        }
        resp = requests.post(url, data=data, headers={"Accept": "application/json"})
        resp.raise_for_status()
        tok = TokenResponse.from_dict(resp.json())
        self.access_token = tok.access_token
        self.refresh_token = tok.refresh_token

    @staticmethod
    def client_credentials(auth_url: str, client_id: str, client_secret: str) -> "AuthClient":
        url = f"{auth_url.rstrip('/')}/oidc/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret
        }
        resp = requests.post(url, data=data, headers={"Accept": "application/json"})
        resp.raise_for_status()
        tok = TokenResponse.from_dict(resp.json())
        return AuthClient(auth_url, tok.access_token)

    def get_me(self) -> MeResponse:
        url = self.auth_url.rstrip("/") + "/me"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return MeResponse.from_dict(resp.json())

    def revoke(self, token: Optional[str] = None, client_id: Optional[str] = None, client_secret: Optional[str] = None) -> MessageResponse:
        url = f"{self.auth_url}/revoke"
        data = {"token": token or self.access_token}

        if client_id and client_secret:
            data["client_id"] = client_id
            data["client_secret"] = client_secret

        resp = requests.post(url, data=data, headers={"Accept": "application/json"})
        resp.raise_for_status()
        return MessageResponse.from_dict(resp.json())

    def introspect(self, token: Optional[str] = None, client_id: Optional[str] = None, client_secret: Optional[str] = None) -> dict:
        url = f"{self.auth_url}/introspect"
        data = {"token": token or self.access_token}

        if client_id and client_secret:
            data["client_id"] = client_id
            data["client_secret"] = client_secret

        resp = requests.post(url, data=data, headers={"Accept": "application/json"})
        resp.raise_for_status()
        return resp.json()
