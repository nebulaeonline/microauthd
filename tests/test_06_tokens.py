import os
import json
import pytest
import subprocess
from mad_testlib import run_mad

AUTH_URL = "http://localhost:9040"
ADMIN_URL = "http://localhost:9041"

def load_state():
    with open("test_state.json") as f:
        return json.load(f)

def fail_with_data(msg, data):
    pytest.fail(f"{msg}\n{json.dumps(data, indent=2)}")

def curl_post_token(data: dict, url: str) -> dict:
    form_data = '&'.join([f"{k}={v}" for k, v in data.items()])
    result = subprocess.run([
        "curl", "-s", "-X", "POST", url,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "--data", form_data
    ], capture_output=True, text=True)
    
    if result.stdout.strip() == "":
        print("Empty response from server")
        print("STDERR:", result.stderr)
        return {}

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print("Failed to parse JSON:")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        raise e

def curl_post_with_auth(data: dict, url: str, token: str) -> dict:
    form_data = '&'.join([f"{k}={v}" for k, v in data.items()])
    result = subprocess.run([
        "curl", "-s", "-X", "POST", url,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "-H", f"Authorization: Bearer {token}",
        "--data", form_data
    ], capture_output=True, text=True)
    print("STDOUT:\n", result.stdout)
    print("STDERR:\n", result.stderr)
    
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(result.stdout)
        raise

def curl_post_basic_auth(data: dict, url: str, client_id: str, client_secret: str) -> dict:
    form_data = '&'.join([f"{k}={v}" for k, v in data.items()])
    result = subprocess.run([
        "curl", "-s", "-X", "POST", url,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "-u", f"{client_id}:{client_secret}",
        "--data", form_data
    ], capture_output=True, text=True)
    
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Failed to parse JSON:")
        print(result.stdout)
        raise

def curl_post_introspect_basic_auth(token: str, url: str, client_id: str, client_secret: str) -> dict:
    form_data = f"token={token}"
    result = subprocess.run([
        "curl", "-s", "-X", "POST", url,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "-u", f"{client_id}:{client_secret}",
        "--data", form_data
    ], capture_output=True, text=True)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Failed to parse JSON:")
        print(result.stdout)
        raise

def test_token_refresh_and_blacklist_flow():
    state = load_state()
    user = state.get("user")
    client = state.get("client")

    assert user and client, "Missing user or client in test_state.json"

    username = user["username"]
    client_id = client["client_id"]
    client_secret = client["client_secret"]

    # Step 1: Issue user token (password grant)
    token_response = curl_post_token({
        "grant_type": "password",
        "username": username,
        "password": "testpass123",
        "client_id": client_id
    }, f"{AUTH_URL}/token")

    access_token = token_response.get("access_token")
    refresh_token = token_response.get("refresh_token")
    jti = token_response.get("jti")

    assert access_token and refresh_token, f"Token issuance failed: {token_response}"

    # Step 2: Refresh token once
    refresh_response_1 = curl_post_token({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }, f"{AUTH_URL}/token")

    assert refresh_response_1.get("access_token"), f"Refresh failed: {refresh_response_1}"

    # Step 3: Attempt to reuse refresh token (should fail)
    refresh_response_2 = curl_post_token({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }, f"{AUTH_URL}/token")

    if refresh_response_2.get("access_token") or refresh_response_2.get("success", True):
        fail_with_data("Reused refresh token should not succeed", refresh_response_2)

    # Step 4: Issue OIDC token (client_credentials grant)
    oidc_token = curl_post_token({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }, f"{AUTH_URL}/oidc/token")

    oidc_access_token = oidc_token.get("access_token")
    oidc_jti = oidc_token.get("jti")
    assert oidc_access_token and oidc_jti, f"OIDC token failure: {oidc_token}"

    # Step 5: Introspect OIDC token (AUTH)
    auth_introspect = curl_post_with_auth({
        "token": oidc_access_token,
        "client_id": client_id,
        "client_secret": client_secret
    }, f"{AUTH_URL}/introspect", oidc_access_token)

    if not auth_introspect.get("active", False):
        fail_with_data("AUTH introspection should return active", auth_introspect)

    # Step 5b: Call /userinfo with the same token
    userinfo_res = subprocess.run([
        "curl", "-s", "-X", "GET", f"{AUTH_URL}/userinfo",
        "-H", f"Authorization: Bearer {oidc_access_token}"
    ], capture_output=True, text=True)

    try:
        userinfo = json.loads(userinfo_res.stdout)
    except json.JSONDecodeError:
        print("Failed to parse /userinfo response:")
        print("STDOUT:", userinfo_res.stdout)
        print("STDERR:", userinfo_res.stderr)
        raise

    if "sub" not in userinfo:
        fail_with_data("Missing 'sub' in /userinfo response", userinfo)

    print("/userinfo response:", userinfo)

    # Step 6: Revoke token
    revoke_response = curl_post_basic_auth(
      {"token": oidc_access_token},
      f"{AUTH_URL}/revoke",
      client_id,
      client_secret
    )
    if not revoke_response.get("success", False):
      fail_with_data("Failed to revoke OIDC token", revoke_response)

    # Step 7: Re-introspect (should now be inactive)
    recheck = curl_post_introspect_basic_auth(
      oidc_access_token,
      f"{AUTH_URL}/introspect",
      client_id,
      client_secret
    )

    if recheck.get("active", True):
      fail_with_data("Token should be inactive after revocation", recheck)
