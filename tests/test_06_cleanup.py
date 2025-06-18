import json
import pytest
from mad_testlib import run_mad

def load_state():
    with open("test_state.json") as f:
        return json.load(f)

def fail_with_data(msg, data):
    pytest.fail(f"{msg}\n{json.dumps(data, indent=2)}")

def test_cleanup_all_test_objects():
    state = load_state()

    user = state.get("user")
    role = state.get("role")
    perm = state.get("permission")
    scope = state.get("scope")
    client = state.get("client")

    # 1. Remove scope from user
    if user and scope:
        run_mad([
            "scope", "remove-from-user",
            "--user-id", user["id"],
            "--scope-id", scope["id"],
            "--json"
        ], fail_ok=True)

    # 2. Remove scope from client
    if client and scope:
        run_mad([
            "scope", "remove-from-client",
            "--client-id", client["id"],
            "--scope-id", scope["id"],
            "--json"
        ], fail_ok=True)

    # 3. Delete scope
    if scope:
        run_mad([
            "scope", "delete",
            "--id", scope["id"],
            "--json"
        ], fail_ok=True)

    # 4. Delete client
    if client:
        run_mad([
            "client", "delete",
            "--id", client["id"],
            "--json"
        ], fail_ok=True)

    # 5. Delete permission
    if perm:
        run_mad([
            "permission", "delete",
            "--id", perm["id"],
            "--json"
        ], fail_ok=True)

    # 6. Delete role
    if role:
        run_mad([
            "role", "delete",
            "--id", role["id"],
            "--json"
        ], fail_ok=True)

    # 7. Delete user <-- deletion is not currently implemented in microauthd
    #if user:
    #    run_mad([
    #        "user", "deactivate", "--id", user["id"]  # Ensure it's inactive
    #    ], fail_ok=True)
    #    run_mad([
    #        "user", "delete", "--id", user["id"]
    #    ], fail_ok=True)

    # 8. Confirm deletions (optional: skip if you're confident)
    #if user:
    #    ok, result = run_mad(["user", "get", "--id", user["id"], "--json"], fail_ok=True)
    #    if ok:
    #        fail_with_data("User still exists after deletion", result)

    if role:
        ok, result = run_mad(["role", "get", "--id", role["id"], "--json"], fail_ok=True)
        if ok:
            fail_with_data("Role still exists after deletion", result)
