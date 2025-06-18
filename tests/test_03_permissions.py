import json
import os
import pytest
from random import randint
from mad_testlib import run_mad

TRACK_FILE = "test_state.json"

def load_state():
    with open(TRACK_FILE, "r") as f:
        return json.load(f)

def save_state(key, obj):
    try:
        state = load_state()
        state[key] = obj
        with open(TRACK_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        pytest.fail(f"Failed to update test_state.json: {e}")

def fail_with_data(message, data):
    pytest.fail(f"{message}\nFull response:\n{json.dumps(data, indent=2)}")

def test_create_update_query_assign_permission():
    state = load_state()
    user = state["user"]
    role = state["role"]

    assert user and role, "test_state.json missing user or role"

    role_id = role["id"]
    user_id = user["id"]

    # CREATE
    name = f"perm_{randint(10000, 99999)}"
    ok, perm = run_mad([
        "permission", "create",
        "--name", name,
        "--json"
    ])
    if not ok:
        fail_with_data("Failed to create permission", perm)

    if "id" not in perm:
        fail_with_data("Permission ID missing after creation", perm)

    perm_id = perm["id"]
    save_state("permission", perm)

    # UPDATE
    ok, updated = run_mad([
        "permission", "update",
        "--id", perm_id,
        "--name", name + "_updated",
        "--json"
    ])
    if not ok:
        fail_with_data("Failed to update permission", updated)

    if not updated.get("name", "").endswith("_updated"):
        fail_with_data("Permission name was not updated", updated)

    # GET
    ok, fetched = run_mad([
        "permission", "get",
        "--id", perm_id,
        "--json"
    ])
    if not ok:
        fail_with_data("Failed to fetch permission", fetched)
    if fetched["id"] != perm_id:
        fail_with_data("Fetched permission ID mismatch", fetched)

    # LIST
    ok, perms = run_mad(["permission", "list", "--json"])
    if not ok or not any(p.get("id") == perm_id for p in perms):
        fail_with_data("Created permission not found in list", perms)

    # ASSIGN TO ROLE
    ok, result = run_mad([
        "permission", "assign",
        "--role-id", role_id,
        "--permission-id", perm_id,
        "--json"
    ])
    if not ok:
        fail_with_data("Failed to assign permission to role", result)

    if not result.get("success", False):
        fail_with_data("Permission assign response did not return success", result)

    # VERIFY EFFECTIVE PERMISSIONS
    ok, effective = run_mad([
        "permission", "list-for-user",
        "--user-id", user_id,
        "--json"
    ])
    if not ok:
        fail_with_data("Failed to get effective permissions for user", effective)

    if not any(p.get("id") == perm_id for p in effective):
        fail_with_data("Assigned permission not found in user's effective permissions", effective)
