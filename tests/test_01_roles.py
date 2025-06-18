import json
import os
import pytest
from random import randint
from mad_testlib import run_mad

TRACK_FILE = "test_state.json"

def load_user():
    with open(TRACK_FILE, "r") as f:
        return json.load(f)["user"]

def save_state(key, obj):
    try:
        state = {}
        if os.path.exists(TRACK_FILE):
            with open(TRACK_FILE, "r") as f:
                state = json.load(f)
        state[key] = obj
        with open(TRACK_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        pytest.fail(f"Failed to update test_state.json: {e}")

def fail_with_data(message, data):
    pytest.fail(f"{message}\nFull response:\n{json.dumps(data, indent=2)}")

def test_create_update_query_role():
    user = load_user()
    role_name = f"testrole_{randint(10000, 99999)}"
    description = "initial test role"

    # CREATE
    ok, role = run_mad([
        "role", "create",
        "--name", role_name,
        "--description", description
    ])
    if not ok:
        fail_with_data("Failed to create role", role)

    if role.get("name") != role_name:
        fail_with_data("Role name mismatch after creation", role)

    if role.get("description") != description:
        fail_with_data("Role description mismatch after creation", role)

    if "id" not in role:
        fail_with_data("Role ID missing", role)

    role_id = role["id"]
    save_state("role", role)

    # UPDATE
    new_desc = "updated test role"
    ok, updated = run_mad([
        "role", "update",
        "--id", role_id,
        "--description", new_desc
    ])
    if not ok:
        fail_with_data("Failed to update role", updated)

    if updated.get("description") != new_desc:
        fail_with_data("Description not updated correctly", updated)

    # GET
    ok, fetched = run_mad([
        "role", "get",
        "--id", role_id
    ])
    if not ok:
        fail_with_data("Failed to get role by ID", fetched)

    if fetched.get("id") != role_id:
        fail_with_data("Role ID mismatch in get", fetched)

    if fetched.get("description") != new_desc:
        fail_with_data("Fetched role does not reflect updated description", fetched)

    # LIST
    ok, roles = run_mad(["role", "list"])
    if not ok:
        fail_with_data("Failed to list roles", roles)

    if not any(r.get("id") == role_id for r in roles):
        fail_with_data("Created role not found in role list", roles)
