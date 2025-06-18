import json
import pytest
from random import randint
from mad_testlib import run_mad

def load_state():
    with open("test_state.json") as f:
        return json.load(f)

def save_state(key, obj):
    state = load_state()
    state[key] = obj
    with open("test_state.json", "w") as f:
        json.dump(state, f, indent=2)

def fail_with_data(msg, data):
    pytest.fail(f"{msg}\n{json.dumps(data, indent=2)}")

def test_create_update_assign_scope():
    state = load_state()
    user = state.get("user")
    assert user, "Missing user in test_state.json"

    user_id = user["id"]

    # Create scope
    name = f"scope_{randint(10000, 99999)}"
    ok, scope = run_mad([
        "scope", "create",
        "--name", name,
        "--description", "test scope",
        "--json"
    ])
    if not ok or "id" not in scope:
        fail_with_data("Failed to create scope", scope)

    scope_id = scope["id"]
    save_state("scope", scope)

    # Update scope
    ok, updated = run_mad([
        "scope", "update",
        "--id", scope_id,
        "--description", "updated description",
        "--json"
    ])
    if not ok or updated.get("desc") != "updated description":
        fail_with_data("Failed to update scope", updated)

    # Get by ID
    ok, fetched = run_mad([
        "scope", "get",
        "--id", scope_id,
        "--json"
    ])
    if not ok or fetched["id"] != scope_id:
        fail_with_data("Failed to fetch scope by id", fetched)

    # Assign to user
    ok, result = run_mad([
        "scope", "assign-to-user",
        "--user-id", user_id,
        "--scope-id", scope_id,
        "--json"
    ])
    if not ok or not result.get("success", False):
        fail_with_data("Failed to assign scope to user", result)

    # List scopes for user
    ok, scopes = run_mad([
        "scope", "list-for-user",
        "--user-id", user_id,
        "--json"
    ])
    if not ok:
        fail_with_data("Failed to list scopes for user", scopes)

    if not any(s.get("id") == scope_id for s in scopes):
        fail_with_data("Assigned scope not found in user's scopes", scopes)
