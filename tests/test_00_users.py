import json
import os
import pytest
from random import randint
from mad_testlib import run_mad

TRACK_FILE = "test_state.json"

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

def test_create_update_query_user():
    username = f"testuser_{randint(10000, 99999)}"
    email = f"{username}@example.com"
    password = "testpass123"

    # CREATE
    ok, user = run_mad([
        "user", "create",
        "--username", username,
        "--user-email", email,
        "--user-password", password
    ])
    if not ok:
        fail_with_data("User creation failed", user)

    if user.get("username") != username:
        fail_with_data("Username mismatch after creation", user)
    if user.get("email") != email:
        fail_with_data("Email mismatch after creation", user)
    if not user.get("is_active", False):
        fail_with_data("User is not active after creation", user)
    if "id" not in user:
        fail_with_data("User ID missing after creation", user)

    user_id = user["id"]
    save_state("user", user)

    # UPDATE
    new_email = f"{username}@updated.example.com"
    ok, updated = run_mad([
        "user", "update",
        "--id", user_id,
        "--email", new_email
    ])
    if not ok:
        fail_with_data("User update failed", updated)
    if updated.get("email") != new_email:
        fail_with_data("Email was not updated correctly", updated)

    # GET
    ok, retrieved = run_mad([
        "user", "get",
        "--id", user_id
    ])
    if not ok:
        fail_with_data("Failed to get user by ID", retrieved)
    if retrieved.get("email") != new_email:
        fail_with_data("Retrieved user does not reflect updated email", retrieved)

    # LIST
    ok, users = run_mad(["user", "list"])
    if not ok:
        fail_with_data("Failed to list users", users)
    if not any(u.get("id") == user_id for u in users):
        fail_with_data("Created user not found in list", users)
