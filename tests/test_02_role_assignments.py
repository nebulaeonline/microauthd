import json
import pytest
from mad_testlib import run_mad

def load_state():
    with open("test_state.json") as f:
        return json.load(f)

def fail_with_data(message, data):
    pytest.fail(f"{message}\nFull response:\n{json.dumps(data, indent=2)}")

def test_role_assign_and_unassign_user():
    state = load_state()
    user = state.get("user")
    role = state.get("role")

    assert user is not None, "User not found in test_state.json"
    assert role is not None, "Role not found in test_state.json"

    user_id = user["id"]
    role_id = role["id"]

    # Assign role
    ok, response = run_mad([
        "role", "assign",
        "--user-id", user_id,
        "--role-id", role_id,
        "--json"
    ], expect_json=True, fail_ok=False)

    if not ok:
        fail_with_data("Failed to assign role to user", response)

    if not response.get("success", False):
        fail_with_data("Assign role did not return success=true", response)

# we let the role persist for the next test
