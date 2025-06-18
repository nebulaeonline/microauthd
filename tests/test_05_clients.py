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

def test_create_update_scope_assign_client():
    state = load_state()
    scope = state.get("scope")
    assert scope and scope.get("id"), "Scope missing from test_state.json"

    client_id = f"client_{randint(10000,99999)}"
    client_secret = f"secret_{randint(100000,999999)}"

    # Create
    ok, client = run_mad([
        "client", "create",
        "--client-id", client_id,
        "--secret", client_secret,
        "--display-name", "Test Client",
        "--audience", client_id,
        "--json"
    ])
    if not ok or "id" not in client:
        fail_with_data("Failed to create client", client)

    cid = client["id"]
    client["client_secret"] = client_secret
    save_state("client", client)

    # Update
    ok, updated = run_mad([
        "client", "update",
        "--id", cid,
        "--display-name", "Test Client (updated)",
        "--json"
    ])
    if not ok or not updated.get("display_name", "").endswith("(updated)"):
        fail_with_data("Client update failed or name not updated", updated)

    # Get
    ok, fetched = run_mad([
        "client", "get",
        "--id", cid,
        "--json"
    ])
    if not ok or fetched["id"] != cid:
        fail_with_data("Client fetch by ID failed", fetched)

    # Assign scope
    ok, result = run_mad([
        "scope", "assign-to-client",
        "--client-id", cid,
        "--scope-id", scope["id"],
        "--json"
    ])
    if not ok or not result.get("success", False):
        fail_with_data("Failed to assign scope to client", result)

    # List scopes
    ok, scopes = run_mad([
        "scope", "list-for-client",
        "--client-id", cid,
        "--json"
    ])
    if not ok:
        fail_with_data("Failed to list scopes for client", scopes)

    if not any(s.get("id") == scope["id"] for s in scopes):
        fail_with_data("Assigned scope not found in client's scope list", scopes)
