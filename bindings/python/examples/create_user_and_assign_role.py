import sys
import os

# Add the parent dir of 'microauthd' to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from python.microauthd.admin_client import AdminClient

client = AdminClient.login_admin("http://localhost:9041", "admin", "adminpass")

# Create user
user = client.create_user("alice", "alice@example.com", "password123")
print(f"Created user: {user.username} ({user.id})")

# Create role
role = client.create_role("auditor", "Can view reports")
print(f"Created role: {role.name} ({role.id})")

# Assign role
success = client.assign_role_to_user(user.id, role.id)
print("Role assigned" if success else "Failed to assign role")