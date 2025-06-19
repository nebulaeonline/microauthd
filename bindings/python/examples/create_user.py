import sys
import os

# Add the parent dir of 'microauthd' to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from microauthd.client import AdminClient
from microauthd.models import UserObject, TokenResponse

ADMIN_URL = "http://localhost:9041"
AUTH_URL = "http://localhost:9040"

admin_username = "admin"
admin_password = "your_admin_password"
client_identifier = "admin"  # or whatever you used during oobe

# Create a client
client = AdminClient.login_admin(ADMIN_URL, admin_username, admin_password, client_identifier)

# Test: Create user
user = client.create_user("api_test", "api_test@example.com", "supersecret")
print(f"Created user: {user.username} ({user.id})")

# Test: Issue token
token = client.issue_token_password("api_test", "supersecret", "app")
print("Access token:", token.access_token)

# Test: Admin introspect
print("Admin introspect result:", client.introspect_token_admin(token.access_token))

# Test: Delete user
client.delete_user(user.id)
print("User deleted")