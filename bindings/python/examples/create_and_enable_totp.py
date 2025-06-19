from microauthd.client import AdminClient

client = AdminClient.login_admin("http://localhost:9041", "admin", "adminpass")

user_id = "your-user-id-here"

# Generate QR code svg for TOTP
qr = client.generate_totp_for_user(user_id, "/path/to/save/qr_code/to")
print("QR code written to:", qr.qr_code_filename) # back end responds with partially random filename for QR code svg

# Prompt for code
code = input("Enter the 6-digit TOTP code: ").strip()

# Enable TOTP
success = client.verify_totp_code(user_id, code)
print("TOTP verified" if success else "TOTP verification failed")