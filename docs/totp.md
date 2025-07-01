# microauthd
---
## Time Based One Time Pad (TOTP)
---

#### Introduction

Time based one time pad (TOTP) authentication is used from apps like Google Authenticator, Microsoft Authenticator, Authy, 1Password, among others. It operates via a secret code that is shared at the outset of using the TOTP service, and is used to generate time-based codes that are good for 30 seconds at a time. This is generally used as the second factor in a multi-factor authentication (MFA) login flow.

#### How It Works in microauthd

An ADMIN authenticated call is made to `/users/{userId}/totp/generate` with a `totp_qr_request`. This request is a JSON object with two fields: `user_id` and `qr_output_path`. Yes, the user_id appears in both the URL and the body — this may be streamlined in the future. Needless to say, you just pass to it the user that wants MFA and instruct microauthd where you want the QR code .svg saved. If successful, the api will respond with a `TotpQrResponse` object, which contains a `success` field and a `filename` field. The response will contain `success: true` and a filename string — a randomized .svg filename containing the QR code (e.g., `totp_qr_a1b2c3.svg`). The full file path can be constructed using your provided `qr_output_path` (the response contains only the filename; no path).

After the QR code is scanned by the user's TOTP app (such as Google Authenticator), the app will begin generating time-based 6-digit codes. To verify the pairing, make a request to the `/users/totp/verify` ADMIN endpoint with a `VerifyTotpRequest` json object, which has two fields `user_id` and `code`. Assuming the code is correct for that period of time, TOTP will become active on the user's account. From that point forward they will need to submit a TOTP code along with their regular login credentials to obtain an access token.

We have added an endpoint to verify the user's username and password outside of the normal user/pass login flow. This endpoint is useful for progressive login flows: authenticate username/password first, then present the TOTP challenge only if `totp_required` is true. This "quick username/pass check" ADMIN endpoint is `/users/verify-password` which accepts a `VerifyPasswordRequest` (consisting of two fields: `username` and `password`), and returns a `VerifyPasswordReponse` object which contains the following fields: `valid` (true/false), `user_id` the user's GUID, `email` which contains the user's email address, and `totp_required` (true/false) which will tell you if this user has TOTP enabled on their account.

There is also an endpoint to disable totp for any given user, `/users/{userId}/disable-totp`, this is a GET endpoint that does not require a request body. Calling this endpoint will disable TOTP MFA for the specified user id.

#### Commentary

The system is pretty nifty. I know it sounds complicated, but you should have admin bindings and the request objects should be there too in your language of choice. Once you have those bindings, it's just basically hitting an endpoint to enable with an output path, then combining that output path with the filename returned and showing that image to your user. It's designed to be as painless as possible for you to integrate into your login flow. If you have any suggestions for improvements or discover any errors, please let us know.