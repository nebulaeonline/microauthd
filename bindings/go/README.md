# microauthd-go

Go client for microauthd's authentication and admin APIs.

## Usage

```go
import "microauthd"

auth, err := microauthd.NewAuthClient("http://localhost:9040", "user", "pass", "app")
if err != nil { ... }

me, err := auth.Me()

admin := microauthd.NewAdminClient("http://localhost:9041", auth.AccessToken)
user, err := admin.CreateUser("bob", "bobpass", "bob@example.com")
```