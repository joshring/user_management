# Readme


## Run the tests
```bash
docker compose up --build db
go test ./... -v
```

## Test coverage report
```bash
docker compose up --build db
go test -coverprofile=test_coverage.out ./...
go tool cover -html test_coverage.out -o test_coverage.html
open test_coverage.html
```
Note: `authMiddleware` rejection of unauthorised users is tested via `TestGetUserUnauthorised` and acceptance of authorised user via: `TestGetUser`

## Start the API and postgres database
```bash
docker compose down
docker compose up --build
```

## Language, libraries, storage etc
- Using Golang
- Go standard library
- For password hashing using `argon2id` as it's resistant to sidechannel attacks and won competitions for resilience.
- UUID for public facing ids as unpredictable
- Using `require` assertion testing library to simplify test code
- Using `postgres` as has many helpful features.
- Using `pgx` postgres driver as best currently maintained postgres driver, supports query timeouts via context so overly large queries cannot eat database resources too long.


## Code structure
```bash
.
├── api_example
├── database
│   └── schema.sql
├── dev.Dockerfile
├── docker-compose.yml
├── go.mod
├── go.sum
├── internal
│   ├── apiroutes
│   │   ├── apiroutes.go
│   │   └── middleware.go
│   ├── apiutil
│   │   └── apiutil.go
│   ├── database
│   │   └── database.go
│   ├── model
│   │   └── errors.go
│   ├── server
│   │   └── server.go
│   ├── testutil
│   │   ├── database.go
│   │   ├── response.go
│   │   ├── server.go
│   │   └── time.go
│   └── user
│       ├── user.go
│       └── user_test.go
├── main.go
└── README.md
```

- Database schema is in database/schema.sql
- Code is within the `internal` directory
- Packages within `internal` are organised into packages by their purpose as follows:

| Package      | Summary |
|--------------|----------|
| apiroutes    | Setup API router and middleware for request logging, handling panics and handling authorisation via sessions |
| apiutil      | Getting userID from request context |
| database     | Connecting to database, starting database transactions |
| server       | Starting API server in a deployment |
| testutil     | Utilities used for testing, starting db connections, checking HTTP responses, starting API servers for testing, time function for deterministic time |
| user         | PostUser, PostLogin, GetUser API handlers and their tests |


## Postgres Tables

```sql
create table if not exists "user" (
    "id"                    serial primary key,
    "public_id"             varchar not null,
    "name"                  varchar not null,
    "email"                 varchar not null,
    "password_hashed"       varchar not null,
    "created_at"            timestamp not null,
    "num_login_attempts"    int not null default 0,
    unique("public_id"),
    unique("email")
);

create table if not exists "session" (
    "id"             serial primary key,
    "public_id"      varchar not null,
    "csrf_token"     varchar not null,
    "user_id"        int references "user"("id") on delete cascade,
    "created_at"     timestamp not null,
    "expires_at"     timestamp not null,
    unique("public_id"),
    unique("user_id", "created_at")
);
```
## Design notes

### `POST /login`
- When a user is registered via `POST /user` they are added to the `user` table
- When a user logs in via `POST /login` a cookie is saved with the following attributes:
    - `Secure` (HTTPS only)
    - `Samesite=Strict` (restricts to the same domain, helps prevent CSRF)
    - `HttpOnly` (inaccessible from Javascript)
- When a user logs in via `POST /login` a `csrf_token` is returned to the user via the request body and saved in the `session` table. This helps bind the session to the client making it harder to steal the user's session as they would need to steal the user's cookie by intercepting a user's request (man-in-the-middle) and have arbitrary local javascript execution on the user client (cross site scripting). The client can store `csrf_token` via local storage for persistence.
- When a user fails to `POST /login` successfully, the `user.num_login_attempts` is incremented, and if this gets greater than 10 the user will be unable to login.
- When a user has less than 10 failed attempts, but has a successful `POST /login` their `user.num_login_attempts` is reset to zero once again.

#### Timing attack mitigations
```go
// Prevent timing attacks (to find if a user already exists) using a random sleep
defer func() {
    time.Sleep(time.Duration(rand.IntN(500)) * time.Millisecond)
}()
```
- Where a function can exit early because a user was not found vs a user was found for instance, we add a deferred random wait to the function so that it is more difficult to observe a difference in function runtime and use that to infer different execution paths. 

### Authorisation
#### Requests are authorised by:
- Setting a `csrf_token` request header with the `csrf_token` value returned from the body of the response from `POST /login`. The client can then store this in the client's local storage and add when making an authorised request.
- The `session` cookie is sent, which was set on the client from the `POST /login`
- The `authMiddleware` wraps an endpoint requiring authorisation, and checks `csrf_token` and the `session` cookie are valid and match the values in the `session` table. Then it returns the corresponding `user.id` which is set into the request context and made available for API handlers.
- `GetUserIDFromReq` is a convenience function for retrieving the `user.id` from the request context used from API handlers.
     



### Table `public_id`
- All tables have internal `id` for quick joins and externally facing `public_id` for when the client needs to reference a record. Used UUID V4 to make the `public_id` unpredictable so it cannot be guessed, like an incremental id can be easily guessed.

### Table constraints and default values
- There are unique constraints to prevent duplicate `user.email` and `session.user_id and session.created_at` combinations and all `public_id` must be unique per table.
- `not null` constraints help prevent null values where we always expect a value.
- Minimal use of default values makes the table more predictable how it will be used, with the exception of `user.num_login_attempts` which seems strange to set on user insert.

### Dependency injection

```go
// PostLogin handles POST /login
//
// Dependency inject dbConn and timeFunc
func PostLogin(
    dbConn *pgx.Conn,
    timeFunc func() time.Time,
) http.HandlerFunc {

    return func(w http.ResponseWriter, r *http.Request) {
        // Handler code here
    }
}
```
- This adds these variables into the returned handler, so the handler can maintain the same function arguments, but gain the additional variables we wish to give it. This is in contrast to using a centralised object to hold all of the state. The advantage is we know exactly which parts of that state need to be provided, and are needed for each handler, which communicates to the developer about how to test the function just from it's signature.
- For example time is a variable we control for by adding a `timeFunc` argument to a function, this means we can fix time in testing for deterministic results, or replace that with `time.Now` in production.


### Database Transactions
```go
err := database.StartTransaction(dbConn, ctx, func(tx pgx.Tx) error {
    // database transaction here
})
```
- To prevent cross-request database side effects on in progress requests, made heavy use of database transactions.
- In the event of a panic or error the transaction is rolled back and no persistent changes are made to the database.




## Future work

### Test with frontend
- Cookies will need to be tweaked depending on the domains of the deployment, eg it needs to work across multiple domains

### CORS
- CORS via https://github.com/rs/cors

### Signup improvements
- Setup an email service 
- Require email verification for new user signups, new users are created with their status as deactivated prior to this.
- Deactivated users are not allowed to `POST /login`

### Login improvements
- Two factor authentication via an authenticator app or email.
- Investigate regulatory requirements and implement recommendations.

### Password reset
- Password reset for activated users, sent via email

### Account removal
- Account removal for activated accounts, so we can comply with GDPR's "right to be forgotten".
