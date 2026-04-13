# SQL Injection in Go — Intentional Vulnerability Demo

This project is a deliberately vulnerable Go application used to demonstrate how SQL injection happens in practice and how to fix it. Original write-up: [wiliamvj.com/posts/sql-injection-golang](https://wiliamvj.com/posts/sql-injection-golang).

## Running

```bash
docker compose up -d
go run cmd/main.go
```

The server exposes four endpoints (see `cmd/main.go`):

- `GET /users?id=...` — **vulnerable**
- `DELETE /users?id=...` — **vulnerable**
- `GET /users/correct?id=...` — safe
- `DELETE /users/correct?id=...` — safe

## The vulnerability

The `id` query parameter is concatenated directly into the SQL string with `fmt.Sprintf`, so an attacker controls part of the query and can change its meaning.

**Location:** `internal/service/user_service.go:16` and `internal/service/user_service.go:56`

```go
// GetUserInject — vulnerable
query := fmt.Sprintf("SELECT id, name, email FROM users WHERE id = %s", id)
rows, err := database.DBConnection.Query(query)

// DeleteUserInject — vulnerable
query := fmt.Sprintf("DELETE FROM users WHERE id = %s", id)
_, err := database.DBConnection.Exec(query)
```

### Exploiting it

Dump every user by turning the `WHERE` clause into a tautology:

```bash
curl "http://localhost:8080/users?id=1%20OR%201=1"
# → SELECT id, name, email FROM users WHERE id = 1 OR 1=1
```

Wipe the whole table through the delete endpoint:

```bash
curl -X DELETE "http://localhost:8080/users?id=1%20OR%201=1"
# → DELETE FROM users WHERE id = 1 OR 1=1
```

Because the input is never validated or escaped, anything the attacker types becomes SQL.

## The fix — parameterized queries

Let the database driver bind the value instead of splicing it into the string. Placeholders (`$1` for `lib/pq`) make the driver send the value as a parameter, so it can never be parsed as SQL.

**Location:** `internal/service/user_service.go:36` and `internal/service/user_service.go:66`

```go
// GetUserCorrect — safe
query := "SELECT id, name, email FROM users WHERE id = $1"
rows, err := database.DBConnection.Query(query, id)

// DeleteUserCorrect — safe
query := "DELETE FROM users WHERE id = $1"
_, err := database.DBConnection.Exec(query, id)
```

Now the same payload is treated as a literal value:

```bash
curl "http://localhost:8080/users/correct?id=1%20OR%201=1"
# → error: invalid input syntax for type integer
```

### Rule of thumb

- Never build SQL with `fmt.Sprintf`, `+`, or any kind of string concatenation when user input is involved.
- Always pass user input as query arguments (`db.Query(sql, arg1, arg2, ...)`).
- Use placeholders matching your driver: `$1, $2...` for PostgreSQL (`lib/pq`, `pgx`), `?` for MySQL/SQLite.
- Identifiers (table/column names) cannot be parameterized — validate them against an allow-list if they must be dynamic.
