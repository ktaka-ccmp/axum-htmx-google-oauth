# Readme

## prep

### prep DB

```text
cd db/
sqlx database create --database-url "sqlite:./sqlite.db"
sqlx migrate add -r customer
vi migrations/20240701161707_customer.udp.sql
vi migrations/20240701161707_customer.down.sql
sqlx migrate run --database-url sqlite:./sqlite.db
#sqlx migrate revert --database-url sqlite:./sqlite.db
#sqlx migrate run --database-url sqlite:./sqlite.db
```

Add user table
```text
cd db/
sqlx migrate add -r user
vi migrations/20240819135742_user.down.sql
vi migrations/20240819135742_user.up.sql
sqlx migrate revert --database-url sqlite:./sqlite.db
sqlx migrate run --database-url sqlite:./sqlite.db
```

`./db/create_data.sh`

### Contents of migration files

xxxx_customer.up.sql

```sql
CREATE TABLE IF NOT EXISTS customer (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL
);

-- Generate a sequence of numbers from 1 to 80
WITH RECURSIVE numbers AS (
  SELECT 1 AS num
  UNION ALL
  SELECT num + 1
  FROM numbers
  WHERE num < 80
)

-- Insert the generated sequence into the customer table
INSERT INTO customer (name, email)
SELECT
  printf('a%03d', num) AS name,
  printf('a%03d@example.com', num) AS email
FROM numbers;
```

xxxx_customer.down.sql

```sql
DROP TABLE customer;
```

### Add dependency

```text
cargo add axum dotenv serde thiserror tracing tracing-subscriber schemars infer
cargo add tokio --features=full
cargo add tower-http --features=trace,fs
cargo add sqlx --features sqlite,runtime-tokio-rustls
cargo add aide --features=axum,scalar,axum-extra-query,axum-headers
cargo add askama_axum
```

### Prepare .env

```text
$ cat .env 
#ORIGIN_SERVER="http://localhost:3000"
ORIGIN_SERVER="https://ff36-217-178-145-231.ngrok-free.app"

DATABASE_URL="sqlite:./db/data.db"
CACHE_STORE="db" # db or redis
CACHE_DB_URL="sqlite:./db/cache.db"
CACHE_REDIS_URL=""

GOOGLE_OAUTH2_CLIENT_ID="xxxxxx-yyyyyy.apps.googleusercontent.com"

SESSION_MAX_AGE=180
NONCE_SALT="xxxxxxxxxxxx"
ADMIN_EMAIL=admin@example.com
```

## run app

```text
cargo watch -x run
```

OpenAPI doc

```text
http://localhost:3000/docs
```
