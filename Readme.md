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
DATABASE_URL="sqlite:./db/sqlite.db"
ORIGIN_SERVER="http://localhost:3000"

GOOGLE_OAUTH2_CLIENT_ID="xxxxxx-yyyyyy.apps.googleusercontent.com"
```

## run app

```text
cargo watch -x run
```

OpenAPI doc

```text
http://localhost:3000/docs
```
