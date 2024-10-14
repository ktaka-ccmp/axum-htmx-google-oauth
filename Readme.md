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
DATABASE_URL="sqlite:./db/data.db"
# CACHE_STORE="db" # db or redis 
CACHE_STORE="redis" # db or redis 
CACHE_DB_URL="sqlite:./db/cache.db"
CACHE_REDIS_URL="redis://localhost:6379/"

#ORIGIN_SERVER="http://localhost:3000"
ORIGIN_SERVER="https://ff36-217-178-145-231.ngrok-free.app"

GOOGLE_OAUTH2_CLIENT_ID="xxxxxx-yyyyyy.apps.googleusercontent.com"
GOOGLE_OAUTH2_CLIENT_SECRET="client_secret_taken_from_google_console"

NONCE_SALT="xxxxxxxxxxxx"
ADMIN_EMAIL=admin@example.com

SESSION_COOKIE_MAX_AGE=180
CSRF_COOKIE_MAX_AGE=20
NONCE_COOKIE_MAX_AGE=20

OAUTH2_RESPONSE_MODE="form_post" #form_post or query
OAUTH2_SCOPE="openid+email+profile"
```

## run app

```text
cargo watch -x run
```

OpenAPI doc

```text
http://localhost:3000/docs
```

## (Optional) Redis for Session Storage

Run redis

```
docker compose -f db/docker-compose.yml up -d
```

Edit .env file

```
# CACHE_STORE=sql
CACHE_STORE=redis
```

re-create a session for admin login
```
./db/create_data.sh
```

## (Optional) Monitor Session storage contents

### SQLite

```
watch -n 1 'echo "select * from sessions" | sqlite3 data/cache.db'
```

### Redis

If the OS has redis-cli, use the following;

```
watch -n 1  'for k in $(redis-cli keys "*" | xargs) ; do echo -n $k": " ; redis-cli get $k|xargs ; done'
```

If the OS does not have redis-cli, first exec into the redis docker container,

```
$ docker ps
CONTAINER ID   IMAGE     COMMAND                  CREATED      STATUS      PORTS                                       NAMES
29a78e16ec02   redis     "docker-entrypoint.s…"   7 days ago   Up 7 days   0.0.0.0:6379->6379/tcp, :::6379->6379/tcp   data-redis-1

$ docker exec -it data-redis-1 bash
```

then monitor the contents using redis-cli, for example;

```
while true ; do sleep 1 ;clear; for k in $(redis-cli keys "*" | xargs) ; do echo -n $k": " ; redis-cli get $k|xargs ;done ; done
```
