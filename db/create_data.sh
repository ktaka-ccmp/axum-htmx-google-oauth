#!/bin/bash

source .env

## Data DB

DB=db/data.db
MIGRATION=db/migrations

echo sqlx migrate revert --source $MIGRATION --database-url sqlite:$DB
sqlx migrate revert --source $MIGRATION --database-url sqlite:$DB
echo sqlx migrate run --source $MIGRATION --database-url sqlite:$DB
sqlx migrate run --source $MIGRATION --database-url sqlite:$DB


echo "Customer:"
echo "select * from customer" | sqlite3 $DB | tail

echo "Users:"
echo "select * from user" | sqlite3 $DB


## Cache DB

pwgen(){
    basenc --base64url < /dev/urandom | head -c 64 ; echo
}

email=${ADMIN_EMAIL}
ssid=$(pwgen)
csrf_token=$(pwgen)

DB=db/cache.db
MIGRATION=db/migrations_cache

echo sqlx migrate revert --source $MIGRATION --database-url sqlite:$DB
sqlx migrate revert --source $MIGRATION --database-url sqlite:$DB
echo sqlx migrate run --source $MIGRATION --database-url sqlite:$DB
sqlx migrate run --source $MIGRATION --database-url sqlite:$DB

echo "insert or replace into sessions (id, session_id,user_id,email,csrf_token) values (1, '$ssid', 1, '$email', '$csrf_token')" | sqlite3 $DB
echo "Sessions:"
echo "select * from sessions" | sqlite3 $DB

if [ "$CACHE_STORE" == "redis" ]; then
    reds_cmd="redis-cli -h $REDIS_HOST -p $REDIS_PORT"

    # Clean up existing sessions
    $reds_cmd keys "*"| xargs -i $reds_cmd del {}

    # Create admin session
    # session_data="{session_id: $ssid, csrf_token: $csrf_token, user_id: 1, email: $email}"
    session_data="{\"session_id\": \"$ssid\", \"csrf_token\": \"$csrf_token\", \"user_id\": \"1\", \"email\": \"$email\"}"
    echo $reds_cmd set session:$ssid \"$session_data\"
    $reds_cmd set session:$ssid "$session_data"
fi
