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
