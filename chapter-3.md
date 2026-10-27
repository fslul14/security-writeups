# Chapter 3: Growing the Lab, File Upload, Command Injection, and CSRF

## Where this picks up

Chapter 2 rebuilt the lab in Docker, put an nginx reverse proxy in front of Juice Shop to capture full request bodies, and re-ran the Chapter 1 attacks (SQL injection auth bypass, IDOR) against that instrumented setup so the resulting traffic could be shipped to Splunk and turned into validated Sigma detections.

Chapter 3 keeps the same attack-then-detect structure but grows the lab itself: a second application, DVWA (Damn Vulnerable Web Application), standing alongside Juice Shop, and three new vulnerability classes that Juice Shop doesn't really demonstrate: unrestricted file upload, OS command injection, and CSRF.

The plan, decided up front: cover all three vulnerability classes at the same depth Chapter 1 covered its three (lighter, broad coverage rather than going deep on one), attack all three first, then write and validate Sigma rules for all three at the end, same order as Chapter 2's methodology. Attack order: file upload, then command injection, then CSRF, saving CSRF for last since it doesn't touch the server at all, it exploits something different.

## Growing the lab: adding DVWA

### Picking an image

DVWA has been dockerized many different ways over the years, and most of the top search results for "DVWA docker" point at images that are five, six, even nine years stale. The actual maintainers (digininja) now publish an official image straight from their own `master` branch to GitHub Container Registry (`ghcr.io/digininja/dvwa`), with their own `compose.yml` showing exactly what it needs: the app container plus a MariaDB container for its database. That's the one this chapter uses, current and straight from source, rather than a convenient but abandoned community image.

### Routing: separate port, not a shared path

The lab already had one nginx reverse proxy in front of Juice Shop, on port 80, with a custom log format capturing full request bodies (needed since attack payloads often live in POST bodies, not just URLs). Adding DVWA meant deciding how nginx should tell the two apps' traffic apart. Three real options existed: a different path (`/dvwa/`), a different hostname (virtual hosting), or a different port.

Path-based routing was ruled out because DVWA's own internal links assume it's served from the root, rewriting every absolute path and redirect to live under a `/dvwa/` prefix is exactly the kind of proxy-plumbing work that burns chapter time without teaching anything about the actual vulnerabilities. Hostname-based virtual hosting was ruled out too, since it would need `/etc/hosts` entries on the host machine for no real benefit in a single-machine lab. A second port, 8081, solved it cleanly: DVWA gets its own `server` block in the same nginx config, proxying to its own upstream, logging to its own file, with no rewriting needed at all.

The resulting `nginx/juice-shop.conf` (not renamed, even though it now covers more than Juice Shop):

```nginx
log_format detailed '$remote_addr - [$time_local] "$request" '
                     'status=$status body="$request_body" '
                     'referrer="$http_referer" ua="$http_user_agent"';

server {
    listen 80;
    server_name _;

    access_log /var/log/nginx/juice-shop-access.log detailed;
    error_log /var/log/nginx/juice-shop-error.log;

    location / {
        proxy_pass http://juice-shop:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 8081;
    server_name _;

    access_log /var/log/nginx/dvwa-access.log detailed;
    error_log /var/log/nginx/dvwa-error.log;

    location / {
        proxy_pass http://dvwa:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Worth noting on that `proxy_pass http://dvwa:80` line: nginx's `listen 8081` and the upstream's port have nothing to do with each other. `listen` is what a client connects to; `proxy_pass` is what the upstream app actually listens on inside its own container, over Docker's internal network. DVWA's own official compose file exposes it to a host machine as `4280:80`, host port 4280 mapped to container port 80, but since nginx reaches it internally rather than through the host, only the `80` (the container-internal side) matters here.

The `docker-compose.yml` additions: a new `dvwa` service and its own `dvwa-db` database container, plus the `8081` port added to `nginx-proxy`'s existing port list.

```yaml
  dvwa:
    image: ghcr.io/digininja/dvwa:latest
    container_name: dvwa
    networks: [labnet]
    environment:
      - DB_SERVER=dvwa-db
    depends_on: [dvwa-db]
    restart: unless-stopped

  dvwa-db:
    image: docker.io/library/mariadb:10
    container_name: dvwa-db
    networks: [labnet]
    environment:
      - MYSQL_ROOT_PASSWORD=dvwa
      - MYSQL_DATABASE=dvwa
      - MYSQL_USER=dvwa
      - MYSQL_PASSWORD=p@ssw0rd
    volumes:
      - dvwa-db-data:/var/lib/mysql
    restart: unless-stopped
```

Once DVWA was up and logged in (default credentials `admin` / `password`), the first real step was changing the security level from `Impossible` (DVWA's default, fully-patched reference implementation, intended to stop anyone who forgets to lower it from accidentally running a wide-open vulnerable app) down to `Low`, where all three target vulnerability classes are straightforwardly exploitable.

## Two debugging detours worth documenting

Both of the real problems in this chapter were the same mistake wearing different clothes: assuming a plausible default instead of verifying the real one. Worth writing up honestly, since this is exactly the kind of thing that eats an afternoon in real work too.

### Mismatched database credentials

The `dvwa-db` container above was first built with `MYSQL_PASSWORD=dvwa`, a guess, since the official compose snippet found during research got cut off mid-line before showing the actual password. DVWA's app code has its own hardcoded fallback credentials it falls back to when `DB_PASSWORD` isn't explicitly set on its own environment, and that fallback is `p@ssw0rd`, not `dvwa`. The mismatch surfaced immediately on first login attempt:

```
Fatal error: Uncaught mysqli_sql_exception: Access denied for user 'dvwa'@'172.18.0.6' (using password: YES)
```

The fix wasn't just editing the YAML, either. MariaDB's official image only runs its user-creation step once, on a completely empty data directory. The wrong password was already permanently baked into the database files sitting in the `dvwa-db-data` volume. The actual fix: stop and remove both containers, delete the stale volume, correct the password in the compose file, then bring just those two services back up so MariaDB could re-initialize from scratch with the right credentials.

### A Splunk monitor that silently never got added

The forwarder (`uf-target`) already had one working `SPLUNK_ADD` environment variable monitoring Juice Shop's access log from Chapter 2. Adding DVWA's log file looked like it just needed a second one, and some older Splunk Docker images do support exactly that pattern, numbered variables like `SPLUNK_ADD_1`, `SPLUNK_ADD_2`.

That pattern turned out to belong to a different, older image lineage with a custom entrypoint script, not the official `splunk/universalforwarder` image actually in use here, which runs on a newer Ansible-based provisioning layer. The numbered variable was silently ignored. Checking the forwarder's actual `inputs.conf` (after discovering it lives in `etc/apps/search/local/`, not the more obvious `etc/system/local/`, and that reading it required running `docker exec` as root rather than the default exec user) showed only the original Juice Shop monitor stanza. DVWA's traffic never reached Splunk at all, confirmed by nginx's own access log showing real, logged attack traffic that simply never showed up in a Splunk search.

The fix: skip the environment-variable layer entirely and call the same underlying Splunk CLI command directly, `splunk add monitor <path>`, the exact operation that variable was supposed to trigger. That came with its own permission wrinkle: Splunk's official image runs everything as a dedicated, unprivileged `splunk` user, and neither the default `docker exec` user nor `root` has the right ownership over Splunk's own files to run its CLI tooling cleanly. Running the command as `-u splunk` specifically is what actually worked:

```
docker exec -u splunk uf-target /opt/splunkforwarder/bin/splunk add monitor /var/log/nginx/dvwa-access.log -auth admin:ChangeThisPassword123!
```

Since this was a brand-new monitor stanza on a file Splunk had never tracked, it ingested the entire existing log from the start, not just new lines going forward, so the attacks already run before the fix still made it into Splunk once this landed.

## Attack 1: Unrestricted File Upload to Remote Code Execution

### The concept

An unrestricted file upload vulnerability isn't really about file size or generic "malware." The specific, severe version of this bug is: if a web application doesn't check what kind of file it's accepting, and a file written in a language the server itself can execute (PHP, on an Apache+PHP stack) ends up inside the web root, visiting that file's URL doesn't serve it as text, it runs it as code. Whoever controls that upload controls what executes on the server.

### What was done

DVWA's Upload module (`/vulnerabilities/upload/`) at Low security has no client-side restriction and no visible extension check anywhere on the page. Confirming that took an actual test rather than just reading the form: uploading a plain `test.txt` file succeeded and the response revealed exactly where uploads land:

```
../../hackable/uploads/test.txt succesfully uploaded!
```

That path, `hackable/uploads/`, sits inside the app's web root, meaning anything placed there is reachable by URL. The next test proved code execution, not just storage: uploading `test.php` containing

```php
<?php echo "test upload executed: " . (1+1); ?>
```

and then visiting `http://localhost:8081/hackable/uploads/test.php` directly returned `test upload executed: 2`, a computed result, not the raw source text a static file server would have returned. That's proof the server ran the code.

From there, escalating to a working webshell was one small step: a file containing

```php
<?php system($_GET['cmd']); ?>
```

uploaded the same way, then visited with a command appended to the URL:

```
http://localhost:8081/hackable/uploads/shell.php?cmd=whoami
```

returned `www-data`, the account Apache runs as on this container. Full, arbitrary remote code execution, triggered by nothing more than an upload form and a URL.

### Why it matters

No extension or content-type validation on an upload endpoint is one of the most severe web vulnerability classes that exists, because the impact isn't limited to the application itself. Anything the web server process can reach (other files, internal network access, further pivoting) is now reachable too. `www-data` isn't root, but it's a genuine foothold, not a theoretical one.

### How it's actually fixed

The dependable fix is layered, not a single check: validate the file's actual content (checking magic bytes or using a proper image/file-type library, not trusting the client-supplied `Content-Type` header, which is trivially forged), enforce a strict allowlist of permitted extensions rather than a denylist, store uploaded files outside the web root entirely (or in a location explicitly configured to never execute scripts, regardless of extension), and rename uploaded files to randomly generated names so an attacker can't predict or control the resulting URL even in a partial bypass.

## Attack 2: OS Command Injection

### The concept

Command injection happens when user input reaches a shell command without being sanitized or properly escaped. If an application builds a shell command by directly concatenating user input into it, shell metacharacters, `&&`, `;`, `|`, let an attacker chain on an entirely separate command of their own choosing.

### What was done

DVWA's Command Injection module (`/vulnerabilities/exec/`) presents a simple ping utility: enter an IP address, the app runs `ping` against it. At Low security it does this by pasting the input straight into a shell command with no sanitization. Entering

```
127.0.0.1 && whoami
```

instead of a plain IP address produced exactly what that implies, normal `ping` output followed by a second, injected command's output:

```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=5.46 ms
...
--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3032ms
rtt min/avg/max/mdev = 0.044/1.416/5.459/2.334 ms
www-data
```

The `&&` operator told the shell "run the next command too, if the first succeeded," and since the app never validated that its input was actually just an IP address, it had no way to tell the difference between a destination to ping and a second command riding along with it.

### Why it matters

This is the same underlying failure as the file upload bug, input reaching something the server executes with no validation in between, just through a different surface: a form field instead of a file. Same account (`www-data`), same severity, different entry point. That repetition is worth noticing: a lot of distinct-sounding vulnerability classes trace back to one shared root cause.

### How it's actually fixed

The real fix is avoiding string-built shell commands entirely wherever possible, using language-level APIs that take arguments as a proper list rather than a single interpolated string (so there's no shell metacharacter interpretation to exploit in the first place). Where a shell call genuinely can't be avoided, strict allowlisting of expected input format (for an IP address, actually validating it's a well-formed IP, not just checking for the absence of a few blocked characters) and refusing anything that doesn't match closes the gap. Denylisting specific "dangerous" characters is a weak defense on its own, since there are usually more ways to chain shell commands than any denylist anticipates.

## Attack 3: Cross-Site Request Forgery (CSRF)

### The concept

CSRF is a different shape of problem than the first two. It doesn't exploit the server directly, no injected code, no malformed input tricking a parser. It exploits trust between a victim's browser and an already-authenticated session. If an application performs a state-changing action (like changing a password) based solely on a valid session cookie, with nothing checking that the request genuinely originated from the app's own form and reflects the user's actual intent, then anything that gets a logged-in victim's browser to send that request, a crafted link, an embedded image tag on an unrelated page, a hidden auto-submitting form, can trigger the action without the victim ever knowing.

### What was done

DVWA's CSRF module lives in its Change Password form (`/vulnerabilities/csrf/`), and the flaw is almost deliberately blunt: the password change isn't just missing a CSRF token, it accepts the change via a plain `GET` request, built entirely from the same two field names the form itself uses:

```
http://localhost:8081/vulnerabilities/csrf/?password_new=hacked123&password_conf=hacked123&Change=Change
```

In a real attack, a victim's browser would send this automatically the moment it loaded that URL from anywhere, an image tag, a phishing link, while still holding a valid DVWA session cookie, since browsers attach cookies based on the destination domain, not the page that triggered the request. In this lab, attacker and victim are the same single session, so the test was simply visiting that URL directly. Confirmation came by logging out and back in with the new password instead of the original:

```
username=admin&password=hacked123&Login=Login
```

successful login, confirming the password had in fact changed with nothing more than a URL visit.

### Why it matters

The severity here isn't about a clever payload, it's about the complete absence of verification that a state-changing request actually reflects the account owner's intent. Any authenticated action with real consequences (changing a password, transferring funds, modifying account settings) is a CSRF target if the only thing protecting it is "the browser has a valid cookie."

### How it's actually fixed

The standard defense is an anti-CSRF token: a random, unpredictable value embedded in the legitimate form and required on submission, which an attacker crafting a URL or a foreign form has no way to know or guess. Pairing that with the `SameSite` cookie attribute (set to `Lax` or `Strict`) stops a browser from attaching the session cookie to a cross-origin request in the first place, a second independent layer. And state-changing actions should never be exposed via plain `GET` requests at all, regardless of token presence, since `GET` requests are exactly the kind a browser will load automatically and unprompted (an image tag, a prefetch, a link preview).

## Detection: writing and validating Sigma rules

With the forwarding pipeline fixed and all three attacks generating real telemetry in `dvwa-access.log`, the next step was writing a Sigma rule for each vulnerability class and converting it to SPL to validate against that captured data, the same attack-then-detect approach as Chapter 2.

### Rule 1: web-executable file upload

```yaml
title: Web-Executable File Upload to DVWA Upload Endpoint
logsource:
  category: webserver
detection:
  selection:
    url|contains: '/vulnerabilities/upload/'
    body|contains: 'filename='
    body|re: '.*filename=".*\.php.*"'
  condition: selection
level: high
```

SPL:
```
source="*dvwa-access.log*" "POST /vulnerabilities/upload/" body="*filename=*.php*"
```

### Rule 2: shell metacharacters in the command injection field

```yaml
title: Shell Metacharacter Injection in DVWA Exec Module
logsource:
  category: webserver
detection:
  selection:
    url|contains: '/vulnerabilities/exec/'
    ip|contains:
      - '%26%26'
      - '%3B'
      - '%7C'
  condition: selection
level: high
```

SPL:
```
source="*dvwa-access.log*" "POST /vulnerabilities/exec/" (ip="*%26%26*" OR ip="*%3B*" OR ip="*%7C*")
```

### Rule 3: password change via unauthenticated-style GET

```yaml
title: DVWA Password Change via Unauthenticated-Style GET Request
logsource:
  category: webserver
detection:
  selection:
    raw|contains: 'GET /vulnerabilities/csrf/?password_new='
  condition: selection
level: medium
```

SPL:
```
source="*dvwa-access.log*" "GET /vulnerabilities/csrf/?password_new="
```

This third rule deliberately anchors on the raw request line rather than Splunk's automatically extracted `password_new` field. Splunk's field extraction picks up key-value pairs wherever they appear in an event, including inside the `referrer` field of later, unrelated requests that simply happened to link back to the CSRF URL. Matching the actual request line avoids false matches from that extraction quirk, a small but real lesson about not trusting auto-extracted fields blindly when building detection logic.

### Validation results

Running all three searches against the captured telemetry:

| Rule | Hits | Expected |
|---|---|---|
| File upload (`.php` extension) | 2 | 2 (`test.php` and `shell.php`; correctly excludes `test.txt`) |
| Command injection (shell metacharacters) | 1 | 1 (the single `&&whoami` request) |
| CSRF (password change via GET) | 1 | 1 (the single crafted URL visit) |

Four total events, matching every attack performed in this chapter exactly, with zero false positives and zero misses. All three rules were saved as Splunk reports for reuse.

## Wrap-up

Three different-sounding vulnerability classes, and two of the three (file upload, command injection) trace back to the identical root cause: user-controlled input reaching something the server executes, with no validation in between. CSRF is a different failure mode, trust in a session cookie standing in for verified user intent, but shares the same underlying lesson: never assume a request means what it appears to mean just because it arrived with valid credentials attached.

The debugging detours turned out to be as worth documenting as the attacks themselves. Both real problems in this chapter came from the same habit: filling a gap in available information with a plausible-sounding guess instead of verifying it. A guessed database password and an assumed environment-variable convention from the wrong image lineage both cost real debugging time, and both were fixed the same way, going back to the actual, verified source instead of trusting what seemed reasonable.
