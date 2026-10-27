# Chapter 2: Attack It, Then Catch It

In Chapter 1 I broke into a vulnerable web app and wrote up what I found. That's the easy
half of the story. The harder, more useful half is what happens next: can you actually see
yourself doing it? I work SOC 2 audits and GRC day to day, not incident response, but
detection is the piece that makes offensive work matter to a blue team, so this chapter is
about closing that loop. I re-ran two of Chapter 1's attacks against an instrumented version
of the same lab, captured real telemetry, and wrote the Sigma rules and SPL queries that
would catch each one.

## Lab architecture

Chapter 1 ran on three VirtualBox VMs with a manually built isolated network. For Chapter 2
I rebuilt the whole thing as four Docker containers on a dedicated bridge network, nginx
in front of Juice Shop as a reverse proxy, a Splunk indexer, and a Universal Forwarder
shipping logs between them:

- **juice-shop** - the same vulnerable app from Chapter 1
- **nginx-proxy** - reverse proxy in front of it, configured to log full request bodies,
  not just the request line, since the interesting part of a SQL injection attack lives
  in the POST body, not the URL
- **splunk-siem** - the indexer, receiving on port 9997
- **uf-target** - a Universal Forwarder watching nginx's access log and shipping it to
  the indexer

The nginx log format:

```nginx
log_format detailed '$remote_addr - [$time_local] "$request" '
                     'status=$status body="$request_body" '
                     'referrer="$http_referer" ua="$http_user_agent"';
```

That `$request_body` variable is the whole point. nginx's default log format only
captures the request line and status code, nothing in the body. Without this, the SQL
injection payload sitting in a login POST would be invisible to any log-based detection,
no matter how good the Sigma rule.

## Re-running the attacks

### SQL injection, authentication bypass

Same payload as Chapter 1, sent directly as a POST body this time instead of through
Burp's Repeater:

```bash
curl -s -X POST http://127.0.0.1/rest/user/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"' or 1=1--\",\"password\":\"x\"}"
```

Logged in as `admin@juice-sh.op` with no valid password, same unsanitized SQL
concatenation as before. The JWT returned in the response contained the admin's password
hash in plaintext: `0192023a7bbd73250516f069df18b500`. A quick Python dictionary attack
against rockyou.txt cracked it in under a second:

```python
import hashlib, sys

target = sys.argv[1]
wordlist = sys.argv[2]

with open(wordlist, encoding="latin-1") as f:
    for word in f:
        word = word.strip()
        if hashlib.md5(word.encode()).hexdigest() == target:
            print(f"Found: {word}")
            break
```

Same password as Chapter 1: `admin123`.

### Broken access control, basket enumeration (IDOR)

Registered a fresh low-privilege account, logged in, then requested basket IDs that
weren't mine:

```bash
curl -s http://127.0.0.1/rest/basket/1 -H "Authorization: Bearer $TOKEN2"
curl -s http://127.0.0.1/rest/basket/2 -H "Authorization: Bearer $TOKEN2"
```

Both returned full basket contents belonging to other users (UserId 1 and UserId 2),
despite the request coming from a newly registered account (id 25). The server checks
that a token is valid, never that its owner actually owns the resource being requested.

## Proving the pipeline

Before trusting any detection, I confirmed the data was actually flowing end to end,
nginx logging the body, the forwarder shipping it, Splunk indexing it:

```bash
docker exec nginx-proxy tail -3 /var/log/nginx/juice-shop-access.log
docker exec -u splunk splunk-siem /opt/splunk/bin/splunk search 'index=main' \
  -auth admin:<password> -maxout 15
```

Both attacks showed up as searchable events in Splunk, request body and all.

## Detections

### Sigma: SQL injection in login

```yaml
title: SQL Injection Attempt in Juice Shop Login
logsource:
    category: proxy
    product: nginx
detection:
    selection_method:
        http_method: POST
    selection_endpoint:
        url|contains: '/rest/user/login'
    selection_sqli:
        request_body|contains:
            - "' or "
            - "' OR "
            - "--"
            - "union select"
    condition: selection_method and selection_endpoint and selection_sqli
level: high
```

### Sigma: basket ID enumeration (IDOR)

```yaml
title: Sequential Basket ID Enumeration (Possible IDOR)
logsource:
    category: proxy
    product: nginx
detection:
    selection:
        http_method: GET
        url|re: '/rest/basket/\d+'
    timeframe: 1m
    condition: selection | count(url) by client_ip > 1
level: medium
```

### Converted to SPL and validated

Both were converted to SPL, saved as searches inside Splunk, and run against the actual
captured traffic, not a synthetic test. Both returned the real attack events: the SQLi
login POST with its payload visible in the body field, and both basket requests from the
same client within the same minute.

## What this closes

Chapter 1 showed the vulnerabilities exist. Chapter 2 shows what it looks like to actually
be watching for them, the exact gap between "we got breached" and "we knew the moment it
happened." That gap is most of what a SOC does.

## What's next

Chapter 3 moves to DVWA alongside Juice Shop for a different set of vulnerability classes,
file upload, command injection, CSRF, with detections written for those too.
