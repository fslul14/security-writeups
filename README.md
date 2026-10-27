# Security Write-Ups

- [Chapter 1: Back to Basics](./README.md)
- [Chapter 2: Attack It, Then Catch It](./chapter-2.md)

---

# Back to Basics: Breaking My Way Back Into OWASP Juice Shop

**TL;DR:** A weekend project to rebuild a proper home lab from scratch and re-attack OWASP Juice Shop, the same vulnerable web app that got me into cybersecurity in college. Four findings: a SQL injection authentication bypass, a leaked and crackable password hash, a broken access control (IDOR) bug, and some basic recon that set it all up. OWASP Top 10 categories covered: Injection (A03), Cryptographic/Sensitive Data Exposure (A02), and Broken Access Control (A01).

---

## Why I Did This

My freshman year of college, I followed a tutorial on SQL injection and ran it against OWASP Juice Shop, a website built specifically to be hacked. I didn't fully understand what I was doing yet, but when one of the payloads worked and the site popped up a little "you found it" message, something clicked. That feeling, of bending an application into doing something it was never supposed to do, is what got me into cybersecurity in the first place.

A few years later, I'm working in security professionally, but in a compliance and audit role, and lately I've felt pretty disconnected from the hands-on side of the field. Talking to a mentor recently, he told me to stop chasing the next certification or job title for a minute and just go back to basics. Rebuild the projects from scratch. Find the joy again. Publish what I learn along the way.

So that's what this is. I rebuilt a proper lab from zero: an isolated network, an attacker machine, a target running Juice Shop, and spent a weekend attacking it the right way, slowly, documenting everything instead of just chasing the flag. Here's what I found.

---

## Lab Setup

To do any of this safely and legally, I needed a lab that was completely cut off from the outside world. Attacking anything you don't own or have explicit permission to test is illegal, full stop, even with "harmless" tools.

I built two virtual machines in VirtualBox on my own laptop. **Kali Linux** was the attacker machine, loaded with the standard pentesting toolkit: nmap, Burp Suite, hashcat, and others. **Ubuntu Server** was the target, running **OWASP Juice Shop** in Docker.

Both machines sit on a VirtualBox internal network (`10.10.10.0/24`) with no route to my home network or the internet. Once Juice Shop was installed and running, I disconnected the target's internet access entirely, so even if something in the lab went sideways, there was no path out. Kali talks to the target only across that isolated link, the same way an attacker would reach a target over a network, just contained to two VMs on my own machine.

| Machine | Role | Address |
|---|---|---|
| Kali Linux | Attacker | `10.10.10.10` |
| Ubuntu Server (Docker, Juice Shop) | Target | `10.10.10.20` |

---

## Finding 1: Recon

Before touching anything, I mapped out what was actually there. From Kali, `nmap -sn 10.10.10.0/24` confirmed only my two lab machines existed on the network, and a full port scan of the target turned up two open ports: 22 (SSH, which I'd installed myself) and 3000 (the Juice Shop web app).

Worth admitting: my first attempt at a more detailed scan had a typo. I meant to scan ports 22 and 3000 together, but a stray space after a comma made nmap treat "3000" as a second target instead of a port, and it quietly scanned a different, unintended IP address. Nothing came of it since that address didn't correspond to a real host, but it's a good reminder that a single misplaced character can send a scan somewhere you never meant it to go. On a real engagement, that's not a harmless mistake, it's a scope violation. I kept the bad scan output alongside the corrected one as a reminder to read every command before hitting enter.

Looking at the actual HTTP response headers from the web app surfaced a few things before I'd exploited anything:

- `Access-Control-Allow-Origin: *` and an OPTIONS response allowing GET, HEAD, PUT, PATCH, POST, and DELETE from any origin. Essentially no CORS restriction at all.
- No `Content-Security-Policy` header anywhere, which makes any future XSS finding easier to actually exploit.
- An `X-Recruiting: /#/jobs` header, a small easter egg baked into the app on purpose.

None of these are exploits on their own, but they told me the app wasn't hardened, which made me want to dig into the parts of it that actually take user input. That's what led me to the login form.

```
$ nmap -sC -sV -p22,3000 10.10.10.20

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 10.2p1 Ubuntu 2ubuntu3.8 (Ubuntu Linux; protocol 2.0)
3000/tcp open  ppp?
```

---

## Finding 2: SQL Injection to Authentication Bypass

The login form seemed like the obvious next target. I proxied my browser traffic through Burp Suite and intercepted a normal login attempt with fake credentials. The request body was plain JSON: `{"email":"...","password":"..."}`, sent as readable text. Juice Shop runs over plain HTTP with no TLS, so on a real network that password would be visible to anyone watching the traffic. In production that's what HTTPS is for, but it was a useful reminder of what's actually happening under the hood every time you type a password into a login form.

With the request captured, I sent it to Burp's Repeater tool, which lets you resend and edit a single request without the browser getting in the way. I replaced the email field with a classic SQL injection payload:

```json
{"email":"' or 1=1--","password":"x"}
```

If the backend builds its SQL query by directly inserting user input instead of using parameterized queries, a payload like this turns the query's WHERE clause into something that's always true, and the `--` comments out the rest of the query, including the password check entirely.

It worked. The server responded with `200 OK` and a full authentication token, logged in as `admin@juice-sh.op`, no valid password required.

**The fix** is straightforward and well known: never build SQL queries by concatenating user input directly into the string. Use parameterized queries or prepared statements instead, where input is always treated as data and never as executable code. Had this app done that, my payload would have simply failed to match any real account.

---

## Finding 3: Sensitive Data Exposure via JWT

The authentication token I got back was a JWT, a JSON Web Token made of three base64-encoded parts separated by dots. The middle part, the payload, isn't encrypted, only encoded, which means anyone holding the token can read it without any key. I decoded mine on the command line:

```bash
echo '<token payload>' | base64 -d
```

The decoded JSON included the admin's email, role, account timestamps, and something that should never leave the server: the admin's password hash, `0192023a7bbd73250516f069df18b500`.

A signature exists on a JWT to prevent tampering, so the server can tell if someone edited the payload after it was issued. It doesn't make the payload secret. Anyone who captures a token, through a compromised machine, a logging system, a browser extension, or anything else, can read everything inside it.

To show this wasn't just theoretical, I ran the hash through John the Ripper against the rockyou.txt wordlist, a list of real passwords from past data breaches:

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt /tmp/john_hash.txt
```

It cracked in under a second: `admin123`. The hashing algorithm itself (plain MD5, no salt) is outdated and fast to crack by design, and the underlying password was weak enough to be in nearly every common wordlist.

**The fix** has two parts. First, the backend should never include password hashes, salts, or any sensitive internal fields in a token handed to the client, only what the client actually needs, like a user ID and role. Second, passwords should be hashed with a slow, purpose-built algorithm like bcrypt or Argon2, not plain MD5, and weak passwords like "admin123" should be rejected at account creation.

---

## Finding 4: Broken Access Control (IDOR)

By this point I'd compromised the admin account outright, but I wanted to test something different: what happens to a completely ordinary, newly registered user. I created a throwaway account, logged in normally with no injection involved, and added an item to my basket.

Juice Shop assigns each basket a simple numeric ID. My basket came back as `/rest/basket/6`, sent with my own valid authentication token in the request. Out of curiosity, I sent the exact same request again in Repeater, changing nothing but the number in the URL, down to `/rest/basket/1`.

It returned a complete basket, full of products, that belonged to a different account entirely (`UserId: 1`). I tried `/rest/basket/2` as well. Same result: another user's basket, returned without complaint. My token was never checked against who actually owned the basket I was asking for.

This is a different kind of failure than the SQL injection. The SQLi broke authentication itself, letting me become someone else entirely. This is a failure of authorization: the server correctly confirmed I was a real, logged-in user, but never checked whether I was the right user for the specific piece of data I was asking for. That distinction matters because the fix is different, and because broken access control shows up in real production applications constantly. It's consistently one of the most common vulnerability classes found in the wild, not just a lab toy.

**The fix** is for the server to use the information it already has. It decodes the JWT to authenticate every request, which means it already knows the requesting user's ID before it touches the database. The basket query should include that ID as a condition, something like `WHERE id = :requestedBasketId AND UserId = :authenticatedUserId`, and return a 403 or 404 if there's no match, rather than trusting the ID in the URL alone.

---

## What's Next

Four findings from one weekend with a vulnerable app and a cup of coffee: broken access control on login, broken access control on data, a leaked password hash cracked in under a second, and an insecure network configuration that would've expanded all of it if I hadn't locked the lab down first. Mapped to the OWASP Top 10, that's injection, cryptographic and sensitive data exposure, and broken access control, three of the most common categories of real-world vulnerabilities, all inside a single application built specifically to teach them.

None of this is cutting-edge. Juice Shop is a learning tool, and everything here is documented in countless other write-ups. That's sort of the point. My mentor's advice wasn't to go find something novel, it was to rebuild the fundamentals from scratch, slowly, and actually understand each step instead of running a tool and copying the output. Typing out the nmap command, getting it wrong, and understanding why it was wrong taught me more than getting it right on the first try would have.

Next up, I'm going to keep building on this lab: DVWA alongside Juice Shop, an attack-and-detect project where I run these same techniques against my own Splunk setup and write the detections for them, and eventually working toward OSCP. I'll keep publishing what I find, partly to hold myself accountable, and partly because the version of me in that freshman dorm room would have liked to read something like this.

---

## Tools Used

Kali Linux, VirtualBox, Docker, nmap, Burp Suite Community, John the Ripper, OWASP Juice Shop
