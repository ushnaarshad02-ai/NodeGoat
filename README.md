## 🔒 Week 4: Security Hardening & Intrusion Detection

During Week 4 of the cybersecurity internship roadmap, advanced environment hardening and defense-in-depth security layers were integrated into both the operating system environment and the application layers of the NodeGoat platform.

### 1. OS-Level Intrusion Detection & Monitoring (Fail2Ban)
* **Implementation:** Installed and configured `fail2ban` within the Ubuntu Linux environment. 
* **Mechanism:** Designed a dedicated local configuration jail (`/etc/fail2ban/jail.local`) targeted at monitoring secure shell (`sshd`) logs.
* **Result:** Real-time automated log scrubbing is active. The system dynamically monitors malicious, repeated authentication failures and drops traffic from abusive IPs at the firewall layer.
* **Verification Status:** Active (`Jail list: sshd`).

### 2. API Security Hardening
* **Rate Limiting (`express-rate-limit`):** Implemented an automated global rate limiter restricting incoming requests to a maximum of `100 requests per 15 minutes` per IP address. Abusive triggers successfully yield an HTTP `429 Too Many Requests` error state.
* **Strict CORS Policies (`cors`):** Restricted Cross-Origin Resource Sharing explicitly to trusted development loopbacks (`http://localhost:4000` and `http://127.0.0.1:4000`). Restricted acceptable HTTP verbs to `GET, POST, PUT, DELETE` to eliminate unauthorized external data manipulation.
* **API Key Verification Middleware:** Configured a custom intercepting middleware requiring a valid authentication token via the custom `X-API-Key` header on all `/api/` matching routes. Unauthenticated requests are safely dropped with an explicit HTTP `401 Unauthorized` response.

### 3. HTTP Security Headers & CSP (Helmet)
* **Content Security Policy (CSP):** Leveraged `helmet` middleware to build structured, granular resource trust boundaries. Explicitly whitelisted safe execution origins (`'self'`) and sanitized inline scripts/styles used by NodeGoat while explicitly shutting down arbitrary injection cross-site scripting (XSS) vectors.
* **Strict-Transport-Security (HSTS):** Enforced a mandatory strict HTTPS layer via transmission header constraints with a `maxAge` policy set to 1 full year (`31536000` seconds), including all subdomains and preloads.
