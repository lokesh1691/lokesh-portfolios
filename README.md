# Lokesh Kumar — Portfolio (Frontend + Secure Backend)

A personal portfolio site with a hardened backend API for the contact form
and a JWT-protected admin session, built to run entirely on free hosting
tiers.

```
lokesh-portfolio/
├── frontend/
│   └── index.html          # static site — deploy to Vercel/Netlify
└── backend/
    ├── server.js            # Express app entrypoint
    ├── middleware/
    │   ├── security.js       # helmet, CORS, rate limits, CSRF, bot filtering
    │   └── auth.js           # JWT verification for protected routes
    ├── routes/
    │   ├── auth.js           # login / logout / session check
    │   └── contact.js        # public contact form endpoint
    ├── scripts/hash-password.js
    └── .env.example
```

## Why frontend and backend are separate

The frontend is static HTML/CSS/JS — it needs no server and deploys to
Vercel's free tier as-is. The backend is a small Node/Express API that
needs a persistent process (for the rate limiter's in-memory counters to
work correctly), so it's deployed separately, on Render's free tier.

## 1. Local setup

```bash
cd backend
npm install
cp .env.example .env
npm run hash-password -- "choose-a-strong-password"
# paste the printed hash into .env as ADMIN_PASSWORD_HASH
# fill in JWT_SECRET and COOKIE_SECRET with long random strings
npm run dev
```

Open `frontend/index.html` in a browser (or serve it with any static
server) — the contact form will talk to `http://localhost:4000`.

## 2. Security features, and why each one is there

| Layer | What it does | Defends against |
|---|---|---|
| **Helmet** | Sets CSP, HSTS, X-Content-Type-Options, frame-ancestors, etc. | XSS injection points, clickjacking, MIME sniffing |
| **CORS allow-list** | Only origins in `ALLOWED_ORIGINS` can call the API from a browser | Unauthorized cross-origin use of your API |
| **express-rate-limit** (global + per-route) | Caps requests per IP per time window | Brute force, spam floods, scripted abuse |
| **express-slow-down** | Progressively delays repeated hits before the hard limit kicks in | Fast scripted bursts |
| **CSRF double-submit token** | State-changing requests must echo a token the attacker's page can't read | Cross-site request forgery |
| **Honeypot field + timing check** | Hidden field bots fill in; rejects submissions faster than a human could type | Basic bots and naive AI-agent form-fillers |
| **express-validator + sanitize-html** | Validates types/lengths, strips HTML from all input | Injection, stored XSS via the contact form |
| **bcrypt (cost 12)** | One-way hashed admin password, never stored in plaintext | Credential theft from source/config leaks |
| **JWT in httpOnly, sameSite=strict cookie** | Token isn't readable by page JS | Token theft via XSS |
| **Small JSON body limit (20kb)** | Rejects oversized payloads before they're processed | Payload-based resource exhaustion |
| **`app.set('trust proxy', 1)`** | Reads the real client IP from your host's proxy header | Rate limits being bypassed behind a proxy |
| **Structured logging** | Every request logged with status/IP | Lets you spot attack patterns and alert on spikes |

## 3. Being straight about DDoS protection

Nothing running inside this Node process can stop a real volumetric DDoS
attack — by the time traffic reaches `express-rate-limit`, your one server
process is already spending CPU/bandwidth per request. Application-level
rate limiting (included here) is a good second layer against abuse and
scripted spam, but the actual DDoS shield has to sit **in front of** the
server, at the network edge. Both of these are free:

- **Cloudflare** (free tier): put your backend domain behind Cloudflare's
  proxy (orange-cloud DNS). It absorbs volumetric attacks before they ever
  reach Render, and gives you a free WAF and bot-fight-mode.
- **Vercel** (frontend): already sits behind Vercel's edge network / CDN
  with built-in DDoS mitigation — nothing to configure.

## 4. Deploy

**Frontend (Vercel, free):**
1. Push this repo to GitHub.
2. On vercel.com → New Project → import the repo → set root directory to
   `frontend` → Deploy.
3. In `frontend/index.html`, set `window.PORTFOLIO_API_BASE` (add a small
   `<script>window.PORTFOLIO_API_BASE = "https://your-backend.onrender.com"</script>`
   before the closing `</head>`) to your deployed backend URL.

**Backend (Render, free):**
1. On render.com → New → Web Service → connect the repo → root directory
   `backend` → build command `npm install` → start command `npm start`.
2. Add all variables from `.env.example` in Render's Environment tab
   (use real secrets, not the placeholders).
3. Set `ALLOWED_ORIGINS` to your Vercel frontend URL.
4. (Recommended) Put a free Cloudflare proxy in front of the Render URL
   for edge-level DDoS/WAF protection, as above.

## 5. Keeping it secure over time

- Run `npm audit` in `backend/` periodically (or enable GitHub's Dependabot
  alerts on the repo) and update flagged dependencies.
- Rotate `JWT_SECRET` and the admin password occasionally; both are read
  from environment variables, never hardcoded.
- Never commit `.env` — it's in `.gitignore` already.
- If you add a database later, use parameterized queries / an ORM (never
  string-concatenated SQL) to avoid injection.
