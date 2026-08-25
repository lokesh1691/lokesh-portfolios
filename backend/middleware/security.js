const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const crypto = require('crypto');

/**
 * Helmet: sets a strong set of HTTP security headers
 * (CSP, HSTS, no-sniff, frameguard, referrer-policy, etc.)
 */
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginResourcePolicy: { policy: 'same-site' },
  referrerPolicy: { policy: 'no-referrer' }
});

/**
 * CORS: only allow the frontend origin(s) you explicitly list in .env.
 * Requests from anywhere else (including most automated scripts / AI agents
 * making direct browser-style calls) are rejected at the browser level.
 */
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const corsMiddleware = cors({
  origin(origin, callback) {
    // Allow same-origin / server-to-server calls with no Origin header (curl, health checks)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'Authorization']
});

/**
 * Global rate limiter: blunt, app-level defense against floods and scripted
 * abuse. This is a second layer — the real DDoS shield should sit in front
 * of this server (Cloudflare proxy / your host's edge network), because a
 * large volumetric attack will exhaust this process before requests ever
 * reach this middleware. See README "DDoS protection" section.
 */
const globalLimiter = rateLimit({
  windowMs: Number(process.env.GLOBAL_RATE_LIMIT_WINDOW_MIN || 1) * 60 * 1000,
  max: Number(process.env.GLOBAL_RATE_LIMIT_MAX || 100),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down and try again shortly.' }
});

/** Tighter limiter specifically for the contact form (prevents spam floods) */
const contactLimiter = rateLimit({
  windowMs: Number(process.env.CONTACT_RATE_LIMIT_WINDOW_MIN || 15) * 60 * 1000,
  max: Number(process.env.CONTACT_RATE_LIMIT_MAX || 5),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many messages sent from this network. Please try again later.' }
});

/** Tighter limiter for login attempts (prevents credential brute-forcing) */
const loginLimiter = rateLimit({
  windowMs: Number(process.env.LOGIN_RATE_LIMIT_WINDOW_MIN || 15) * 60 * 1000,
  max: Number(process.env.LOGIN_RATE_LIMIT_MAX || 5),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again later.' }
});

/**
 * Progressive slowdown on the contact route: legitimate one-off senders are
 * unaffected, but a script firing many requests quickly gets throttled
 * before it even hits the hard rate-limit ceiling.
 */
const contactSlowDown = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 2,
  delayMs: (hits) => hits * 500
});

/**
 * CSRF protection using the double-submit cookie pattern:
 * - GET /api/csrf-token issues a random token, set both as a readable cookie
 *   and returned in the JSON body.
 * - The frontend echoes it back in the X-CSRF-Token header on state-changing
 *   requests. We compare header vs cookie — an attacker's cross-site page
 *   can trigger a request but cannot read the cookie to copy its value.
 */
function issueCsrfToken(req, res) {
  const token = crypto.randomBytes(32).toString('hex');
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie('csrfToken', token, {
    httpOnly: false, // must be readable by frontend JS to be echoed back
    secure: isProd, // required when sameSite is 'none'
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 60 * 60 * 1000
  });
  res.json({ csrfToken: token });
}

function verifyCsrf(req, res, next) {
  const cookieToken = req.cookies?.csrfToken;
  const headerToken = req.headers['x-csrf-token'];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token.' });
  }
  next();
}

/**
 * Lightweight bot / automated-agent heuristics for the public contact form.
 * None of these block a determined attacker on their own, but combined they
 * filter out the overwhelming majority of scripted/AI-agent spam without
 * inconveniencing real visitors or requiring a third-party CAPTCHA.
 */
function botHeuristics(req, res, next) {
  const { company, renderedAt } = req.body || {};

  // 1. Honeypot: a field hidden from real users via CSS. Bots that fill
  //    every field on a form will populate it.
  if (company) {
    return res.status(400).json({ error: 'Submission rejected.' });
  }

  // 2. Timing check: a human takes at least a couple of seconds to read the
  //    form and type a message. Scripted submissions often fire instantly.
  if (typeof renderedAt === 'number') {
    const elapsed = Date.now() - renderedAt;
    if (elapsed < 1500) {
      return res.status(400).json({ error: 'Submission rejected.' });
    }
  }

  // 3. Obvious non-browser / known-bot user agents. Easy to spoof, so this
  //    is a filter, not a security boundary — real protection is the
  //    rate limiter + honeypot + CSRF above.
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const suspicious = ['curl/', 'python-requests', 'scrapy', 'go-http-client', 'headlesschrome'];
  if (suspicious.some((s) => ua.includes(s))) {
    return res.status(400).json({ error: 'Submission rejected.' });
  }

  next();
}

module.exports = {
  helmetMiddleware,
  corsMiddleware,
  globalLimiter,
  contactLimiter,
  loginLimiter,
  contactSlowDown,
  issueCsrfToken,
  verifyCsrf,
  botHeuristics
};
