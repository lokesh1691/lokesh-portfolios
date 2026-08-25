const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { loginLimiter, verifyCsrf } = require('../middleware/security');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

/**
 * POST /api/auth/login
 * Single-admin login (this portfolio has one owner). Credentials are never
 * stored in code: username comes from env, password is compared against a
 * bcrypt hash generated once via `npm run hash-password`.
 */
router.post(
  '/login',
  loginLimiter,
  verifyCsrf,
  [
    body('username').trim().notEmpty().withMessage('Username is required.'),
    body('password').isString().notEmpty().withMessage('Password is required.')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { username, password } = req.body;

    // Constant-shape response whether the username or password is wrong,
    // so the endpoint doesn't leak which one was incorrect.
    const validUsername = username === process.env.ADMIN_USERNAME;
    const passwordMatch = validUsername
      ? await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH || '')
      : await bcrypt.compare(password, '$2a$10$invalidsaltinvalidsaltinvalidsalte'); // dummy compare to equalize timing

    if (!validUsername || !passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const token = jwt.sign(
      { sub: username, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '15m' }
    );

    res.cookie('session', token, {
      httpOnly: true, // not readable by JS — mitigates token theft via XSS
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });

    res.json({ ok: true, user: { username } });
  }
);

/** POST /api/auth/logout — clears the session cookie */
router.post('/logout', verifyCsrf, (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

/** GET /api/auth/me — lets the frontend check if an admin session is active */
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: { username: req.user.sub, role: req.user.role } });
});

module.exports = router;
