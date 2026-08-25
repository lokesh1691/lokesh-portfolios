const express = require('express');
const { body, validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html');
const {
  contactLimiter,
  contactSlowDown,
  verifyCsrf,
  botHeuristics
} = require('../middleware/security');
const logger = require('../utils/logger');

const router = express.Router();

const clean = (input) =>
  sanitizeHtml(input, { allowedTags: [], allowedAttributes: {} }).trim();

/**
 * POST /api/contact
 * Order of defense: rate limit -> slow-down -> CSRF -> bot heuristics ->
 * input validation/sanitization -> handler. Each layer rejects cheaply
 * before the more expensive ones run.
 */
router.post(
  '/',
  contactLimiter,
  contactSlowDown,
  verifyCsrf,
  botHeuristics,
  [
    body('name').isString().trim().isLength({ min: 1, max: 80 }).withMessage('Name is required (max 80 chars).'),
    body('email').isString().trim().isEmail().withMessage('A valid email is required.').isLength({ max: 120 }),
    body('message').isString().trim().isLength({ min: 1, max: 2000 }).withMessage('Message is required (max 2000 chars).')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const name = clean(req.body.name);
    const email = clean(req.body.email);
    const message = clean(req.body.message);

    // Wire this up to your real delivery method: an email provider (Resend,
    // SendGrid, SES) or a database insert. Kept as a log line here so the
    // repo runs with zero external accounts required.
    logger.info('New contact submission', {
      name,
      email,
      messagePreview: message.slice(0, 120),
      ip: req.ip
    });

    res.status(200).json({ ok: true });
  }
);

module.exports = router;
