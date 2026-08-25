const express = require('express');
const { body, validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html');
const { Resend } = require('resend');
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

// Email delivery is optional: if RESEND_API_KEY isn't set, submissions are
// still validated, sanitized, and logged — just not emailed. This keeps the
// repo runnable with zero external accounts, while letting you turn on real
// delivery by adding one env var.
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

async function sendNotificationEmail({ name, email, message }) {
  if (!resend || !process.env.CONTACT_TO_EMAIL) return { sent: false };

  const { data, error } = await resend.emails.send({
    // Resend's shared sending domain — works with zero setup. Once you
    // verify your own domain in the Resend dashboard, swap this for
    // something like "Portfolio <contact@yourdomain.com>".
    from: 'Portfolio Contact <onboarding@resend.dev>',
    to: [process.env.CONTACT_TO_EMAIL],
    replyTo: email, // lets you hit "Reply" and answer the sender directly
    subject: `New portfolio contact from ${name}`,
    text: `From: ${name} <${email}>\n\n${message}`
  });

  if (error) {
    // Don't throw — a failed email shouldn't turn into a 500 for the
    // visitor. Log it so you notice and can check Resend's dashboard.
    logger.error('Resend send failed', { error: error.message || error });
    return { sent: false };
  }
  return { sent: true, id: data?.id };
}

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

    const emailResult = await sendNotificationEmail({ name, email, message });
    if (emailResult.sent) {
      logger.info('Contact notification emailed', { id: emailResult.id });
    }

    res.status(200).json({ ok: true });
  }
);

module.exports = router;