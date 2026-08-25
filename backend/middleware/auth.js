const jwt = require('jsonwebtoken');

/**
 * Reads the JWT from an httpOnly cookie (never from localStorage — that
 * would expose it to any XSS on the page). Verifies signature + expiry.
 */
function requireAuth(req, res, next) {
  const token = req.cookies?.session;
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session expired or invalid. Please log in again.' });
  }
}

module.exports = { requireAuth };
