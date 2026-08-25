require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const {
  helmetMiddleware,
  corsMiddleware,
  globalLimiter,
  issueCsrfToken
} = require('./middleware/security');

const authRoutes = require('./routes/auth');
const contactRoutes = require('./routes/contact');
const logger = require('./utils/logger');

const REQUIRED_ENV = ['JWT_SECRET', 'ADMIN_USERNAME', 'ADMIN_PASSWORD_HASH'];
const missing = REQUIRED_ENV.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`Missing required environment variables: ${missing.join(', ')}`);
  console.error('Copy .env.example to .env and fill these in (see README).');
  process.exit(1);
}

const app = express();

// Trust the first proxy hop (Render/Vercel/Cloudflare) so req.ip and
// rate-limiting see the real client IP instead of the proxy's.
app.set('trust proxy', 1);

app.use(helmetMiddleware);
app.use(corsMiddleware);
app.use(express.json({ limit: '20kb' })); // small body limit — blunt defense against oversized payload floods
app.use(cookieParser());
app.use(morgan('combined'));
app.use(globalLimiter);

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/api/csrf-token', issueCsrfToken);

app.use('/api/auth', authRoutes);
app.use('/api/contact', contactRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// Central error handler — never leak stack traces or internals to clients.
app.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'Origin not allowed.' });
  }
  logger.error('Unhandled error', { message: err.message });
  res.status(500).json({ error: 'Something went wrong.' });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  logger.info(`Backend listening on port ${PORT}`, { env: process.env.NODE_ENV });
});
