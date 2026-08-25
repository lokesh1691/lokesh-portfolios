/**
 * Minimal structured logger. In production, point this at a real log sink
 * (CloudWatch, Datadog, Better Stack, etc.) so you can alert on spikes in
 * 401s/403s/429s — that pattern is usually the first sign of an attack.
 */
function line(level, message, meta) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    message,
    ...(meta || {})
  };
  console.log(JSON.stringify(entry));
}

module.exports = {
  info: (message, meta) => line('info', message, meta),
  warn: (message, meta) => line('warn', message, meta),
  error: (message, meta) => line('error', message, meta)
};
