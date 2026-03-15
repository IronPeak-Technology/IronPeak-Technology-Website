const crypto = require('crypto');

/**
 * POST /api/verify
 * Body: { "password": "..." }
 *
 * Verifies the trading page password server-side against the
 * TRADING_PASSWORD environment variable set in the Vercel dashboard.
 * The password never appears in the repository source code.
 */
module.exports = async function handler(req, res) {
  // Only allow POST
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Parse body whether Vercel pre-parsed it or not
  let body;
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: 'Invalid request body' });
  }

  const submitted = typeof body?.password === 'string' ? body.password : '';
  const correct   = process.env.TRADING_PASSWORD;

  if (!correct) {
    // Env var not configured in Vercel dashboard
    return res.status(500).json({ error: 'Server not configured' });
  }

  // Constant-time comparison prevents timing attacks
  const a = Buffer.from(submitted, 'utf8');
  const b = Buffer.from(correct,   'utf8');
  const match = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (match) {
    return res.status(200).json({ ok: true });
  }

  return res.status(401).json({ error: 'Invalid password' });
};
