const crypto = require('crypto');
const FormData = require('form-data');
const Mailgun = require('mailgun.js');

// ---------------------------------------------------------------------------
// Mailgun client (lazy)
// ---------------------------------------------------------------------------
let _mgClient = null;
function getMailgunClient() {
  if (_mgClient) return _mgClient;
  const mailgun = new Mailgun(FormData);
  _mgClient = mailgun.client({
    username: 'api',
    key: process.env.MAILGUN_API_KEY,
    url: process.env.MAILGUN_API_BASE_URL || 'https://api.mailgun.net',
  });
  return _mgClient;
}

// ---------------------------------------------------------------------------
// Upstash Redis (lazy). Returns null if not configured.
// Uses the standard KV_REST_API_URL / KV_REST_API_TOKEN env vars that the
// Vercel + Upstash Marketplace integration provisions automatically.
// ---------------------------------------------------------------------------
let _kv = null;
let _kvAttempted = false;
async function getKV() {
  if (_kv) return _kv;
  if (_kvAttempted) return null;
  _kvAttempted = true;
  if (!process.env.KV_REST_API_URL || !process.env.KV_REST_API_TOKEN) {
    console.warn('Upstash Redis env vars not set; persistence disabled');
    return null;
  }
  try {
    const { Redis } = await import('@upstash/redis');
    _kv = new Redis({
      url: process.env.KV_REST_API_URL,
      token: process.env.KV_REST_API_TOKEN,
    });
    return _kv;
  } catch (err) {
    console.error('Failed to load @upstash/redis:', err.message);
    return null;
  }
}

const QUOTES_KEY = 'ironpeak:quotes';

// ---------------------------------------------------------------------------
// Rate limiting / IP blocking
//   Per-IP failed login attempts are tracked in Upstash Redis.
//   - 5 failed attempts within FAIL_WINDOW => IP is blocked for BLOCK_TTL
//   - Successful login clears the counter
//   - BLOCKED_IPS env var (comma-separated) is a permanent blocklist
// ---------------------------------------------------------------------------
const FAIL_WINDOW = 15 * 60;       // 15 minutes (seconds)
const FAIL_THRESHOLD = 5;
const BLOCK_TTL = 60 * 60;         // 1 hour block (seconds)

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  if (req.headers['x-real-ip']) return String(req.headers['x-real-ip']).trim();
  return req.socket?.remoteAddress || 'unknown';
}

function isPermanentlyBlocked(ip) {
  const list = (process.env.BLOCKED_IPS || '').split(',').map(s => s.trim()).filter(Boolean);
  return list.includes(ip);
}

async function checkRateLimit(scope, ip) {
  if (isPermanentlyBlocked(ip)) {
    return { blocked: true, reason: 'IP permanently blocked', retryAfter: 0 };
  }
  const kv = await getKV();
  if (!kv) return { blocked: false }; // fail-open if storage missing
  const blockKey = `ratelimit:${scope}:block:${ip}`;
  try {
    const blocked = await kv.get(blockKey);
    if (blocked) {
      const ttl = await kv.ttl(blockKey).catch(() => BLOCK_TTL);
      return { blocked: true, reason: 'Too many failed attempts', retryAfter: Math.max(0, ttl) };
    }
  } catch (e) {
    console.warn('rate limit check failed:', e.message);
  }
  return { blocked: false };
}

async function recordFailedAttempt(scope, ip) {
  const kv = await getKV();
  if (!kv) return;
  const failKey = `ratelimit:${scope}:fail:${ip}`;
  const blockKey = `ratelimit:${scope}:block:${ip}`;
  try {
    const count = await kv.incr(failKey);
    if (count === 1) await kv.expire(failKey, FAIL_WINDOW);
    if (count >= FAIL_THRESHOLD) {
      await kv.set(blockKey, '1', { ex: BLOCK_TTL });
      await kv.del(failKey);
      console.warn(`[security] IP ${ip} blocked from ${scope} for ${BLOCK_TTL}s after ${count} failed attempts`);
    }
  } catch (e) {
    console.warn('rate limit record failed:', e.message);
  }
}

async function clearFailedAttempts(scope, ip) {
  const kv = await getKV();
  if (!kv) return;
  try { await kv.del(`ratelimit:${scope}:fail:${ip}`); } catch {}
}

// ---------------------------------------------------------------------------
// Admin token (HMAC). Secret = ADMIN_PASSWORD. TTL = 12h.
// ---------------------------------------------------------------------------
function signAdminToken(ttlMs = 12 * 60 * 60 * 1000) {
  const secret = process.env.ADMIN_PASSWORD;
  if (!secret) throw new Error('ADMIN_PASSWORD not configured');
  const exp = String(Date.now() + ttlMs);
  const sig = crypto.createHmac('sha256', secret).update(exp).digest('hex');
  return `${exp}.${sig}`;
}

function verifyAdminToken(token) {
  const secret = process.env.ADMIN_PASSWORD;
  if (!secret || !token || typeof token !== 'string') return false;
  const idx = token.indexOf('.');
  if (idx <= 0) return false;
  const exp = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expected = crypto.createHmac('sha256', secret).update(exp).digest('hex');
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(sig, 'hex');
  if (a.length !== b.length) return false;
  if (!crypto.timingSafeEqual(a, b)) return false;
  return Number(exp) > Date.now();
}

function requireAdmin(body, res) {
  if (!verifyAdminToken(body?.token)) {
    res.status(401).json({ error: 'Unauthorized' });
    return false;
  }
  return true;
}

/**
 * POST /api/verify
 * Request types:
 *   password_verify    — trading page password gate
 *   quote_request      — pricing calculator submission (emails Travis + persists to KV)
 *   admin_login        — admin password → returns short-lived token
 *   admin_quotes_list  — list saved quotes (admin)
 *   admin_quote_save   — create or update a quote/customer record (admin)
 *   admin_quote_delete — delete a stored quote (admin)
 *   admin_send_agreement — email rendered agreement HTML to a customer (admin)
 */
module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  let body;
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: 'Invalid request body' });
  }

  const requestType = body?.type || 'password_verify';

  switch (requestType) {
    case 'password_verify':     return handlePasswordVerification(body, req, res);
    case 'quote_request':       return handleQuoteRequest(body, res);
    case 'admin_login':         return handleAdminLogin(body, req, res);
    case 'admin_quotes_list':   return handleAdminQuotesList(body, res);
    case 'admin_quote_save':    return handleAdminQuoteSave(body, res);
    case 'admin_quote_delete':  return handleAdminQuoteDelete(body, res);
    case 'admin_send_agreement':return handleAdminSendAgreement(body, res);
    default:                    return res.status(400).json({ error: 'Invalid request type' });
  }
};

function handlePasswordVerification(body, req, res) {
  return (async () => {
    const ip = getClientIp(req);
    const limit = await checkRateLimit('trading', ip);
    if (limit.blocked) {
      res.setHeader('Retry-After', String(limit.retryAfter || BLOCK_TTL));
      return res.status(429).json({ error: limit.reason || 'Too many attempts. Try again later.' });
    }
    const submitted = typeof body?.password === 'string' ? body.password : '';
    const correct = process.env.TRADING_PASSWORD;

    if (!correct) {
      return res.status(500).json({ error: 'Server not configured' });
    }

    const a = Buffer.from(submitted, 'utf8');
    const b = Buffer.from(correct, 'utf8');
    const match = a.length === b.length && crypto.timingSafeEqual(a, b);

    if (match) {
      await clearFailedAttempts('trading', ip);
      return res.status(200).json({ ok: true });
    }

    await recordFailedAttempt('trading', ip);
    return res.status(401).json({ error: 'Invalid password' });
  })();
}

async function handleQuoteRequest(body, res) {
  try {
    // Validate required environment variables
    if (!process.env.MAILGUN_API_KEY || !process.env.MAILGUN_DOMAIN) {
      console.error('Missing required Mailgun environment variables');
      return res.status(500).json({ 
        error: 'Email service not configured properly',
        details: 'Missing MAILGUN_API_KEY or MAILGUN_DOMAIN'
      });
    }

    // Format email content
    const emailHtml = formatQuoteEmailHtml(body);
    const emailText = body.body; // Plain text version

    const message = {
      from: `IronPeak Quote System <quotes@${process.env.MAILGUN_DOMAIN}>`,
      to: ['tfinch@ironpeaktechnology.com'],
      subject: body.subject,
      text: emailText,
      html: emailHtml,
    };
    if (body.customerData?.email) {
      message['h:Reply-To'] = body.customerData.email;
    }

    const mg = getMailgunClient();
    const result = await mg.messages.create(process.env.MAILGUN_DOMAIN, message);

    // Best-effort persist to KV so it shows up in the admin Customer Manager
    let savedId = null;
    try {
      const kv = await getKV();
      if (kv) {
        const id = generateId();
        const record = {
          id,
          createdAt: new Date().toISOString(),
          source: 'pricing_calculator',
          status: 'new',
          messageId: result.id,
          customerData: body.customerData || {},
          quoteData: body.quoteData || {},
        };
        await kv.hset(QUOTES_KEY, { [id]: JSON.stringify(record) });
        savedId = id;
      }
    } catch (kvErr) {
      console.error('KV persist failed (quote still emailed):', kvErr.message);
    }

    console.log('Quote email sent successfully:', {
      messageId: result.id,
      kvId: savedId,
      company: body.customerData?.company,
      email: body.customerData?.email,
      total: body.quoteData?.total,
      timestamp: new Date().toISOString()
    });

    return res.status(200).json({
      ok: true,
      message: 'Quote request sent successfully',
      messageId: result.id,
      quoteId: savedId,
    });

  } catch (error) {
    console.error('Error sending quote email:', error);
    return res.status(500).json({ 
      error: 'Failed to send quote request',
      details: error.message
    });
  }
}

function generateId() {
  return (typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex')).replace(/-/g, '').slice(0, 16);
}

// ---------------------------------------------------------------------------
// Admin handlers
// ---------------------------------------------------------------------------
function handleAdminLogin(body, req, res) {
  return (async () => {
    const ip = getClientIp(req);
    const limit = await checkRateLimit('admin', ip);
    if (limit.blocked) {
      res.setHeader('Retry-After', String(limit.retryAfter || BLOCK_TTL));
      console.warn(`[security] blocked admin login attempt from ${ip}`);
      return res.status(429).json({ error: limit.reason || 'Too many failed attempts. Try again later.' });
    }
    const submitted = typeof body?.password === 'string' ? body.password : '';
    const correct = process.env.ADMIN_PASSWORD;
    if (!correct) return res.status(500).json({ error: 'Admin not configured (set ADMIN_PASSWORD)' });
    const a = Buffer.from(submitted, 'utf8');
    const b = Buffer.from(correct, 'utf8');
    const match = a.length === b.length && crypto.timingSafeEqual(a, b);
    if (!match) {
      await recordFailedAttempt('admin', ip);
      console.warn(`[security] failed admin login from ${ip}`);
      return res.status(401).json({ error: 'Invalid admin password' });
    }
    await clearFailedAttempts('admin', ip);
    try {
      const token = signAdminToken();
      return res.status(200).json({ ok: true, token, expiresIn: 12 * 60 * 60 });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  })();
}

async function handleAdminQuotesList(body, res) {
  if (!requireAdmin(body, res)) return;
  const kv = await getKV();
  if (!kv) return res.status(503).json({ error: 'Storage not configured (Upstash Redis env vars missing)' });
  try {
    const all = (await kv.hgetall(QUOTES_KEY)) || {};
    const quotes = Object.values(all)
      .map(v => { try { return typeof v === 'string' ? JSON.parse(v) : v; } catch { return null; } })
      .filter(Boolean)
      .sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    return res.status(200).json({ ok: true, quotes });
  } catch (err) {
    console.error('admin_quotes_list error:', err);
    return res.status(500).json({ error: 'Failed to load quotes', details: err.message });
  }
}

async function handleAdminQuoteSave(body, res) {
  if (!requireAdmin(body, res)) return;
  const kv = await getKV();
  if (!kv) return res.status(503).json({ error: 'Storage not configured (Upstash Redis env vars missing)' });
  try {
    const incoming = body.quote || {};
    const id = (incoming.id && String(incoming.id).match(/^[a-zA-Z0-9_-]{4,64}$/)) ? incoming.id : generateId();
    const record = {
      id,
      createdAt: incoming.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      source: incoming.source || 'admin_manual',
      status: incoming.status || 'new',
      customerData: incoming.customerData || {},
      quoteData: incoming.quoteData || {},
    };
    await kv.hset(QUOTES_KEY, { [id]: JSON.stringify(record) });
    return res.status(200).json({ ok: true, quote: record });
  } catch (err) {
    console.error('admin_quote_save error:', err);
    return res.status(500).json({ error: 'Failed to save quote', details: err.message });
  }
}

async function handleAdminQuoteDelete(body, res) {
  if (!requireAdmin(body, res)) return;
  const kv = await getKV();
  if (!kv) return res.status(503).json({ error: 'Storage not configured (Upstash Redis env vars missing)' });
  const id = body.id;
  if (!id || typeof id !== 'string') return res.status(400).json({ error: 'Missing id' });
  try {
    await kv.hdel(QUOTES_KEY, id);
    return res.status(200).json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete', details: err.message });
  }
}

async function handleAdminSendAgreement(body, res) {
  if (!requireAdmin(body, res)) return;
  if (!process.env.MAILGUN_API_KEY || !process.env.MAILGUN_DOMAIN) {
    return res.status(500).json({ error: 'Email service not configured' });
  }
  const to = (body.to || '').trim();
  const subject = (body.subject || 'Managed Services Agreement — IronPeak Technology LLC').trim();
  const html = body.html;
  if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return res.status(400).json({ error: 'Invalid recipient email' });
  if (!html || typeof html !== 'string' || html.length < 50) return res.status(400).json({ error: 'Missing agreement html' });
  if (html.length > 750000) return res.status(413).json({ error: 'Agreement HTML too large' });

  try {
    const domain = process.env.MAILGUN_DOMAIN;
    const mg = getMailgunClient();

    const customerMessage = {
      from: `IronPeak Technology <agreements@${domain}>`,
      to: [to],
      subject,
      html,
      'h:Reply-To': 'tfinch@ironpeaktechnology.com',
    };
    const internalMessage = {
      from: `IronPeak Agreements <agreements@${domain}>`,
      to: ['tfinch@ironpeaktechnology.com'],
      subject: `[SENT AGREEMENT COPY] ${subject}`,
      html,
      'h:Reply-To': to,
    };

    const [customerRes, internalRes] = await Promise.allSettled([
      mg.messages.create(domain, customerMessage),
      mg.messages.create(domain, internalMessage),
    ]);

    if (customerRes.status === 'rejected') {
      console.error('Customer agreement email failed:', customerRes.reason);
      return res.status(502).json({ error: 'Failed to email customer', details: customerRes.reason?.message });
    }
    if (internalRes.status === 'rejected') {
      console.error('Internal copy failed:', internalRes.reason);
    }

    // Optionally update the saved quote status
    if (body.quoteId) {
      try {
        const kv = await getKV();
        if (kv) {
          const raw = await kv.hget(QUOTES_KEY, body.quoteId);
          if (raw) {
            const q = typeof raw === 'string' ? JSON.parse(raw) : raw;
            q.status = 'agreement_sent';
            q.agreementSentAt = new Date().toISOString();
            q.agreementSentTo = to;
            await kv.hset(QUOTES_KEY, { [body.quoteId]: JSON.stringify(q) });
          }
        }
      } catch (e) {
        console.warn('Failed to update quote status:', e.message);
      }
    }

    return res.status(200).json({ ok: true, messageId: customerRes.value?.id });
  } catch (err) {
    console.error('admin_send_agreement error:', err);
    return res.status(500).json({ error: 'Failed to send agreement', details: err.message });
  }
}

function formatQuoteEmailHtml(body) {
  const { customerData, quoteData } = body;
  
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>New Quote Request</title>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        .info-grid { display: grid; grid-template-columns: 200px 1fr; gap: 10px; margin-bottom: 15px; }
        .info-label { font-weight: bold; color: #7f8c8d; }
        .pricing-item { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #ecf0f1; }
        .total-row { font-weight: bold; font-size: 1.2em; color: #e74c3c; padding: 15px 0; border-top: 2px solid #3498db; }
        .features-list { list-style: none; padding: 0; }
        .features-list li { padding: 5px 0; }
        .features-list li:before { content: "✓ "; color: #27ae60; font-weight: bold; }
        .notes-box { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1 style="margin: 0; color: #2c3e50;">New MSP Quote Request</h1>
          <p style="margin: 5px 0 0 0; color: #7f8c8d;">Generated on ${new Date().toLocaleString()}</p>
        </div>

        <div class="section">
          <h2>Contact Information</h2>
          <div class="info-grid">
            <div class="info-label">Company:</div>
            <div>${customerData?.company || 'Not provided'}</div>
            <div class="info-label">Contact Name:</div>
            <div>${customerData?.name || 'Not provided'}</div>
            <div class="info-label">Email:</div>
            <div><a href="mailto:${customerData?.email}">${customerData?.email || 'Not provided'}</a></div>
            <div class="info-label">Phone:</div>
            <div><a href="tel:${customerData?.phone}">${customerData?.phone || 'Not provided'}</a></div>
          </div>
        </div>

        <div class="section">
          <h2>Selected Plan Details</h2>
          <div class="info-grid">
            <div class="info-label">Service Tier:</div>
            <div><strong>${quoteData?.tier ? quoteData.tier.charAt(0).toUpperCase() + quoteData.tier.slice(1) : 'Not specified'}</strong></div>
            <div class="info-label">Number of Users:</div>
            <div><strong>${quoteData?.userCount || 'Not specified'}</strong></div>
          </div>
        </div>

        <div class="section">
          <h2>Pricing Breakdown</h2>
          <div style="background: #f8f9fa; padding: 15px; border-radius: 5px;">
            ${quoteData?.breakdown ? quoteData.breakdown.map(line => {
              const parts = line.split(':');
              return `<div class="pricing-item">
                <span>${parts[0]}:</span>
                <span><strong>${parts.slice(1).join(':').trim()}</strong></span>
              </div>`;
            }).join('') : '<p>No pricing breakdown available</p>'}
            
            <div class="total-row">
              <div style="display: flex; justify-content: space-between;">
                <span>Monthly Total:</span>
                <span>$${quoteData?.total?.toFixed(2) || '0.00'}</span>
              </div>
            </div>
            
            <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #dee2e6; font-size: 0.9em; color: #6c757d;">
              <strong>One-time Setup Fee:</strong> $${quoteData?.userCount ? (quoteData.userCount * 2 * 100) : '0'} 
              (${quoteData?.userCount ? (quoteData.userCount * 2) : '0'} devices × $100)
            </div>
          </div>
        </div>

        <div class="section">
          <h2>Included Features & Services</h2>
          <ul class="features-list">
            ${quoteData?.features ? quoteData.features.map(feature => `<li>${feature}</li>`).join('') : '<li>No features specified</li>'}
          </ul>
        </div>

        ${customerData?.notes ? `
        <div class="section">
          <h2>Additional Notes</h2>
          <div class="notes-box">
            ${customerData.notes.replace(/\n/g, '<br>')}
          </div>
        </div>
        ` : ''}

        <div class="section" style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #dee2e6; text-align: center; color: #6c757d;">
          <p><strong>Next Steps:</strong> This quote has been saved to the Customer Manager in your <a href="${process.env.SITE_URL || 'https://ironpeaktechnology.com'}/admin.html">Admin Portal</a>. From there you can review, edit, and generate a formal agreement to email the customer.</p>
          <p style="font-size: 0.9em;">This quote was generated automatically from the IronPeak Technology pricing calculator.</p>
        </div>
      </div>
    </body>
    </html>
  `;
}

function buildAgreementUrl(body) {
  const base = process.env.SITE_URL || 'https://ironpeaktechnology.com';
  const c = body.customerData || {};
  const q = body.quoteData || {};
  const params = new URLSearchParams();
  if (c.company) params.append('company', c.company);
  if (c.name) params.append('contact', c.name);
  if (c.email) params.append('email', c.email);
  if (q.tier) params.append('tier', q.tier);
  if (q.userCount) params.append('users', String(q.userCount));
  if (typeof q.total === 'number') params.append('total', q.total.toFixed(2));
  if (Array.isArray(q.breakdown)) {
    const services = q.breakdown.map(line => {
      const m = line.match(/^(.*?):\s*(.*?)\s*=\s*(\$[\d,.]+)\s*$/);
      if (m) return { label: `${m[1].trim()} (${m[2].trim()})`, amount: m[3] };
      const m2 = line.match(/^(.*?):\s*(.*)$/);
      if (m2) return { label: m2[1].trim(), amount: m2[2].trim() };
      return { label: line, amount: '' };
    });
    params.append('services', JSON.stringify(services));
  }
  return `${base}/agreement.html?${params.toString()}`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

