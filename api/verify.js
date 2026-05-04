const crypto = require('crypto');

/**
 * POST /api/verify
 * Handles multiple request types:
 * 1. Password verification for trading page
 * 2. Quote request emails from pricing calculator (via Mailgun HTTP API)
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

  const requestType = body?.type || 'password_verify';

  if (requestType === 'password_verify') {
    return handlePasswordVerification(body, res);
  } else if (requestType === 'quote_request') {
    return handleQuoteRequest(body, res);
  } else if (requestType === 'sign_agreement') {
    return handleSignAgreement(body, req, res);
  }

  return res.status(400).json({ error: 'Invalid request type' });
};

function handlePasswordVerification(body, res) {
  const submitted = typeof body?.password === 'string' ? body.password : '';
  const correct = process.env.TRADING_PASSWORD;

  if (!correct) {
    return res.status(500).json({ error: 'Server not configured' });
  }

  // Constant-time comparison prevents timing attacks
  const a = Buffer.from(submitted, 'utf8');
  const b = Buffer.from(correct, 'utf8');
  const match = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (match) {
    return res.status(200).json({ ok: true });
  }

  return res.status(401).json({ error: 'Invalid password' });
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

    // Prepare form data for Mailgun API
    const formData = new URLSearchParams();
    formData.append('from', `IronPeak Quote System <postmaster@${process.env.MAILGUN_DOMAIN}>`);
    formData.append('to', 'tfinch@ironpeaktechnology.com');
    formData.append('subject', body.subject);
    formData.append('text', emailText);
    formData.append('html', emailHtml);
    if (body.customerData?.email) {
      formData.append('h:Reply-To', body.customerData.email);
    }

    // Send email via Mailgun HTTP API
    const response = await fetch(`https://api.mailgun.net/v3/${process.env.MAILGUN_DOMAIN}/messages`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${Buffer.from(`api:${process.env.MAILGUN_API_KEY}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formData.toString()
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Mailgun API error:', response.status, errorText);
      throw new Error(`Mailgun API error: ${response.status} ${errorText}`);
    }

    const result = await response.json();
    
    console.log('Quote email sent successfully:', {
      messageId: result.id,
      company: body.customerData?.company,
      email: body.customerData?.email,
      total: body.quoteData?.total,
      timestamp: new Date().toISOString()
    });

    return res.status(200).json({ 
      ok: true, 
      message: 'Quote request sent successfully',
      messageId: result.id
    });

  } catch (error) {
    console.error('Error sending quote email:', error);
    return res.status(500).json({ 
      error: 'Failed to send quote request',
      details: error.message
    });
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
          <p><strong>Next Steps:</strong> Review this quote and follow up with the customer within 24 hours to finalize the agreement.</p>
          <p><strong>Send Agreement Link:</strong> <a href="${buildAgreementUrl(body)}">${buildAgreementUrl(body)}</a></p>
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

async function handleSignAgreement(body, req, res) {
  try {
    if (!process.env.MAILGUN_API_KEY || !process.env.MAILGUN_DOMAIN) {
      return res.status(500).json({ error: 'Email service not configured' });
    }

    const signed = body.signed || {};
    const agreement = body.agreement || {};

    if (!signed.name || !signed.email || !signed.company || !signed.agreed) {
      return res.status(400).json({ error: 'Missing required signature fields' });
    }

    const ip = (req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown').toString().split(',')[0].trim();
    const userAgent = req.headers['user-agent'] || 'unknown';
    const signedAt = signed.signedAt || new Date().toISOString();

    const html = formatSignedAgreementHtml({ signed, agreement, ip, userAgent, signedAt });
    const subject = `[SIGNED AGREEMENT] ${signed.company} — ${signed.name}`;

    // Send to Travis
    const internalForm = new URLSearchParams();
    internalForm.append('from', `IronPeak Agreements <postmaster@${process.env.MAILGUN_DOMAIN}>`);
    internalForm.append('to', 'tfinch@ironpeaktechnology.com');
    internalForm.append('subject', subject);
    internalForm.append('html', html);
    internalForm.append('h:Reply-To', signed.email);

    // Send copy to customer
    const customerForm = new URLSearchParams();
    customerForm.append('from', `IronPeak Technology <postmaster@${process.env.MAILGUN_DOMAIN}>`);
    customerForm.append('to', signed.email);
    customerForm.append('subject', `Signed Agreement Copy — IronPeak Technology LLC`);
    customerForm.append('html', html);
    customerForm.append('h:Reply-To', 'tfinch@ironpeaktechnology.com');

    const mailgunUrl = `https://api.mailgun.net/v3/${process.env.MAILGUN_DOMAIN}/messages`;
    const auth = `Basic ${Buffer.from(`api:${process.env.MAILGUN_API_KEY}`).toString('base64')}`;

    const [internalRes, customerRes] = await Promise.all([
      fetch(mailgunUrl, { method: 'POST', headers: { 'Authorization': auth, 'Content-Type': 'application/x-www-form-urlencoded' }, body: internalForm.toString() }),
      fetch(mailgunUrl, { method: 'POST', headers: { 'Authorization': auth, 'Content-Type': 'application/x-www-form-urlencoded' }, body: customerForm.toString() })
    ]);

    if (!internalRes.ok) {
      const t = await internalRes.text();
      console.error('Internal email failed:', internalRes.status, t);
      throw new Error(`Internal email failed: ${internalRes.status}`);
    }
    if (!customerRes.ok) {
      const t = await customerRes.text();
      console.error('Customer email failed:', customerRes.status, t);
      // Don't fail the request if just the customer copy fails — Travis still has the record
    }

    console.log('Agreement signed:', { company: signed.company, name: signed.name, email: signed.email, signedAt, ip });

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error('Error processing signed agreement:', error);
    return res.status(500).json({ error: 'Failed to process signed agreement', details: error.message });
  }
}

function formatSignedAgreementHtml({ signed, agreement, ip, userAgent, signedAt }) {
  const dateStr = new Date(signedAt).toLocaleString();
  const services = Array.isArray(agreement.services) ? agreement.services : [];
  const serviceRows = services.length
    ? services.map(s => `<tr><td style="padding:8px;border-bottom:1px solid #e5e7eb;">${escapeHtml(s.label)}</td><td style="padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;font-family:monospace;">${escapeHtml(s.amount || '')}</td></tr>`).join('')
    : `<tr><td colspan="2" style="padding:8px;font-style:italic;color:#6b7280;">${agreement.tier ? escapeHtml(agreement.tier) + ' plan' : 'See agreement'}</td></tr>`;

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signed Agreement</title></head>
<body style="font-family:Arial,sans-serif;line-height:1.5;color:#1f2937;max-width:760px;margin:0 auto;padding:24px;">
  <div style="background:#0f172a;color:#fff;padding:20px;border-radius:8px;margin-bottom:24px;">
    <h1 style="margin:0;font-size:22px;">✅ Signed Managed Services Agreement</h1>
    <p style="margin:6px 0 0 0;color:#cbd5e1;font-size:13px;">IronPeak Technology LLC &mdash; Executed ${dateStr}</p>
  </div>

  <h2 style="font-size:16px;border-bottom:2px solid #f97316;padding-bottom:6px;">Signature Record</h2>
  <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:24px;">
    <tr><td style="padding:6px;color:#6b7280;width:170px;">Signed By:</td><td style="padding:6px;font-weight:bold;">${escapeHtml(signed.name)}</td></tr>
    <tr><td style="padding:6px;color:#6b7280;">Title:</td><td style="padding:6px;">${escapeHtml(signed.title || '')}</td></tr>
    <tr><td style="padding:6px;color:#6b7280;">Company:</td><td style="padding:6px;font-weight:bold;">${escapeHtml(signed.company)}</td></tr>
    <tr><td style="padding:6px;color:#6b7280;">Email:</td><td style="padding:6px;"><a href="mailto:${escapeHtml(signed.email)}">${escapeHtml(signed.email)}</a></td></tr>
    <tr><td style="padding:6px;color:#6b7280;">Agreed to Terms:</td><td style="padding:6px;color:#16a34a;font-weight:bold;">YES</td></tr>
    <tr><td style="padding:6px;color:#6b7280;">Signed At:</td><td style="padding:6px;">${dateStr}</td></tr>
    <tr><td style="padding:6px;color:#6b7280;">IP Address:</td><td style="padding:6px;font-family:monospace;font-size:12px;">${escapeHtml(ip)}</td></tr>
    <tr><td style="padding:6px;color:#6b7280;">User Agent:</td><td style="padding:6px;font-size:11px;color:#6b7280;">${escapeHtml(userAgent)}</td></tr>
  </table>

  <h2 style="font-size:16px;border-bottom:2px solid #f97316;padding-bottom:6px;">Services Agreed To</h2>
  <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:8px;">
    <thead><tr style="background:#f3f4f6;"><th style="padding:8px;text-align:left;">Service</th><th style="padding:8px;text-align:right;">Amount</th></tr></thead>
    <tbody>${serviceRows}</tbody>
    <tfoot><tr style="background:#fef3c7;border-top:2px solid #0f172a;"><td style="padding:10px;font-weight:bold;">Monthly Total</td><td style="padding:10px;text-align:right;font-weight:bold;">$${(agreement.total || 0).toFixed(2)}</td></tr></tfoot>
  </table>
  <p style="font-size:12px;color:#6b7280;">Setup fee: $${((agreement.userCount || 0) * 2 * 100).toFixed(2)} one-time (${(agreement.userCount || 0) * 2} devices × $100). Out-of-scope work: $120/hour.</p>

  ${agreement.documentUrl ? `<p style="font-size:12px;color:#6b7280;margin-top:24px;">Original document: <a href="${escapeHtml(agreement.documentUrl)}">${escapeHtml(agreement.documentUrl)}</a></p>` : ''}

  <div style="margin-top:32px;padding-top:16px;border-top:1px solid #e5e7eb;font-size:11px;color:#9ca3af;text-align:center;">
    This is an electronically executed agreement. The typed name above constitutes a legally binding signature pursuant to the U.S. Electronic Signatures in Global and National Commerce Act (E-SIGN Act).
  </div>
</body></html>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

