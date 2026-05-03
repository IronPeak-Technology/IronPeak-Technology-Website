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
    formData.append('to', 'quotes@ironpeak.technology');
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
          <p style="font-size: 0.9em;">This quote was generated automatically from the IronPeak Technology pricing calculator.</p>
        </div>
      </div>
    </body>
    </html>
  `;
}
