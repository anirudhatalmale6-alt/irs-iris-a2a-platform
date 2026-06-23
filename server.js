const express = require('express');
const multer = require('multer');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const upload = multer({ dest: 'uploads/', limits: { fileSize: 5 * 1024 * 1024 } });

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());

// ── JWK Generation ──────────────────────────────────────────────────────────

function pemToJwk(certPem, privateKeyPem) {
  const cert = forge.pki.certificateFromPem(certPem);
  const pubKey = cert.publicKey;

  if (pubKey.n === undefined) {
    throw new Error('Certificate does not contain an RSA public key');
  }

  const n = Buffer.from(pubKey.n.toByteArray());
  const e = Buffer.from(pubKey.e.toByteArray());

  const nBase64url = trimLeadingZero(n).toString('base64url');
  const eBase64url = trimLeadingZero(e).toString('base64url');

  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const x5c = Buffer.from(derBytes, 'binary').toString('base64');

  const sha1 = crypto.createHash('sha1').update(Buffer.from(derBytes, 'binary')).digest();
  const x5t = sha1.toString('base64url');

  const kid = generateKid(cert);

  const jwk = {
    kty: 'RSA',
    kid: kid,
    use: 'sig',
    n: nBase64url,
    e: eBase64url,
    x5c: [x5c],
    x5t: x5t
  };

  const jwks = { keys: [jwk] };

  let privateJwk = null;
  if (privateKeyPem) {
    const privKey = forge.pki.privateKeyFromPem(privateKeyPem);
    privateJwk = {
      kty: 'RSA',
      kid: kid,
      use: 'sig',
      n: nBase64url,
      e: eBase64url,
      d: trimLeadingZero(Buffer.from(privKey.d.toByteArray())).toString('base64url'),
      p: trimLeadingZero(Buffer.from(privKey.p.toByteArray())).toString('base64url'),
      q: trimLeadingZero(Buffer.from(privKey.q.toByteArray())).toString('base64url'),
      dp: trimLeadingZero(Buffer.from(privKey.dP.toByteArray())).toString('base64url'),
      dq: trimLeadingZero(Buffer.from(privKey.dQ.toByteArray())).toString('base64url'),
      qi: trimLeadingZero(Buffer.from(privKey.qInv.toByteArray())).toString('base64url'),
      x5c: [x5c],
      x5t: x5t
    };
  }

  const certInfo = {
    subject: cert.subject.attributes.map(a => `${a.shortName}=${a.value}`).join(', '),
    issuer: cert.issuer.attributes.map(a => `${a.shortName}=${a.value}`).join(', '),
    validFrom: cert.validity.notBefore.toISOString(),
    validTo: cert.validity.notAfter.toISOString(),
    serialNumber: cert.serialNumber,
    isExpired: new Date() > cert.validity.notAfter
  };

  return { jwks, privateJwk, certInfo };
}

function trimLeadingZero(buf) {
  if (buf[0] === 0 && buf.length > 1) {
    return buf.slice(1);
  }
  return buf;
}

function generateKid(cert) {
  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  return crypto.createHash('sha256').update(Buffer.from(derBytes, 'binary')).digest('hex').substring(0, 16);
}

// ── API Routes ──────────────────────────────────────────────────────────────

const api = express.Router();

api.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0' });
});

api.post('/jwk/generate-pfx', upload.single('pfx'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'PFX file is required' });
    }

    const pfxPassword = req.body.password || '';
    const pfxBuf = fs.readFileSync(req.file.path);
    const pfxAsn1 = forge.asn1.fromDer(pfxBuf.toString('binary'));
    const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, pfxPassword);

    const certBags = pfx.getBags({ bagType: forge.pki.oids.certBag });
    const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });

    const certBag = (certBags[forge.pki.oids.certBag] || [])[0];
    const keyBag = (keyBags[forge.pki.oids.pkcs8ShroudedKeyBag] || [])[0];

    if (!certBag || !certBag.cert) {
      return res.status(400).json({ error: 'No certificate found in PFX file' });
    }

    const certPem = forge.pki.certificateToPem(certBag.cert);
    const privateKeyPem = keyBag && keyBag.key ? forge.pki.privateKeyToPem(keyBag.key) : null;

    try { fs.unlinkSync(req.file.path); } catch (_) {}

    const result = pemToJwk(certPem, privateKeyPem);

    res.json({
      success: true,
      jwks: result.jwks,
      privateJwk: result.privateJwk,
      certInfo: result.certInfo,
      instructions: [
        'Copy the JWKS JSON below and paste it into the IRS API Client ID application.',
        'Make sure to include the full JSON including the opening { and closing }.',
        'The attributes are in the exact order required by IRS Publication 5718.',
        'Keep your private JWK secure - you will need it to sign JWTs for A2A authentication.'
      ]
    });
  } catch (err) {
    if (req.file) { try { fs.unlinkSync(req.file.path); } catch (_) {} }
    const msg = err.message.includes('Invalid password') || err.message.includes('PKCS#12')
      ? 'Invalid PFX password or corrupted file. Please check the password and try again.'
      : err.message;
    res.status(400).json({ error: msg });
  }
});

api.post('/jwk/generate', upload.fields([
  { name: 'cert', maxCount: 1 },
  { name: 'privateKey', maxCount: 1 }
]), (req, res) => {
  try {
    let certPem, privateKeyPem;

    if (req.files && req.files.cert) {
      certPem = fs.readFileSync(req.files.cert[0].path, 'utf8');
    } else if (req.body.certPem) {
      certPem = req.body.certPem;
    } else {
      return res.status(400).json({ error: 'Certificate is required' });
    }

    if (req.files && req.files.privateKey) {
      privateKeyPem = fs.readFileSync(req.files.privateKey[0].path, 'utf8');
    } else if (req.body.privateKeyPem) {
      privateKeyPem = req.body.privateKeyPem;
    }

    certPem = certPem.trim();
    if (privateKeyPem) privateKeyPem = privateKeyPem.trim();

    const result = pemToJwk(certPem, privateKeyPem);

    if (req.files) {
      Object.values(req.files).flat().forEach(f => {
        try { fs.unlinkSync(f.path); } catch (_) {}
      });
    }

    res.json({
      success: true,
      jwks: result.jwks,
      privateJwk: result.privateJwk,
      certInfo: result.certInfo,
      instructions: [
        'Copy the JWKS JSON below and paste it into the IRS API Client ID application.',
        'Make sure to include the full JSON including the opening { and closing }.',
        'The attributes are in the exact order required by IRS Publication 5718.',
        'Keep your private JWK secure - you will need it to sign JWTs for A2A authentication.'
      ]
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.post('/jwk/validate', (req, res) => {
  try {
    const { jwk } = req.body;
    if (!jwk) return res.status(400).json({ error: 'JWK object is required' });

    const requiredFields = ['kty', 'kid', 'use', 'n', 'e', 'x5c', 'x5t'];
    const errors = [];
    const warnings = [];

    for (const field of requiredFields) {
      if (!(field in jwk)) {
        errors.push(`Missing required attribute: ${field}`);
      }
    }

    if (jwk.kty && jwk.kty !== 'RSA') {
      errors.push(`kty must be "RSA", got "${jwk.kty}"`);
    }
    if (jwk.use && jwk.use !== 'sig') {
      errors.push(`use must be "sig", got "${jwk.use}"`);
    }
    if (jwk.e) {
      const eDecoded = Buffer.from(jwk.e, 'base64url');
      const eHex = eDecoded.toString('hex');
      if (eHex !== '010001') {
        warnings.push('Unusual public exponent. IRS expects AQAB (65537).');
      }
    }

    const fieldOrder = Object.keys(jwk);
    const expectedOrder = ['kty', 'kid', 'use', 'n', 'e', 'x5c', 'x5t'];
    const actualOrder = fieldOrder.filter(f => expectedOrder.includes(f));
    if (JSON.stringify(actualOrder) !== JSON.stringify(expectedOrder)) {
      warnings.push('Attributes are not in the order required by IRS. Expected: kty, kid, use, n, e, x5c, x5t');
    }

    const extraFields = fieldOrder.filter(f => !expectedOrder.includes(f));
    if (extraFields.length > 0) {
      warnings.push(`Extra attributes found that should be removed per IRS guidelines: ${extraFields.join(', ')}`);
    }

    res.json({ valid: errors.length === 0, errors, warnings });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.post('/a2a/client-jwt', (req, res) => {
  try {
    const privateKeyPem = req.body.privateKeyPem || appConfig.privateKeyPem;
    const clientId = req.body.clientId || appConfig.clientId;
    if (!privateKeyPem || !clientId) {
      return res.status(400).json({ error: 'Private key and Client ID are required. Configure them in Settings.' });
    }

    const tokenUrl = req.body.irsTokenUrl || (appConfig.environment === 'production' ? 'https://api.irs.gov/auth/oauth/v2/token' : 'https://api.test.irs.gov/auth/oauth/v2/token');
    const now = Math.floor(Date.now() / 1000);
    const payload = { iss: clientId, sub: clientId, aud: tokenUrl, iat: now, exp: now + 300 };

    const token = jwt.sign(payload, privateKeyPem, {
      algorithm: 'RS256',
      header: { alg: 'RS256', typ: 'JWT' }
    });

    res.json({ success: true, clientJwt: token, expiresIn: 300 });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.post('/a2a/user-jwt', (req, res) => {
  try {
    const privateKeyPem = req.body.privateKeyPem || appConfig.privateKeyPem;
    const clientId = req.body.clientId || appConfig.clientId;
    const userId = req.body.userId;
    if (!privateKeyPem || !clientId || !userId) {
      return res.status(400).json({ error: 'Private key, Client ID, and User ID are required. Configure key/ID in Settings.' });
    }

    const tokenUrl = req.body.irsTokenUrl || (appConfig.environment === 'production' ? 'https://api.irs.gov/auth/oauth/v2/token' : 'https://api.test.irs.gov/auth/oauth/v2/token');
    const now = Math.floor(Date.now() / 1000);
    const payload = { iss: clientId, sub: userId, aud: tokenUrl, iat: now, exp: now + 300 };

    const token = jwt.sign(payload, privateKeyPem, {
      algorithm: 'RS256',
      header: { alg: 'RS256', typ: 'JWT' }
    });

    res.json({ success: true, userJwt: token, expiresIn: 300 });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.post('/a2a/get-access-token', async (req, res) => {
  try {
    const privateKeyPem = appConfig.privateKeyPem;
    const clientId = appConfig.clientId;
    const userId = req.body.userId || appConfig.transmitterTIN;
    if (!privateKeyPem || !clientId) {
      return res.status(400).json({ error: 'Private key and Client ID not configured. Go to Settings first.' });
    }

    const tokenUrl = appConfig.environment === 'production'
      ? 'https://api.irs.gov/auth/oauth/v2/token'
      : 'https://api.test.irs.gov/auth/oauth/v2/token';

    const now = Math.floor(Date.now() / 1000);

    const clientJwtPayload = { iss: clientId, sub: clientId, aud: tokenUrl, iat: now, exp: now + 300 };
    const clientJwt = jwt.sign(clientJwtPayload, privateKeyPem, { algorithm: 'RS256', header: { alg: 'RS256', typ: 'JWT' } });

    const userJwtPayload = { iss: clientId, sub: userId, aud: tokenUrl, iat: now, exp: now + 300 };
    const userJwt = jwt.sign(userJwtPayload, privateKeyPem, { algorithm: 'RS256', header: { alg: 'RS256', typ: 'JWT' } });

    const https = require('https');
    const querystring = require('querystring');
    const postData = querystring.stringify({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: clientJwt,
      user_assertion_type: 'urn:ietf:params:oauth:user-assertion-type:jwt-bearer',
      user_assertion: userJwt
    });

    res.json({
      success: true,
      clientJwt,
      userJwt,
      tokenUrl,
      environment: appConfig.environment,
      userId,
      postData,
      message: 'JWTs generated. Use these to request an access token from the IRS Authorization Server.'
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── IRIS Transmission Routes ────────────────────────────────────────────────

const A2AAuth = require('./lib/a2a-auth');
const IRISClient = require('./lib/iris-client');
const { buildManifest, buildTransmissionXML, FORM_TYPES } = require('./lib/iris-builder');

const CONFIG_FILE = path.join(__dirname, 'data', 'config.json');

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    }
  } catch (e) { /* ignore corrupt config */ }
  // Fall back to environment variables (for Render/cloud deployments)
  const env = process.env;
  return {
    clientId: env.IRS_CLIENT_ID || null,
    privateKeyPem: env.IRS_PRIVATE_KEY ? env.IRS_PRIVATE_KEY.replace(/\\n/g, '\n') : null,
    environment: env.IRS_ENVIRONMENT || 'test',
    transmitterTIN: env.IRS_TRANSMITTER_TIN || null,
    transmitterName: env.IRS_TRANSMITTER_NAME || null,
    stripeSecretKey: env.STRIPE_SECRET_KEY || null,
    ppClientId: env.PAYPAL_CLIENT_ID || null,
    ppClientSecret: env.PAYPAL_CLIENT_SECRET || null,
    ppEnvironment: env.PAYPAL_ENVIRONMENT || 'sandbox',
    qbClientId: env.QB_CLIENT_ID || null,
    qbClientSecret: env.QB_CLIENT_SECRET || null,
    qbEnvironment: env.QB_ENVIRONMENT || 'sandbox'
  };
}

function saveConfig() {
  fs.mkdirSync(path.dirname(CONFIG_FILE), { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(appConfig, null, 2));
}

let appConfig = loadConfig();

api.post('/config/save', (req, res) => {
  const { clientId, privateKeyPem, environment, transmitterTIN, transmitterName } = req.body;
  if (clientId) appConfig.clientId = clientId;
  if (privateKeyPem) appConfig.privateKeyPem = privateKeyPem;
  if (environment) appConfig.environment = environment;
  if (transmitterTIN) appConfig.transmitterTIN = transmitterTIN;
  if (transmitterName) appConfig.transmitterName = transmitterName;
  saveConfig();
  res.json({ success: true, config: { ...appConfig, privateKeyPem: appConfig.privateKeyPem ? '[SET]' : null, stripeSecretKey: appConfig.stripeSecretKey ? '[SET]' : null } });
});

api.get('/config', (req, res) => {
  const swiftCfg = appConfig.swiftConfig || {};
  res.json({
    clientId: appConfig.clientId,
    hasPrivateKey: !!appConfig.privateKeyPem,
    environment: appConfig.environment,
    transmitterTIN: appConfig.transmitterTIN,
    transmitterName: appConfig.transmitterName,
    hasStripeKey: !!appConfig.stripeSecretKey,
    hasSwiftConfig: !!(swiftCfg.swiftBIC && swiftCfg.bankName && swiftCfg.accountNumber),
    hasQuickBooks: !!(appConfig.qbAccessToken && appConfig.qbRealmId),
    qbConfigured: !!(appConfig.qbClientId && appConfig.qbClientSecret),
    hasPayPal: !!(appConfig.ppClientId && appConfig.ppClientSecret),
    ppEnvironment: appConfig.ppEnvironment || 'sandbox'
  });
});

api.post('/iris/build-xml', (req, res) => {
  try {
    const { formType, records, taxYear } = req.body;

    if (!formType || !records || !records.length) {
      return res.status(400).json({ error: 'formType and records are required' });
    }

    if (!FORM_TYPES[formType]) {
      return res.status(400).json({ error: `Unsupported form type: ${formType}. Supported: ${Object.keys(FORM_TYPES).join(', ')}` });
    }

    const manifest = buildManifest({
      transmitterTIN: appConfig.transmitterTIN || 'PENDING',
      transmitterName: appConfig.transmitterName || 'PENDING',
      taxYear: taxYear || String(new Date().getFullYear()),
      totalPayeeCount: records.length
    });

    const xml = buildTransmissionXML({ manifest, formType, records });

    res.json({ success: true, xml, manifest });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.post('/iris/submit', async (req, res) => {
  try {
    const { formType, records, taxYear, userId } = req.body;

    if (!appConfig.clientId || !appConfig.privateKeyPem) {
      return res.status(400).json({ error: 'API configuration is incomplete. Set your Client ID and private key first.' });
    }

    if (!formType || !records || !records.length) {
      return res.status(400).json({ error: 'formType and records are required' });
    }

    if (!userId) {
      return res.status(400).json({ error: 'userId is required for A2A authentication' });
    }

    const manifest = buildManifest({
      transmitterTIN: appConfig.transmitterTIN,
      transmitterName: appConfig.transmitterName,
      taxYear: taxYear || String(new Date().getFullYear()),
      totalPayeeCount: records.length
    });

    const xml = buildTransmissionXML({ manifest, formType, records });

    const auth = new A2AAuth({
      clientId: appConfig.clientId,
      privateKeyPem: appConfig.privateKeyPem,
      environment: appConfig.environment
    });

    const accessToken = await auth.getAccessToken(userId);

    const irisClient = new IRISClient({ environment: appConfig.environment });
    const result = await irisClient.submitTransmission(accessToken, xml);

    res.json({
      success: true,
      transmissionId: manifest.UniqueTransmissionId,
      irsResponse: result
    });
  } catch (err) {
    const status = err.response ? err.response.status : 500;
    const detail = err.response ? err.response.data : err.message;
    res.status(status).json({ error: 'Submission failed', detail });
  }
});

api.get('/iris/status/:transmissionId', async (req, res) => {
  try {
    if (!appConfig.clientId || !appConfig.privateKeyPem) {
      return res.status(400).json({ error: 'API configuration is incomplete' });
    }

    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ error: 'userId query parameter is required' });
    }

    const auth = new A2AAuth({
      clientId: appConfig.clientId,
      privateKeyPem: appConfig.privateKeyPem,
      environment: appConfig.environment
    });

    const accessToken = await auth.getAccessToken(userId);
    const irisClient = new IRISClient({ environment: appConfig.environment });
    const result = await irisClient.getTransmissionStatus(accessToken, req.params.transmissionId);

    res.json({ success: true, status: result });
  } catch (err) {
    const detail = err.response ? err.response.data : err.message;
    res.status(500).json({ error: 'Status check failed', detail });
  }
});

api.get('/iris/form-types', (req, res) => {
  res.json({ formTypes: Object.keys(FORM_TYPES) });
});

// ── Submission Tracking ─────────────────────────────────────────────────────

const db = require('./lib/db');

api.post('/submissions/record', (req, res) => {
  try {
    const { formType, transactionId, receiptNumber, submissionId, recipientName, amount, taxYear, notes } = req.body;
    if (!transactionId || !submissionId) {
      return res.status(400).json({ error: 'transactionId and submissionId are required' });
    }
    const submission = db.addSubmission({
      id: transactionId,
      formType: formType || 'Unknown',
      transactionId,
      receiptNumber: receiptNumber || '',
      submissionId,
      recipientName: recipientName || '',
      amount: amount || '0.00',
      taxYear: taxYear || String(new Date().getFullYear()),
      notes: notes || '',
      status: 'accepted',
      payoutStatus: 'pending'
    });
    res.json({ success: true, submission });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.get('/submissions', (req, res) => {
  res.json({ submissions: db.readAll() });
});

api.get('/submissions/:id', (req, res) => {
  const sub = db.getSubmission(req.params.id);
  if (!sub) return res.status(404).json({ error: 'Submission not found' });
  res.json({ submission: sub });
});

// ── Stripe Payout Routes ────────────────────────────────────────────────────

const StripePayouts = require('./lib/stripe-payouts');

api.post('/stripe/config', (req, res) => {
  const { stripeSecretKey } = req.body;
  if (!stripeSecretKey) return res.status(400).json({ error: 'stripeSecretKey is required' });
  appConfig.stripeSecretKey = stripeSecretKey;
  saveConfig();
  res.json({ success: true, message: 'Stripe configured' });
});

api.post('/stripe/payout', async (req, res) => {
  try {
    if (!appConfig.stripeSecretKey) {
      return res.status(400).json({ error: 'Stripe is not configured. Add your secret key in Settings.' });
    }

    const { submissionId, recipientEmail, recipientName, amount, description } = req.body;
    if (!amount || !recipientEmail) {
      return res.status(400).json({ error: 'amount and recipientEmail are required' });
    }

    const stripe = new StripePayouts(appConfig.stripeSecretKey);

    const paymentIntent = await stripe.createPaymentIntent({
      amount: parseFloat(amount),
      description: description || `Payout for submission ${submissionId}`,
      metadata: { submissionId: submissionId || '', recipientName: recipientName || '' }
    });

    const payout = db.addPayout({
      id: paymentIntent.id,
      submissionId: submissionId || '',
      recipientEmail,
      recipientName: recipientName || '',
      amount: parseFloat(amount),
      status: paymentIntent.status,
      stripeId: paymentIntent.id
    });

    if (submissionId) {
      db.updateSubmission(submissionId, { payoutStatus: 'initiated', payoutId: paymentIntent.id });
    }

    res.json({ success: true, payout, stripePaymentIntent: paymentIntent });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.post('/stripe/transfer', async (req, res) => {
  try {
    if (!appConfig.stripeSecretKey) {
      return res.status(400).json({ error: 'Stripe is not configured' });
    }

    const { amount, destinationAccountId, description, submissionId } = req.body;
    if (!amount || !destinationAccountId) {
      return res.status(400).json({ error: 'amount and destinationAccountId are required' });
    }

    const stripe = new StripePayouts(appConfig.stripeSecretKey);
    const transfer = await stripe.createTransfer({
      amount: parseFloat(amount),
      destination: destinationAccountId,
      description: description || `Transfer for submission ${submissionId}`,
      metadata: { submissionId: submissionId || '' }
    });

    const payout = db.addPayout({
      id: transfer.id,
      submissionId: submissionId || '',
      destinationAccountId,
      amount: parseFloat(amount),
      status: 'transferred',
      stripeId: transfer.id,
      type: 'transfer'
    });

    if (submissionId) {
      db.updateSubmission(submissionId, { payoutStatus: 'transferred', payoutId: transfer.id });
    }

    res.json({ success: true, payout, stripeTransfer: transfer });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.get('/stripe/balance', async (req, res) => {
  try {
    if (!appConfig.stripeSecretKey) {
      return res.status(400).json({ error: 'Stripe is not configured' });
    }
    const stripe = new StripePayouts(appConfig.stripeSecretKey);
    const balance = await stripe.getBalance();
    res.json({ success: true, balance });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.get('/payouts', (req, res) => {
  res.json({ payouts: db.getPayouts() });
});

api.post('/record-distribution', (req, res) => {
  try {
    const { submissionId, amount, recipientName, recipientEmail, description, method } = req.body;
    if (!amount) return res.status(400).json({ error: 'amount is required' });

    const id = 'DIST-' + crypto.randomBytes(6).toString('hex');
    const payout = db.addPayout({
      id,
      submissionId: submissionId || '',
      recipientEmail: recipientEmail || '',
      recipientName: recipientName || '',
      amount: parseFloat(amount),
      status: 'completed',
      type: method || 'manual_bank_transfer',
      description: description || ''
    });

    if (submissionId) {
      db.updateSubmission(submissionId, { payoutStatus: 'distributed', payoutId: id });
    }

    res.json({ success: true, payout });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.post('/stripe/checkout', async (req, res) => {
  try {
    if (!appConfig.stripeSecretKey) {
      return res.status(400).json({ error: 'Stripe is not configured. Add your secret key in Settings.' });
    }

    const { submissionId, amount, recipientName, description } = req.body;
    if (!amount) {
      return res.status(400).json({ error: 'amount is required' });
    }

    const stripe = new StripePayouts(appConfig.stripeSecretKey);
    const baseUrl = `${req.protocol}://${req.get('host')}`;

    const session = await stripe.stripe.checkout.sessions.create({
      payment_method_types: ['card', 'us_bank_account'],
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: description || `Payment for ${recipientName || 'IRS Submission'}`,
            description: submissionId ? `IRS Transaction: ${submissionId.substring(0, 20)}...` : undefined
          },
          unit_amount: Math.round(parseFloat(amount) * 100)
        },
        quantity: 1
      }],
      success_url: `${baseUrl}?payment=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${baseUrl}?payment=cancelled`,
      metadata: { submissionId: submissionId || '', recipientName: recipientName || '' }
    });

    if (submissionId) {
      db.updateSubmission(submissionId, { collectStatus: 'link_created', checkoutSessionId: session.id, checkoutUrl: session.url });
    }

    res.json({ success: true, checkoutUrl: session.url, sessionId: session.id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.post('/stripe/send-payout', async (req, res) => {
  try {
    if (!appConfig.stripeSecretKey) {
      return res.status(400).json({ error: 'Stripe is not configured. Add your secret key in Settings.' });
    }

    const { submissionId, amount, recipientEmail, recipientName, description } = req.body;
    if (!amount) {
      return res.status(400).json({ error: 'amount is required' });
    }

    const stripe = new StripePayouts(appConfig.stripeSecretKey);
    const bal = await stripe.getBalance();
    const available = (bal.available || []).reduce((sum, b) => sum + (b.currency === 'usd' ? b.amount : 0), 0) / 100;

    if (available < parseFloat(amount)) {
      return res.status(400).json({
        error: `Insufficient Stripe balance. Available: $${available.toFixed(2)}, Requested: $${parseFloat(amount).toFixed(2)}. Funds may still be pending (takes 2 business days after collection). Use PayPal or Wire Transfer to distribute from other sources.`
      });
    }

    const payout = await stripe.createPayout({
      amount: parseFloat(amount),
      description: description || `Distribution - ${recipientName || recipientEmail || submissionId || 'manual'}`
    });

    const record = db.addPayout({
      id: payout.id,
      submissionId: submissionId || '',
      recipientEmail: recipientEmail || '',
      recipientName: recipientName || '',
      amount: parseFloat(amount),
      status: payout.status,
      stripeId: payout.id,
      type: 'stripe_payout'
    });

    if (submissionId) {
      db.updateSubmission(submissionId, { payoutStatus: 'distributed', payoutId: payout.id });
    }

    res.json({ success: true, payout: record, stripePaymentIntent: { id: payout.id, status: payout.status } });
  } catch (err) {
    const msg = err.message || '';
    if (msg.includes('balance') || msg.includes('insufficient')) {
      return res.status(400).json({ error: 'Insufficient Stripe balance. Collected funds may still be pending. Use PayPal Payout or Wire Transfer instead.' });
    }
    res.status(400).json({ error: err.message });
  }
});

// ── QuickBooks Integration ─────────────────────────────────────────────────

const axios = require('axios');

const QB_AUTH_URL = 'https://appcenter.intuit.com/connect/oauth2';
const QB_TOKEN_URL = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
const QB_API_BASE = 'https://quickbooks.api.intuit.com/v3/company';
const QB_SANDBOX_API = 'https://sandbox-quickbooks.api.intuit.com/v3/company';

function getQBApiBase() {
  return (appConfig.qbEnvironment === 'production') ? QB_API_BASE : QB_SANDBOX_API;
}

async function refreshQBToken() {
  if (!appConfig.qbRefreshToken || !appConfig.qbClientId || !appConfig.qbClientSecret) return null;
  try {
    const res = await axios.post(QB_TOKEN_URL, new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: appConfig.qbRefreshToken
    }).toString(), {
      headers: {
        'Authorization': 'Basic ' + Buffer.from(appConfig.qbClientId + ':' + appConfig.qbClientSecret).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    appConfig.qbAccessToken = res.data.access_token;
    appConfig.qbRefreshToken = res.data.refresh_token;
    appConfig.qbTokenExpiry = Date.now() + (res.data.expires_in * 1000);
    saveConfig();
    return appConfig.qbAccessToken;
  } catch (err) {
    console.error('QB token refresh failed:', err.message);
    return null;
  }
}

async function getQBToken() {
  if (appConfig.qbAccessToken && appConfig.qbTokenExpiry && Date.now() < appConfig.qbTokenExpiry - 60000) {
    return appConfig.qbAccessToken;
  }
  return refreshQBToken();
}

api.post('/quickbooks/config', (req, res) => {
  const { qbClientId, qbClientSecret, qbEnvironment } = req.body;
  if (!qbClientId || !qbClientSecret) {
    return res.status(400).json({ error: 'QuickBooks Client ID and Client Secret are required' });
  }
  appConfig.qbClientId = qbClientId;
  appConfig.qbClientSecret = qbClientSecret;
  appConfig.qbEnvironment = qbEnvironment || 'sandbox';
  saveConfig();
  res.json({ success: true, message: 'QuickBooks credentials saved. Now connect your QuickBooks account.' });
});

api.get('/quickbooks/connect', (req, res) => {
  if (!appConfig.qbClientId) {
    return res.status(400).json({ error: 'QuickBooks Client ID not configured. Save your credentials first.' });
  }
  const redirectUri = `${req.protocol}://${req.get('host')}/api/quickbooks/callback`;
  const scope = 'com.intuit.quickbooks.accounting';
  const state = crypto.randomBytes(16).toString('hex');
  appConfig.qbOAuthState = state;
  saveConfig();

  const authUrl = `${QB_AUTH_URL}?client_id=${encodeURIComponent(appConfig.qbClientId)}&response_type=code&scope=${encodeURIComponent(scope)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;
  res.json({ success: true, authUrl });
});

api.get('/quickbooks/callback', async (req, res) => {
  try {
    const { code, state, realmId } = req.query;
    if (state !== appConfig.qbOAuthState) {
      return res.status(400).send('Invalid OAuth state. Please try connecting again.');
    }

    const redirectUri = `${req.protocol}://${req.get('host')}/api/quickbooks/callback`;
    const tokenRes = await axios.post(QB_TOKEN_URL, new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri
    }).toString(), {
      headers: {
        'Authorization': 'Basic ' + Buffer.from(appConfig.qbClientId + ':' + appConfig.qbClientSecret).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    appConfig.qbAccessToken = tokenRes.data.access_token;
    appConfig.qbRefreshToken = tokenRes.data.refresh_token;
    appConfig.qbTokenExpiry = Date.now() + (tokenRes.data.expires_in * 1000);
    appConfig.qbRealmId = realmId;
    saveConfig();

    res.send('<html><body style="background:#0f1117;color:#e4e7ef;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;"><div style="text-align:center;"><h1 style="color:#34d399;">QuickBooks Connected!</h1><p>You can close this window and return to the app.</p><script>setTimeout(function(){window.close();},3000);</script></div></body></html>');
  } catch (err) {
    res.status(500).send('QuickBooks connection failed: ' + err.message);
  }
});

api.get('/quickbooks/status', (req, res) => {
  res.json({
    configured: !!(appConfig.qbClientId && appConfig.qbClientSecret),
    connected: !!(appConfig.qbAccessToken && appConfig.qbRealmId),
    realmId: appConfig.qbRealmId || null,
    environment: appConfig.qbEnvironment || 'sandbox'
  });
});

api.post('/quickbooks/create-credit', async (req, res) => {
  try {
    const token = await getQBToken();
    if (!token) {
      return res.status(401).json({ error: 'QuickBooks not connected or token expired. Please reconnect.' });
    }

    const { amount, recipientName, transactionId, formType, notes } = req.body;
    if (!amount) return res.status(400).json({ error: 'Amount is required' });

    const journalEntry = {
      Line: [
        {
          Amount: parseFloat(amount),
          DetailType: 'JournalEntryLineDetail',
          JournalEntryLineDetail: {
            PostingType: 'Debit',
            AccountRef: { name: 'Accounts Receivable (A/R)' }
          },
          Description: `IRS IRIS Credit - ${formType || '1099'} - ${transactionId || 'N/A'}`
        },
        {
          Amount: parseFloat(amount),
          DetailType: 'JournalEntryLineDetail',
          JournalEntryLineDetail: {
            PostingType: 'Credit',
            AccountRef: { name: 'Other Income' }
          },
          Description: `IRS IRIS Credit - ${recipientName || ''} - ${transactionId || 'N/A'}`
        }
      ],
      PrivateNote: `IRS Transaction: ${transactionId || 'N/A'} | Form: ${formType || 'N/A'} | ${notes || ''}`
    };

    const qbRes = await axios.post(
      `${getQBApiBase()}/${appConfig.qbRealmId}/journalentry?minorversion=65`,
      journalEntry,
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      }
    );

    res.json({
      success: true,
      journalEntryId: qbRes.data.JournalEntry.Id,
      message: `Credit of $${amount} recorded in QuickBooks as Journal Entry #${qbRes.data.JournalEntry.Id}`
    });
  } catch (err) {
    const detail = err.response ? err.response.data : err.message;
    res.status(400).json({ error: 'QuickBooks credit creation failed', detail });
  }
});

api.post('/quickbooks/disconnect', (req, res) => {
  delete appConfig.qbAccessToken;
  delete appConfig.qbRefreshToken;
  delete appConfig.qbTokenExpiry;
  delete appConfig.qbRealmId;
  delete appConfig.qbOAuthState;
  saveConfig();
  res.json({ success: true, message: 'QuickBooks disconnected' });
});

// ── PayPal Integration ────────────────────────────────────────────────────

const PP_LIVE_URL = 'https://api-m.paypal.com';
const PP_SANDBOX_URL = 'https://api-m.sandbox.paypal.com';

function getPPBase() {
  return (appConfig.ppEnvironment === 'production') ? PP_LIVE_URL : PP_SANDBOX_URL;
}

async function getPPToken() {
  if (!appConfig.ppClientId || !appConfig.ppClientSecret) return null;
  if (appConfig.ppAccessToken && appConfig.ppTokenExpiry && Date.now() < appConfig.ppTokenExpiry - 30000) {
    return appConfig.ppAccessToken;
  }
  try {
    const res = await axios.post(`${getPPBase()}/v1/oauth2/token`, 'grant_type=client_credentials', {
      headers: {
        'Authorization': 'Basic ' + Buffer.from(appConfig.ppClientId + ':' + appConfig.ppClientSecret).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    appConfig.ppAccessToken = res.data.access_token;
    appConfig.ppTokenExpiry = Date.now() + (res.data.expires_in * 1000);
    return appConfig.ppAccessToken;
  } catch (err) {
    console.error('PayPal token failed:', err.message);
    return null;
  }
}

api.post('/paypal/config', (req, res) => {
  const { ppClientId, ppClientSecret, ppEnvironment } = req.body;
  if (!ppClientId || !ppClientSecret) {
    return res.status(400).json({ error: 'PayPal Client ID and Secret are required' });
  }
  appConfig.ppClientId = ppClientId;
  appConfig.ppClientSecret = ppClientSecret;
  appConfig.ppEnvironment = ppEnvironment || 'sandbox';
  saveConfig();
  res.json({ success: true, message: 'PayPal configured' });
});

api.get('/paypal/status', (req, res) => {
  res.json({
    configured: !!(appConfig.ppClientId && appConfig.ppClientSecret),
    environment: appConfig.ppEnvironment || 'sandbox'
  });
});

api.post('/paypal/create-order', async (req, res) => {
  try {
    const token = await getPPToken();
    if (!token) return res.status(400).json({ error: 'PayPal not configured or credentials invalid' });

    const { submissionId, amount, recipientName, description } = req.body;
    if (!amount) return res.status(400).json({ error: 'Amount is required' });

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const orderRes = await axios.post(`${getPPBase()}/v2/checkout/orders`, {
      intent: 'CAPTURE',
      purchase_units: [{
        amount: { currency_code: 'USD', value: parseFloat(amount).toFixed(2) },
        description: description || `IRS 1099 Credit - ${recipientName || 'Payment'}`,
        custom_id: submissionId || ''
      }],
      application_context: {
        return_url: `${baseUrl}?paypal=success`,
        cancel_url: `${baseUrl}?paypal=cancelled`,
        brand_name: 'IRS IRIS Platform',
        user_action: 'PAY_NOW'
      }
    }, {
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
    });

    const approveLink = orderRes.data.links.find(l => l.rel === 'approve');

    if (submissionId) {
      db.updateSubmission(submissionId, { ppOrderId: orderRes.data.id, ppStatus: 'created' });
    }

    res.json({
      success: true,
      orderId: orderRes.data.id,
      approveUrl: approveLink ? approveLink.href : null
    });
  } catch (err) {
    const detail = err.response ? err.response.data : err.message;
    res.status(400).json({ error: 'PayPal order creation failed', detail });
  }
});

api.post('/paypal/capture-order', async (req, res) => {
  try {
    const token = await getPPToken();
    if (!token) return res.status(400).json({ error: 'PayPal not configured' });

    const { orderId, submissionId } = req.body;
    if (!orderId) return res.status(400).json({ error: 'Order ID is required' });

    const captureRes = await axios.post(`${getPPBase()}/v2/checkout/orders/${orderId}/capture`, {}, {
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
    });

    if (submissionId) {
      db.updateSubmission(submissionId, { ppStatus: 'captured', collectStatus: 'collected' });
    }

    res.json({ success: true, capture: captureRes.data });
  } catch (err) {
    const detail = err.response ? err.response.data : err.message;
    res.status(400).json({ error: 'PayPal capture failed', detail });
  }
});

api.post('/paypal/send-payout', async (req, res) => {
  try {
    const token = await getPPToken();
    if (!token) return res.status(400).json({ error: 'PayPal not configured' });

    const { submissionId, amount, recipientEmail, recipientName, description } = req.body;
    if (!amount || !recipientEmail) {
      return res.status(400).json({ error: 'Amount and recipient email are required' });
    }

    const payoutRes = await axios.post(`${getPPBase()}/v1/payments/payouts`, {
      sender_batch_header: {
        sender_batch_id: 'IRS-' + crypto.randomBytes(8).toString('hex'),
        email_subject: description || 'You have received a payment',
        email_message: `Payment of $${amount} for IRS 1099 submission`
      },
      items: [{
        recipient_type: 'EMAIL',
        amount: { value: parseFloat(amount).toFixed(2), currency: 'USD' },
        receiver: recipientEmail,
        note: `IRS Credit Distribution - ${recipientName || ''} - ${submissionId || ''}`,
        sender_item_id: submissionId || crypto.randomBytes(4).toString('hex')
      }]
    }, {
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
    });

    const payout = db.addPayout({
      id: payoutRes.data.batch_header.payout_batch_id,
      submissionId: submissionId || '',
      recipientEmail,
      recipientName: recipientName || '',
      amount: parseFloat(amount),
      status: payoutRes.data.batch_header.batch_status,
      paypalBatchId: payoutRes.data.batch_header.payout_batch_id,
      type: 'paypal'
    });

    if (submissionId) {
      db.updateSubmission(submissionId, { payoutStatus: 'distributed', payoutId: payoutRes.data.batch_header.payout_batch_id });
    }

    res.json({ success: true, payout, paypalBatch: payoutRes.data.batch_header });
  } catch (err) {
    const detail = err.response ? err.response.data : err.message;
    res.status(400).json({ error: 'PayPal payout failed', detail });
  }
});

// ── SWIFT Settlement Routes ────────────────────────────────────────────────

api.post('/swift/config', (req, res) => {
  const { swiftBIC, bankName, accountNumber, accountName, iban, correspondentBIC, correspondentBank, messageType } = req.body;
  if (!swiftBIC || !bankName || !accountNumber) {
    return res.status(400).json({ error: 'SWIFT BIC, Bank Name, and Account Number are required' });
  }
  appConfig.swiftConfig = {
    swiftBIC, bankName, accountNumber, accountName: accountName || '',
    iban: iban || '', correspondentBIC: correspondentBIC || '',
    correspondentBank: correspondentBank || '', messageType: messageType || 'MT103'
  };
  saveConfig();
  res.json({ success: true, message: 'SWIFT bank configuration saved' });
});

api.get('/swift/config', (req, res) => {
  const cfg = appConfig.swiftConfig || {};
  res.json({
    configured: !!(cfg.swiftBIC && cfg.bankName && cfg.accountNumber),
    swiftBIC: cfg.swiftBIC || '',
    bankName: cfg.bankName || '',
    accountNumber: cfg.accountNumber ? '****' + cfg.accountNumber.slice(-4) : '',
    accountName: cfg.accountName || '',
    iban: cfg.iban ? '****' + cfg.iban.slice(-4) : '',
    messageType: cfg.messageType || 'MT103'
  });
});

api.post('/swift/settle', (req, res) => {
  try {
    const { submissionId, transactionId, amount, beneficiaryName, beneficiaryAccount, beneficiaryBIC, beneficiaryBank, currency, reference } = req.body;
    if (!transactionId || !amount || !beneficiaryName || !beneficiaryAccount || !beneficiaryBIC) {
      return res.status(400).json({ error: 'Transaction ID, amount, beneficiary name, account, and BIC are required' });
    }

    const swiftCfg = appConfig.swiftConfig;
    if (!swiftCfg || !swiftCfg.swiftBIC) {
      return res.status(400).json({ error: 'SWIFT bank not configured. Go to Settlement page and configure your bank details first.' });
    }

    const utiPrefix = 'USIRS';
    const txIdClean = transactionId.replace(/[^A-Za-z0-9]/g, '').substring(0, 20);
    const timestamp = Date.now().toString(36).toUpperCase();
    const uti = utiPrefix + txIdClean + timestamp;

    const messageType = swiftCfg.messageType || 'MT103';
    const settlementRef = 'SETL-' + crypto.randomBytes(8).toString('hex').toUpperCase();

    const swiftMessage = {
      messageType,
      senderBIC: swiftCfg.swiftBIC,
      receiverBIC: beneficiaryBIC,
      transactionRef: settlementRef,
      uti: uti,
      valueDate: new Date().toISOString().split('T')[0].replace(/-/g, ''),
      currency: currency || 'USD',
      amount: parseFloat(amount).toFixed(2),
      orderingCustomer: {
        account: swiftCfg.accountNumber,
        name: swiftCfg.accountName || swiftCfg.bankName,
        bic: swiftCfg.swiftBIC
      },
      beneficiary: {
        account: beneficiaryAccount,
        name: beneficiaryName,
        bic: beneficiaryBIC,
        bank: beneficiaryBank || ''
      },
      remittanceInfo: 'IRS IRIS Transmission UTI: ' + uti,
      irsTransactionId: transactionId
    };

    const settlement = db.addSettlement({
      id: settlementRef,
      submissionId: submissionId || '',
      transactionId,
      uti,
      messageType,
      senderBIC: swiftCfg.swiftBIC,
      receiverBIC: beneficiaryBIC,
      amount: parseFloat(amount).toFixed(2),
      currency: currency || 'USD',
      beneficiaryName,
      beneficiaryAccount: '****' + beneficiaryAccount.slice(-4),
      status: 'initiated',
      swiftMessage
    });

    if (submissionId) {
      db.updateSubmission(submissionId, { settlementStatus: 'initiated', settlementId: settlementRef, uti });
    }

    res.json({
      success: true,
      settlement,
      uti,
      settlementRef,
      swiftMessage,
      instructions: [
        'Settlement initiated with UTI: ' + uti,
        'SWIFT ' + messageType + ' message generated',
        'Submit this message through your SWIFT-connected bank portal',
        'The UTI links this settlement back to IRS Transaction: ' + transactionId.substring(0, 16) + '...'
      ]
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

api.get('/swift/settlements', (req, res) => {
  res.json({ settlements: db.getSettlements() });
});

api.post('/swift/settlements/:id/status', (req, res) => {
  const { status } = req.body;
  if (!status) return res.status(400).json({ error: 'status is required' });
  const updated = db.updateSettlement(req.params.id, { status });
  if (!updated) return res.status(404).json({ error: 'Settlement not found' });
  res.json({ success: true, settlement: updated });
});

// Payment page data endpoint (public - no sensitive data exposed)
api.get('/payment-info/:submissionId', (req, res) => {
  const sub = db.getSubmission(req.params.submissionId);
  if (!sub) return res.status(404).json({ error: 'Submission not found' });
  res.json({
    submissionId: sub.transactionId,
    amount: sub.amount || '0',
    recipientName: sub.recipientName || 'IRS Submission',
    description: `IRS 1099 Credit - ${sub.recipientName || 'Payment'}`,
    paypalClientId: appConfig.ppClientId || null,
    ppEnvironment: appConfig.ppEnvironment || 'sandbox',
    hasStripe: !!appConfig.stripeSecretKey
  });
});

// Create Stripe PaymentIntent for embedded checkout
api.post('/stripe/create-payment-intent', async (req, res) => {
  try {
    if (!appConfig.stripeSecretKey) {
      return res.status(400).json({ error: 'Stripe not configured' });
    }
    const { amount, submissionId, description } = req.body;
    if (!amount) return res.status(400).json({ error: 'Amount is required' });
    const stripe = new StripePayouts(appConfig.stripeSecretKey);
    const intent = await stripe.stripe.paymentIntents.create({
      amount: Math.round(parseFloat(amount) * 100),
      currency: 'usd',
      payment_method_types: ['card', 'us_bank_account'],
      description: description || 'IRS IRIS Payment',
      metadata: { submissionId: submissionId || '' }
    });
    res.json({ clientSecret: intent.client_secret, intentId: intent.id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Create Stripe Checkout for the payment page
api.post('/stripe/create-checkout-for-payment', async (req, res) => {
  try {
    if (!appConfig.stripeSecretKey) return res.status(400).json({ error: 'Stripe not configured' });
    const { submissionId, amount, description, returnUrl } = req.body;
    if (!amount) return res.status(400).json({ error: 'Amount is required' });
    const stripe = new StripePayouts(appConfig.stripeSecretKey);
    const session = await stripe.stripe.checkout.sessions.create({
      payment_method_types: ['card', 'us_bank_account'],
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: description || 'IRS IRIS Payment' },
          unit_amount: Math.round(parseFloat(amount) * 100)
        },
        quantity: 1
      }],
      success_url: returnUrl ? `${returnUrl}?payment=success` : `${req.protocol}://${req.get('host')}/pay.html?id=${submissionId}&status=success`,
      cancel_url: returnUrl ? `${returnUrl}?payment=cancelled` : `${req.protocol}://${req.get('host')}/pay.html?id=${submissionId}&status=cancelled`,
      metadata: { submissionId: submissionId || '' }
    });
    if (submissionId) {
      db.updateSubmission(submissionId, { collectStatus: 'link_created', checkoutSessionId: session.id });
    }
    res.json({ checkoutUrl: session.url, sessionId: session.id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.use('/api', api);

// ── Static + SPA Fallback ───────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`IRS Finance App running on port ${PORT}`);
});
