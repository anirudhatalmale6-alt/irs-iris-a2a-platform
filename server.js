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

app.use(cors());
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
    const { privateKeyPem, clientId, irsTokenUrl } = req.body;
    if (!privateKeyPem || !clientId) {
      return res.status(400).json({ error: 'privateKeyPem and clientId are required' });
    }

    const tokenUrl = irsTokenUrl || 'https://api.irs.gov/auth/oauth/v2/token';
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
    const { privateKeyPem, clientId, userId, irsTokenUrl } = req.body;
    if (!privateKeyPem || !clientId || !userId) {
      return res.status(400).json({ error: 'privateKeyPem, clientId, and userId are required' });
    }

    const tokenUrl = irsTokenUrl || 'https://api.irs.gov/auth/oauth/v2/token';
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

// ── IRIS Transmission Routes ────────────────────────────────────────────────

const A2AAuth = require('./lib/a2a-auth');
const IRISClient = require('./lib/iris-client');
const { buildManifest, buildTransmissionXML, FORM_TYPES } = require('./lib/iris-builder');

let appConfig = {
  clientId: null,
  privateKeyPem: null,
  environment: 'test',
  transmitterTIN: null,
  transmitterName: null
};

api.post('/config/save', (req, res) => {
  const { clientId, privateKeyPem, environment, transmitterTIN, transmitterName } = req.body;
  if (clientId) appConfig.clientId = clientId;
  if (privateKeyPem) appConfig.privateKeyPem = privateKeyPem;
  if (environment) appConfig.environment = environment;
  if (transmitterTIN) appConfig.transmitterTIN = transmitterTIN;
  if (transmitterName) appConfig.transmitterName = transmitterName;
  res.json({ success: true, config: { ...appConfig, privateKeyPem: appConfig.privateKeyPem ? '[SET]' : null } });
});

api.get('/config', (req, res) => {
  res.json({
    clientId: appConfig.clientId,
    hasPrivateKey: !!appConfig.privateKeyPem,
    environment: appConfig.environment,
    transmitterTIN: appConfig.transmitterTIN,
    transmitterName: appConfig.transmitterName
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

app.use('/api', api);

// ── Static + SPA Fallback ───────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`IRS Finance App running on port ${PORT}`);
});
