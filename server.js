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
