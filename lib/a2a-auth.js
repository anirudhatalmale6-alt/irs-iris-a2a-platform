const jwt = require('jsonwebtoken');
const axios = require('axios');

const IRS_TOKEN_URL_PROD = 'https://api.irs.gov/auth/oauth/v2/token';
const IRS_TOKEN_URL_TEST = 'https://api.test.irs.gov/auth/oauth/v2/token';

class A2AAuth {
  constructor({ clientId, privateKeyPem, environment = 'test' }) {
    this.clientId = clientId;
    this.privateKeyPem = privateKeyPem;
    this.tokenUrl = environment === 'production' ? IRS_TOKEN_URL_PROD : IRS_TOKEN_URL_TEST;
    this.accessToken = null;
    this.tokenExpiry = null;
  }

  signJwt(payload) {
    return jwt.sign(payload, this.privateKeyPem, {
      algorithm: 'RS256',
      header: { alg: 'RS256', typ: 'JWT' }
    });
  }

  generateClientJwt() {
    const now = Math.floor(Date.now() / 1000);
    return this.signJwt({
      iss: this.clientId,
      sub: this.clientId,
      aud: this.tokenUrl,
      iat: now,
      exp: now + 300
    });
  }

  generateUserJwt(userId) {
    const now = Math.floor(Date.now() / 1000);
    return this.signJwt({
      iss: this.clientId,
      sub: userId,
      aud: this.tokenUrl,
      iat: now,
      exp: now + 300
    });
  }

  async getAccessToken(userId) {
    if (this.accessToken && this.tokenExpiry && Date.now() < this.tokenExpiry) {
      return this.accessToken;
    }

    const clientJwt = this.generateClientJwt();
    const userJwt = this.generateUserJwt(userId);

    const params = new URLSearchParams();
    params.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
    params.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    params.append('client_assertion', clientJwt);
    params.append('user_assertion', userJwt);

    const response = await axios.post(this.tokenUrl, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    this.accessToken = response.data.access_token;
    const expiresIn = response.data.expires_in || 3600;
    this.tokenExpiry = Date.now() + (expiresIn - 60) * 1000;

    return this.accessToken;
  }

  clearToken() {
    this.accessToken = null;
    this.tokenExpiry = null;
  }
}

module.exports = A2AAuth;
