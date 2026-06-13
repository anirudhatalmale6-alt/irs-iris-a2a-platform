const axios = require('axios');

const IRIS_BASE_PROD = 'https://api.irs.gov/iris/v1';
const IRIS_BASE_TEST = 'https://api.test.irs.gov/iris/v1';

class IRISClient {
  constructor({ environment = 'test' }) {
    this.baseUrl = environment === 'production' ? IRIS_BASE_PROD : IRIS_BASE_TEST;
  }

  async submitTransmission(accessToken, xmlPayload) {
    const response = await axios.post(`${this.baseUrl}/transmissions`, xmlPayload, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/xml',
        'Accept': 'application/json'
      }
    });
    return response.data;
  }

  async getTransmissionStatus(accessToken, transmissionId) {
    const response = await axios.get(`${this.baseUrl}/transmissions/${transmissionId}/status`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    });
    return response.data;
  }

  async getSubmissionStatus(accessToken, submissionId) {
    const response = await axios.get(`${this.baseUrl}/submissions/${submissionId}/status`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    });
    return response.data;
  }

  async getRecordStatus(accessToken, recordId) {
    const response = await axios.get(`${this.baseUrl}/records/${recordId}/status`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    });
    return response.data;
  }
}

module.exports = IRISClient;
