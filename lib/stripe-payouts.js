const Stripe = require('stripe');

class StripePayouts {
  constructor(secretKey) {
    this.stripe = new Stripe(secretKey);
  }

  async createPaymentIntent({ amount, currency = 'usd', description, metadata }) {
    return this.stripe.paymentIntents.create({
      amount: Math.round(amount * 100),
      currency,
      description,
      metadata
    });
  }

  async createTransfer({ amount, destination, description, metadata }) {
    return this.stripe.transfers.create({
      amount: Math.round(amount * 100),
      currency: 'usd',
      destination,
      description,
      metadata
    });
  }

  async createPayout({ amount, description, metadata }) {
    return this.stripe.payouts.create({
      amount: Math.round(amount * 100),
      currency: 'usd',
      description,
      metadata
    });
  }

  async createConnectedAccount({ email, businessName, type = 'express' }) {
    return this.stripe.accounts.create({
      type,
      email,
      business_profile: { name: businessName },
      capabilities: {
        transfers: { requested: true }
      }
    });
  }

  async createAccountLink({ accountId, refreshUrl, returnUrl }) {
    return this.stripe.accountLinks.create({
      account: accountId,
      refresh_url: refreshUrl,
      return_url: returnUrl,
      type: 'account_onboarding'
    });
  }

  async getBalance() {
    return this.stripe.balance.retrieve();
  }

  async listTransfers({ limit = 10 }) {
    return this.stripe.transfers.list({ limit });
  }

  async listPayouts({ limit = 10 }) {
    return this.stripe.payouts.list({ limit });
  }
}

module.exports = StripePayouts;
