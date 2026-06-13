const { create } = require('xmlbuilder2');
const crypto = require('crypto');
const uuidv4 = () => crypto.randomUUID();

const FORM_TYPES = {
  '1099-A': { detailType: 'Form1099ADetail', submissionGroup: 'IRSubmission1Grp' },
  '1099-B': { detailType: 'Form1099BDetail', submissionGroup: 'IRSubmission1Grp' },
  '1099-C': { detailType: 'Form1099CDetail', submissionGroup: 'IRSubmission1Grp' },
  '1099-MISC': { detailType: 'Form1099MISCDetail', submissionGroup: 'IRSubmission1Grp' },
  '1099-OID': { detailType: 'Form1099OIDDetail', submissionGroup: 'IRSubmission1Grp' }
};

function buildManifest({ transmitterTIN, transmitterName, taxYear, totalPayeeCount }) {
  return {
    UniqueTransmissionId: uuidv4(),
    Timestamp: new Date().toISOString(),
    TransmitterTIN: transmitterTIN,
    TransmitterName: transmitterName,
    TaxYear: taxYear,
    TotalPayeeCount: totalPayeeCount
  };
}

function build1099A(record) {
  return {
    PayerTIN: record.payerTIN,
    PayerName: record.payerName,
    PayerAddress: {
      Street: record.payerStreet,
      City: record.payerCity,
      State: record.payerState,
      ZipCode: record.payerZip
    },
    RecipientTIN: record.recipientTIN,
    RecipientName: record.recipientName,
    RecipientAddress: {
      Street: record.recipientStreet,
      City: record.recipientCity,
      State: record.recipientState,
      ZipCode: record.recipientZip
    },
    DateOfAcquisition: record.dateOfAcquisition,
    BalanceOfPrincipalOutstanding: record.balanceOutstanding,
    FairMarketValue: record.fairMarketValue,
    PropertyDescription: record.propertyDescription,
    PersonallyLiable: record.personallyLiable || false
  };
}

function build1099B(record) {
  return {
    PayerTIN: record.payerTIN,
    PayerName: record.payerName,
    RecipientTIN: record.recipientTIN,
    RecipientName: record.recipientName,
    RecipientAddress: {
      Street: record.recipientStreet,
      City: record.recipientCity,
      State: record.recipientState,
      ZipCode: record.recipientZip
    },
    DateAcquired: record.dateAcquired,
    DateSold: record.dateSold,
    Proceeds: record.proceeds,
    CostBasis: record.costBasis,
    ShortTermGainLoss: record.shortTermGainLoss,
    LongTermGainLoss: record.longTermGainLoss,
    FederalIncomeTaxWithheld: record.federalTaxWithheld || '0.00'
  };
}

function build1099C(record) {
  return {
    PayerTIN: record.payerTIN,
    PayerName: record.payerName,
    RecipientTIN: record.recipientTIN,
    RecipientName: record.recipientName,
    RecipientAddress: {
      Street: record.recipientStreet,
      City: record.recipientCity,
      State: record.recipientState,
      ZipCode: record.recipientZip
    },
    DateOfIdentifiableEvent: record.dateOfEvent,
    AmountOfDebtCanceled: record.amountCanceled,
    InterestIncluded: record.interestIncluded || '0.00',
    DebtDescription: record.debtDescription,
    PersonallyLiable: record.personallyLiable || false,
    IdentifiableEventCode: record.eventCode || 'A'
  };
}

function build1099MISC(record) {
  return {
    PayerTIN: record.payerTIN,
    PayerName: record.payerName,
    PayerAddress: {
      Street: record.payerStreet,
      City: record.payerCity,
      State: record.payerState,
      ZipCode: record.payerZip
    },
    RecipientTIN: record.recipientTIN,
    RecipientName: record.recipientName,
    RecipientAddress: {
      Street: record.recipientStreet,
      City: record.recipientCity,
      State: record.recipientState,
      ZipCode: record.recipientZip
    },
    Rents: record.rents || '0.00',
    Royalties: record.royalties || '0.00',
    OtherIncome: record.otherIncome || '0.00',
    FederalIncomeTaxWithheld: record.federalTaxWithheld || '0.00',
    FishingBoatProceeds: record.fishingBoatProceeds || '0.00',
    MedicalPayments: record.medicalPayments || '0.00',
    SubstitutePayments: record.substitutePayments || '0.00',
    CropInsuranceProceeds: record.cropInsurance || '0.00',
    GrossProceeds: record.grossProceeds || '0.00',
    Section409ADeferrals: record.section409a || '0.00',
    NonqualifiedDeferredComp: record.nonqualifiedDeferred || '0.00',
    StateTaxWithheld: record.stateTaxWithheld || '0.00'
  };
}

function build1099OID(record) {
  return {
    PayerTIN: record.payerTIN,
    PayerName: record.payerName,
    RecipientTIN: record.recipientTIN,
    RecipientName: record.recipientName,
    RecipientAddress: {
      Street: record.recipientStreet,
      City: record.recipientCity,
      State: record.recipientState,
      ZipCode: record.recipientZip
    },
    OriginalIssueDiscount: record.oid,
    OtherPeriodicInterest: record.otherInterest || '0.00',
    EarlyWithdrawalPenalty: record.earlyWithdrawalPenalty || '0.00',
    FederalIncomeTaxWithheld: record.federalTaxWithheld || '0.00',
    MarketDiscount: record.marketDiscount || '0.00',
    AcquisitionPremium: record.acquisitionPremium || '0.00',
    Description: record.description
  };
}

const BUILDERS = {
  '1099-A': build1099A,
  '1099-B': build1099B,
  '1099-C': build1099C,
  '1099-MISC': build1099MISC,
  '1099-OID': build1099OID
};

function buildTransmissionXML({ manifest, formType, records }) {
  if (!FORM_TYPES[formType]) {
    throw new Error(`Unsupported form type: ${formType}`);
  }
  if (!BUILDERS[formType]) {
    throw new Error(`No builder for form type: ${formType}`);
  }

  const builder = BUILDERS[formType];
  const formConfig = FORM_TYPES[formType];

  const doc = create({ version: '1.0', encoding: 'UTF-8' });
  const root = doc.ele('IRTransmission');

  const manifestEl = root.ele('Manifest');
  manifestEl.ele('UniqueTransmissionId').txt(manifest.UniqueTransmissionId);
  manifestEl.ele('Timestamp').txt(manifest.Timestamp);
  manifestEl.ele('TransmitterTIN').txt(manifest.TransmitterTIN);
  manifestEl.ele('TransmitterName').txt(manifest.TransmitterName);
  manifestEl.ele('TaxYear').txt(manifest.TaxYear);
  manifestEl.ele('TotalPayeeCount').txt(String(manifest.TotalPayeeCount));

  const submGroup = root.ele(formConfig.submissionGroup);
  const header = submGroup.ele('IRSubmission1Header');
  header.ele('SubmissionId').txt(uuidv4());
  header.ele('FormType').txt(formType);
  header.ele('RecordCount').txt(String(records.length));

  for (const record of records) {
    const detail = submGroup.ele(formConfig.detailType);
    const built = builder(record);
    addFieldsToElement(detail, built);
  }

  return doc.end({ prettyPrint: true });
}

function addFieldsToElement(parent, obj) {
  for (const [key, value] of Object.entries(obj)) {
    if (value === null || value === undefined) continue;
    if (typeof value === 'object' && !Array.isArray(value)) {
      const child = parent.ele(key);
      addFieldsToElement(child, value);
    } else if (typeof value === 'boolean') {
      parent.ele(key).txt(value ? '1' : '0');
    } else {
      parent.ele(key).txt(String(value));
    }
  }
}

module.exports = {
  FORM_TYPES,
  buildManifest,
  buildTransmissionXML,
  BUILDERS
};
