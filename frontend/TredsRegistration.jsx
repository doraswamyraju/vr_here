import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'treds-registration',
  title: 'TReDS Platform Registration (RXIL, M1xchange, Invoicemart)',
  hero: {
    title: 'TReDS Invoice Discounting Registration in {city}',
    subtitle: 'Get your MSME registered on RBI regulated TReDS platforms (RXIL, M1xchange, Invoicemart) to get unpaid corporate & PSU trade invoices discounted in 48 hours.',
    badgeText: 'RBI AUTHORIZED TREDS PLATFORM INTEGRATION',
    consultationPrice: 499
  },
  stats: [
    { value: '48 Hours', label: 'INVOICE DISCOUNTING' },
    { value: 'Without', label: 'COLLATERAL SECURITY' },
    { value: 'Lowest', label: 'BANK BIDDING RATES' },
    { value: '4.9/5', label: 'MSME RATING' }
  ],
  packages: [
    {
      id: 'treds-onboarding-plan',
      name: 'TReDS Multi-Platform Onboarding',
      price: 3499,
      isPopular: true,
      isAdjustable: false,
      description: 'Complete registration on RBI authorized TReDS platforms including digital document verification and bank mandate setup.',
      features: ['Registration on RXIL / M1xchange / Invoicemart', 'Udyam & Corporate Master Linking', 'NACH Mandate & Escrow Setup', 'Digital Signature Linking', 'First Invoice Factoring Handholding'],
      creativeButtonText: 'Register on TReDS'
    }
  ],
  steps: [
    { number: '01', title: 'KYC & Entity Verification', desc: 'Submit business PAN, Udyam certificate, audited financials, and bank details.', badge: 'Step 1' },
    { number: '02', title: 'Platform Master Upload', desc: 'Upload supplier profile and buyer (corporate/PSU) mapped lists on TReDS.', badge: 'Step 2' },
    { number: '03', title: 'Bank Agreement & e-Sign', desc: 'Execute online master agreements using Class 3 DSC and e-NACH mandate.', badge: 'Step 3' },
    { number: '04', title: 'Discount Invoices', desc: 'Upload verified sales invoices; multiple banks bid with competitive interest rates.', badge: 'Step 4' }
  ],
  guide: {
    title: 'TReDS Invoice Discounting Guide',
    overview: 'Trade Receivables Discounting System (TReDS) is an RBI initiative enabling MSME suppliers to auction accepted trade receivables to multiple financiers with zero collateral.',
    checklistTitle: 'Required Documents',
    checklist: ['Udyam MSME Registration Certificate', 'PAN & GST Certificate of Supplier Entity', 'Bank Statement with NACH / e-Mandate Support', 'Class 3 Organization DSC']
  },
  faqs: [
    { q: 'Is TReDS financing without recourse?', a: 'Yes! Once a buyer accepts the invoice on TReDS and a bank discounts it, the financing is generally without recourse to the MSME seller.' }
  ],
  popularSearches: ['TReDS Platform Registration', 'M1xchange Onboarding', 'RXIL Registration Online', 'Invoice Discounting for MSMEs']
};

const TredsRegistrationPage = () => <UniversalServicePage config={serviceConfig} pageId="treds-registration" />;

export default TredsRegistrationPage;
