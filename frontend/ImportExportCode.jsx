import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'import-export-code',
  title: 'Import Export Code (IEC) Online Registration',
  hero: {
    title: 'Import Export Code (IEC Code) Online in {city}',
    subtitle: 'Obtain your 10-digit DGFT Import Export Code with lifetime validity in 24 hours. Clear customs and initiate international cross-border trade.',
    badgeText: 'DGFT MINISTRY OF COMMERCE VERIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: '24 Hours', label: 'IEC ISSUED' },
    { value: 'Lifetime', label: 'VALIDITY' },
    { value: 'Zero', label: 'EXPORT RESTRICTIONS' },
    { value: '4.9/5', label: 'EXPORTER RATING' }
  ],
  packages: [
    {
      id: 'iec-registration-plan',
      name: 'IEC Code Registration Plan',
      price: 2199,
      isPopular: true,
      isAdjustable: false,
      description: 'Complete DGFT online portal registration, DSC linking, bank verification, and IEC certificate issuance.',
      features: ['Official DGFT 10-Digit IEC Certificate', 'Customs ICEGATE Integration Guidance', 'RCMC Council Advisory', 'Authorized Dealer (AD) Code Registration Support', 'Annual DGFT IEC Update Guidance'],
      creativeButtonText: 'Get IEC Code'
    }
  ],
  steps: [
    { number: '01', title: 'Document Upload', desc: 'Submit business PAN, cancelled bank cheque with printed entity name, and address proof.', badge: 'Step 1' },
    { number: '02', title: 'DGFT Portal Filing', desc: 'File ANF-2A application on DGFT portal with Aadhaar OTP / DSC authentication.', badge: 'Step 2' },
    { number: '03', title: 'Bank API Validation', desc: 'DGFT systems validate bank account details via PFMS integration.', badge: 'Step 3' },
    { number: '04', title: 'Certificate Delivery', desc: 'Official IEC certificate with e-IEC barcode delivered instantly.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Import Export Code (IEC) Guide',
    overview: 'An IEC is a mandatory 10-digit code issued by the Directorate General of Foreign Trade (DGFT) for importing or exporting goods and commercial services.',
    checklistTitle: 'Required Documents',
    checklist: ['PAN Card of Business & Directors / Partners', 'Cancelled Bank Cheque with Pre-printed Company Name', 'Address Proof of Business Premises', 'Class 3 DSC or Aadhaar OTP of Signatory']
  },
  faqs: [
    { q: 'Is IEC required for service exporters (IT, SaaS, Freelancers)?', a: 'Yes! Service exporters receiving foreign currency payments and claiming export incentives (SEIS / RoDTEP) require an active IEC.' },
    { q: 'Is there any annual renewal fee for IEC?', a: 'There is no renewal fee, but DGFT mandates that every IEC holder must confirm or update their IEC details once a year between April and June.' }
  ],
  popularSearches: ['IEC Code Online Apply', 'DGFT Import Export Code', 'IEC Registration Cost', 'AD Code Registration ICEGATE', 'Import License India']
};

const ImportExportCodePage = () => <UniversalServicePage config={serviceConfig} pageId="import-export-code" />;

export default ImportExportCodePage;
