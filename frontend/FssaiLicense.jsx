import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'fssai-license',
  title: 'FSSAI Food License & Registration (Basic, State & Central)',
  hero: {
    title: 'FSSAI Food Safety License Online in {city}',
    subtitle: 'Obtain 14-digit FSSAI Registration, State License, or Central License on FoSCoS portal for restaurants, cloud kitchens, manufacturers, and food traders.',
    badgeText: 'FSSAI & FOSCOS GOVT AUTHORIZED',
    consultationPrice: 499
  },
  stats: [
    { value: '3-5 Days', label: 'TURNAROUND' },
    { value: '14-Digit', label: 'FSSAI LICENSE NO.' },
    { value: '1 to 5 Yrs', label: 'VALIDITY OPTIONS' },
    { value: '4.9/5', label: 'FOOD RATING' }
  ],
  packages: [
    {
      id: 'fssai-basic',
      name: 'FSSAI Basic Registration',
      price: 1999,
      isPopular: true,
      isAdjustable: false,
      description: 'For small food businesses, home kitchens, stalls, and distributors with turnover up to ₹12 Lakhs/year.',
      features: ['14-Digit FSSAI Registration Certificate', 'FoSCoS Portal Filing & Tracking', 'Food Category Selection Support', 'Swiggy / Zomato Onboarding Proof', '1-Year License Validity'],
      creativeButtonText: 'Select Basic FSSAI'
    },
    {
      id: 'fssai-state-license',
      name: 'FSSAI State License Plan',
      price: 4999,
      isPopular: false,
      isAdjustable: false,
      description: 'For medium manufacturers, restaurants, caterers, and wholesalers with turnover between ₹12 Lakhs and ₹20 Crores.',
      features: ['Official FSSAI State License Certificate', 'Form B Application & Layout Drafting', 'FSMS Declaration & Food Category Mapping', 'Water Test Report Guidance', 'Food Safety Officer Query Assistance'],
      creativeButtonText: 'Select State License'
    },
    {
      id: 'fssai-central-license',
      name: 'FSSAI Central License Plan',
      price: 9999,
      isPopular: false,
      isAdjustable: false,
      description: 'For large food manufacturers, importers, exporters, and multi-state cloud kitchen chains with turnover >₹20 Crores.',
      features: ['FSSAI Central License Issuance', 'Import/Export Clearance Integration', 'Multi-Unit Operations Compliance', 'Complete FSMS Plan & Technical Drafting', 'Dedicated FSSAI Senior Consultant'],
      creativeButtonText: 'Select Central License'
    }
  ],
  steps: [
    { number: '01', title: 'Business Scale Assessment', desc: 'Determine whether Basic Registration, State License, or Central License is required.', badge: 'Step 1' },
    { number: '02', title: 'FoSCoS Portal Filing', desc: 'File Form A (Registration) or Form B (License) with food category selection.', badge: 'Step 2' },
    { number: '03', title: 'Food Officer Review', desc: 'Food Safety Officer examines premises documentation and declarations.', badge: 'Step 3' },
    { number: '04', title: 'License Issuance', desc: '14-digit FSSAI license certificate issued with digital QR code.', badge: 'Step 4' }
  ],
  guide: {
    title: 'FSSAI Food License Guide',
    overview: 'Under the Food Safety and Standards Act, 2006, every food business operator (FBO) involved in manufacturing, processing, packaging, storing, or selling food must hold an active FSSAI registration/license.',
    checklistTitle: 'Required Documents',
    checklist: ['Photo of Applicant / Authorized Signatory', 'PAN & Aadhaar Card of Business Owner', 'Premises Rent Agreement / Electricity Bill & NOC', 'List of Food Products / Menu Items']
  },
  faqs: [
    { q: 'Is FSSAI mandatory for listing on Zomato and Swiggy?', a: 'Yes, Zomato, Swiggy, Blinkit, and Amazon strictly require an active 14-digit FSSAI license number before approving restaurant or grocery listings.' },
    { q: 'What is the maximum validity period of an FSSAI license?', a: 'You can apply for 1 year up to 5 years validity at the time of initial application.' }
  ],
  popularSearches: ['FSSAI License Apply Online', 'FoSCoS Portal Login', 'FSSAI Registration for Swiggy', 'Food License Cost India', 'FSSAI State vs Central License']
};

const FssaiLicensePage = () => <UniversalServicePage config={serviceConfig} pageId="fssai-license" />;

export default FssaiLicensePage;
