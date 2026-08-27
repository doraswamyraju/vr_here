import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'trade-license',
  title: 'Municipal Trade License Online Registration',
  hero: {
    title: 'Municipal Trade License Registration in {city}',
    subtitle: 'Obtain mandatory municipal corporation trade licenses and health trade certificates to legally operate commercial, retail, or industrial businesses.',
    badgeText: 'MUNICIPAL CORPORATION CERTIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: '3-5 Days', label: 'TURNAROUND' },
    { value: '100%', label: 'MUNICIPAL COMPLIANT' },
    { value: 'Annual / Multi-Yr', label: 'VALIDITY' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'trade-license-plan',
      name: 'Trade License Registration Plan',
      price: 2499,
      isPopular: true,
      isAdjustable: false,
      description: 'Municipal trade license application, zone clearance, and official trade certificate delivery.',
      features: ['Municipal Corporation Application Filing', 'Health & Hygiene Verification Support', 'Zone / Ward Mapping', 'Trade License Certificate Issuance', 'Annual Renewal Notification'],
      creativeButtonText: 'Apply for Trade License'
    }
  ],
  steps: [
    { number: '01', title: 'Premises Verification', desc: 'Verify commercial zoning, municipal property tax receipt, and rental agreement.', badge: 'Step 1' },
    { number: '02', title: 'Municipal Filing', desc: 'Submit application on urban local body portal (e.g., CDMA, GHMC, BBMP, BMC, MCD).', badge: 'Step 2' },
    { number: '03', title: 'Ward Officer Review', desc: 'Municipal health / sanitary inspector validates business trade category.', badge: 'Step 3' },
    { number: '04', title: 'License Issuance', desc: 'Official Trade License Certificate issued with municipal digital seal.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Trade License Guide',
    overview: 'A Trade License is issued by the local Municipal Corporation permitting an enterprise to carry out specific commercial activities without causing health or safety hazards.',
    checklistTitle: 'Required Documents',
    checklist: ['Property Tax Receipt / Commercial Electricity Bill', 'Rent Agreement & Owner NOC', 'PAN & Aadhaar of Business Owner', 'Premises Layout Plan & Photo']
  },
  faqs: [
    { q: 'Who issues the Trade License?', a: 'Trade licenses are issued by the local municipal body, such as Municipal Corporations, Municipalities, or Town Panchayats.' }
  ],
  popularSearches: ['Trade License Apply Online', 'Municipal Trade License Cost', 'GHMC Trade License', 'BBMP Trade License Online']
};

const TradeLicensePage = () => <UniversalServicePage config={serviceConfig} pageId="trade-license" />;

export default TradeLicensePage;
