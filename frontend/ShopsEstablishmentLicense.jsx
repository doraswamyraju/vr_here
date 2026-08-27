import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'shops-establishment-license',
  title: 'Shops & Establishment Act Registration (Gumasta / Trade License)',
  hero: {
    title: 'Shops & Establishment Registration in {city}',
    subtitle: 'Mandatory state labour department registration for commercial offices, retail shops, IT firms, restaurants, and warehouses.',
    badgeText: 'STATE LABOUR DEPARTMENT VERIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: '2-3 Days', label: 'CERTIFICATE TIME' },
    { value: '100%', label: 'LEGAL COMMERCE' },
    { value: 'Bank A/c', label: 'MANDATORY PROOF' },
    { value: '4.9/5', label: 'CLIENT RATING' }
  ],
  packages: [
    {
      id: 'shops-establishment-plan',
      name: 'Shops & Establishment Certificate',
      price: 1499,
      isPopular: true,
      isAdjustable: false,
      description: 'Complete registration application, address proof verification, and certificate delivery.',
      features: ['Official State Labour Dept Certificate', 'Current Bank Account Opening Proof', 'Working Hours & Holiday Compliance Setup', 'Employee Register Formats Provided', 'Annual Renewal Reminder'],
      creativeButtonText: 'Register Shop / Office'
    }
  ],
  steps: [
    { number: '01', title: 'Document Upload', desc: 'Submit rent agreement / property deed, photo of storefront/office board, and employer PAN/Aadhaar.', badge: 'Step 1' },
    { number: '02', title: 'Portal Filing', desc: 'Application filed on state labour portal (e.g. AP/TS Meeseva, Karnataka e-Karmika, Delhi e-District).', badge: 'Step 2' },
    { number: '03', title: 'Labour Inspector Review', desc: 'Labour department validates address and business categorization.', badge: 'Step 3' },
    { number: '04', title: 'License Issuance', desc: 'Official Shops & Establishment Registration Certificate issued with government seal.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Shops & Establishment Act Guide',
    overview: 'Every commercial office, shop, and workplace must register under the State Shops & Establishment Act within 30 days of commencing operations.',
    checklistTitle: 'Required Documents',
    checklist: ['PAN & Aadhaar of Proprietor / Partners / Directors', 'Premises Rent Agreement / Utility Bill & NOC', 'Photo of Storefront / Office with Name Board', 'List of Employees with Designation & Salary']
  },
  faqs: [
    { q: 'Is Shops & Establishment registration required for IT software startups?', a: 'Yes! Even software and service offices operating with employees must register with the state labour department.' },
    { q: 'Can this certificate be used for opening a Current Bank Account?', a: 'Yes, banks accept Shops & Establishment certificates as primary entity and business address proof.' }
  ],
  popularSearches: ['Shops and Establishment License Online', 'Gumasta License Apply', 'e Karmika Registration Karnataka', 'AP TS Shops Act Online', 'Office Labour License']
};

const ShopsEstablishmentLicensePage = () => <UniversalServicePage config={serviceConfig} pageId="shops-establishment-license" />;

export default ShopsEstablishmentLicensePage;
