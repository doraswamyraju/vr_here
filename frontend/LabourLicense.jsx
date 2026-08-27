import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'labour-license',
  title: 'Contract Labour License & Registration (CLRA Act)',
  hero: {
    title: 'Contract Labour License (CLRA) in {city}',
    subtitle: 'Principal Employer Registration (Form I) and Contractor Labour License (Form IV) under the Contract Labour (Regulation & Abolition) Act.',
    badgeText: 'STATE LABOUR COMMISSIONER APPROVED',
    consultationPrice: 499
  },
  stats: [
    { value: '5-7 Days', label: 'TURNAROUND' },
    { value: 'Form I & IV', label: 'SCHEMES COVERED' },
    { value: '100%', label: 'STATUTORY COMPLIANT' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'contractor-labour-license',
      name: 'Contractor Labour License Plan',
      price: 5499,
      isPopular: true,
      isAdjustable: false,
      description: 'For contractors employing 20 or more contract workers on a project site.',
      features: ['Form IV License Application', 'Form V Principal Employer Certificate Validation', 'Security Deposit Calculation Guidance', 'Mandatory Labour Registers Formats', 'Labour Commissioner Query Handling'],
      creativeButtonText: 'Get Labour License'
    },
    {
      id: 'principal-employer-rc',
      name: 'Principal Employer RC (Form I)',
      price: 6999,
      isPopular: false,
      isAdjustable: false,
      description: 'Mandatory Registration Certificate for establishments engaging contract labour.',
      features: ['Form I Principal Employer Application', 'Registration Certificate (Form II) Issuance', 'Form V Issuance Guidelines', 'Annual Return (Form XXV) Preparation', 'Contractor Audit Compliance'],
      creativeButtonText: 'Register as Principal Employer'
    }
  ],
  steps: [
    { number: '01', title: 'Work Order & Form V', desc: 'Verify contract work order, workman count, and Form V certificate.', badge: 'Step 1' },
    { number: '02', title: 'Online Portal Filing', desc: 'File application on state labour licensing portal / Shram Suvidha.', badge: 'Step 2' },
    { number: '03', title: 'Fee & Security Deposit', desc: 'Calculate and deposit government treasury fees based on workman slabs.', badge: 'Step 3' },
    { number: '04', title: 'License Issuance', desc: 'Official Contract Labour License (Form VI) issued by Licensing Officer.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Contract Labour License (CLRA) Guide',
    overview: 'The CLRA Act applies to any establishment employing 20 (or 50 in some states) or more contract workers and to contractors executing contracts with such labour.',
    checklistTitle: 'Required Documentation',
    checklist: ['Work Order / Contract Agreement Copy', 'Form V from Principal Employer', 'PAN, GST & Address Proof of Contractor', 'List of Workmen & Proposed Commencement Dates']
  },
  faqs: [
    { q: 'When is a Contractor Labour License mandatory?', a: 'When a contractor deploys 20 or more workers in an establishment on any single day.' }
  ],
  popularSearches: ['Contract Labour License Online', 'CLRA License Apply', 'Form V Labour License', 'Principal Employer Registration CLRA']
};

const LabourLicensePage = () => <UniversalServicePage config={serviceConfig} pageId="labour-license" />;

export default LabourLicensePage;
