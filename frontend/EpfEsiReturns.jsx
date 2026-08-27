import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'epf-esi-returns',
  title: 'EPF & ESIC Registration & Monthly Return Filing',
  hero: {
    title: 'EPF & ESIC Registration & ECR Filing in {city}',
    subtitle: 'Provident Fund (PF) and Employee State Insurance (ESI) registration, UAN generation, monthly ECR challans, and inspection assistance.',
    badgeText: 'EPFO & ESIC STATUTORY CERTIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: '100%', label: 'ECR ACCURACY' },
    { value: '2-3 Days', label: 'REGISTRATION' },
    { value: 'Zero', label: 'INSPECTION RISK' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'pf-esi-registration',
      name: 'PF & ESI Registration Code',
      price: 2999,
      isPopular: false,
      isAdjustable: false,
      description: 'Establishment code generation under Shram Suvidha & EPFO/ESIC portals.',
      features: ['EPFO Employer Code', 'ESIC Sub-Code Issuance', 'Digital Signature (DSC) Linking', 'Portal Master Setup'],
      creativeButtonText: 'Get PF & ESI Codes'
    },
    {
      id: 'pf-esi-monthly-filing',
      name: 'Monthly ECR Return Filing',
      price: 1999,
      isPopular: true,
      isAdjustable: false,
      description: 'Monthly ECR preparation, challan generation, employee additions & exit marking.',
      features: ['Monthly ECR Upload & Filing', 'UAN Generation for New Joinees', 'ESI Insurance Card (TIC) Issuance', 'Member KYC Approval Support', 'Inspection & Notice Advisory'],
      creativeButtonText: 'Select Monthly Filing'
    }
  ],
  steps: [
    { number: '01', title: 'Data Upload', desc: 'Submit establishment registration documents, DSC, and director details.', badge: 'Step 1' },
    { number: '02', title: 'Portal Filing', desc: 'Application filed on Unified Shram Suvidha portal for PF & ESI.', badge: 'Step 2' },
    { number: '03', title: 'Code Allotment', desc: 'Employer code numbers allotted and verified with digital signatures.', badge: 'Step 3' },
    { number: '04', title: 'Monthly ECR Run', desc: 'Monthly ECR filed before the 15th of every month with payment challan.', badge: 'Step 4' }
  ],
  guide: {
    title: 'EPF & ESI Compliance Guide',
    overview: 'PF is mandatory for establishments with 20+ employees (voluntary for less), and ESI is mandatory for units with 10+ employees earning up to ₹21,000/month.',
    checklistTitle: 'Required Documents',
    checklist: ['PAN Card of Business & Directors', 'Address Proof of Establishment', 'List of Employees with Salary & Aadhaar', 'Class 3 DSC of Authorized Signatory']
  },
  faqs: [
    { q: 'What is the due date for monthly PF and ESI payments?', a: 'PF and ESI contributions must be deposited on or before the 15th of every succeeding month.' },
    { q: 'What are the contribution rates?', a: 'EPF: 12% employee + 12% employer. ESIC: 0.75% employee + 3.25% employer.' }
  ],
  popularSearches: ['PF Registration Online', 'ESIC Return Filing', 'EPF ECR Challan Online', 'UAN Number Generation', 'PF Consultant India']
};

const EpfEsiReturnsPage = () => <UniversalServicePage config={serviceConfig} pageId="epf-esi-returns" />;

export default EpfEsiReturnsPage;
