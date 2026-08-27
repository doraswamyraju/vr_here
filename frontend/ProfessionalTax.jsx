import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'professional-tax',
  title: 'Professional Tax (PT) Registration & Returns',
  hero: {
    title: 'Professional Tax (PT) Registration & Filing in {city}',
    subtitle: 'Obtain PT Enrollment Certificate (PTEC) & PT Registration Certificate (PTRC) with timely monthly and annual return filing.',
    badgeText: 'STATE TAX DEPARTMENT VERIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: '2-3 Days', label: 'REGISTRATION TIME' },
    { value: '100%', label: 'SLAB COMPLIANT' },
    { value: '4.9/5', label: 'CLIENT RATING' },
    { value: 'All States', label: 'SUPPORTED' }
  ],
  packages: [
    {
      id: 'pt-registration-only',
      name: 'PT Registration (PTEC/PTRC)',
      price: 1999,
      isPopular: true,
      isAdjustable: false,
      description: 'Registration of establishment with state commercial tax department.',
      features: ['PTEC / PTRC Registration', 'Certificate Issuance', 'Slab Assessment Advisory', 'Online Portal Setup'],
      creativeButtonText: 'Register for PT'
    },
    {
      id: 'pt-annual-filing',
      name: 'Annual PT Filing & Returns',
      price: 3499,
      isPopular: false,
      isAdjustable: false,
      description: 'Monthly deduction compliance and annual return submission with payment challans.',
      features: ['Monthly PT Deduction Schedules', 'Annual Form Filing', 'Challan Preparation & Payment', 'Penalty Protection'],
      creativeButtonText: 'Select PT Filing'
    }
  ],
  steps: [
    { number: '01', title: 'Document Submission', desc: 'Submit Certificate of Incorporation, Director KYC, address proof and employee count.', badge: 'Step 1' },
    { number: '02', title: 'Online Application', desc: 'Application filed on state commercial taxes portal.', badge: 'Step 2' },
    { number: '03', title: 'Department Verification', desc: 'Commercial Tax Officer reviews and approves establishment profile.', badge: 'Step 3' },
    { number: '04', title: 'Certificate Delivery', desc: 'Official PT Enrollment (PTEC) and Registration (PTRC) certificates issued.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Professional Tax Guide',
    overview: 'Professional Tax is a state-level tax levied on salaried employees, business entities, and self-employed professionals.',
    checklistTitle: 'Required Documents',
    checklist: ['PAN Card of Business & Directors', 'Address Proof of Business Premises', 'Employee Salary Summary & Count', 'Bank Statement & Cancelled Cheque']
  },
  faqs: [
    { q: 'What is the difference between PTEC and PTRC?', a: 'PTEC (Professional Tax Enrollment Certificate) is for the employer/business itself to pay its own tax, while PTRC (Professional Tax Registration Certificate) allows the employer to deduct and deposit PT on behalf of employees.' },
    { q: 'Is Professional Tax applicable in all Indian states?', a: 'PT is applicable in major states including Andhra Pradesh, Telangana, Karnataka, Maharashtra, West Bengal, Tamil Nadu, Gujarat, Kerala, etc.' }
  ],
  popularSearches: ['Professional Tax Registration', 'PTRC Certificate Online', 'PTEC Registration AP TS', 'Professional Tax Slabs', 'PT Return Filing Due Date']
};

const ProfessionalTaxPage = () => <UniversalServicePage config={serviceConfig} pageId="professional-tax" />;

export default ProfessionalTaxPage;
