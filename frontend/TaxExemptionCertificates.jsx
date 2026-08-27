import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: '12aa-80g-certificates',
  title: '12A & 80G Tax Exemption Certificates for NGOs & Trusts',
  hero: {
    title: '12A & 80G Tax Exemption Registration in {city}',
    subtitle: 'Obtain 100% tax exemption on trust income under Section 12A/12AB and enable 50% tax deduction for your donors under Section 80G.',
    badgeText: 'INCOME TAX DEPT VERIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: '100%', label: 'TAX EXEMPT INCOME' },
    { value: '50%', label: 'DONOR TAX REBATE' },
    { value: 'CSR & FCRA', label: 'ELIGIBILITY' },
    { value: '4.9/5', label: 'NGO RATING' }
  ],
  packages: [
    {
      id: '12a-provisional',
      name: 'Provisional 12A & 80G (New NGOs)',
      price: 6999,
      isPopular: true,
      isAdjustable: false,
      description: 'Fast-track Form 10A provisional registration valid for 3 years for newly established NGOs/Trusts.',
      features: ['Form 10A Drafting & Online Filing', 'Provisional 12A Certificate (3 Yrs)', 'Provisional 80G Certificate (3 Yrs)', 'Unique Registration Number (URN) Issuance', 'Basic DARPAN Registration'],
      creativeButtonText: 'Get Provisional 12A/80G'
    },
    {
      id: '12a-regular',
      name: 'Regular 12AB & 80G (5-Year Final)',
      price: 11999,
      isPopular: false,
      isAdjustable: false,
      description: 'Form 10AB application for permanent 5-year registration with activity report drafting and CIT queries.',
      features: ['Form 10AB Drafting & Verification', 'Activity Report & Donation Ledgers Preparation', 'CIT (Exemptions) Query Handling', 'Final 5-Year 12AB & 80G Approval', 'CSR-1 Registration Included'],
      creativeButtonText: 'Select Final 12AB/80G'
    }
  ],
  steps: [
    { number: '01', title: 'Document Review', desc: 'Verify Trust Deed, Society MOA, or Section 8 Company Certificate of Incorporation.', badge: 'Step 1' },
    { number: '02', title: 'Form 10A/10AB Filing', desc: 'File electronic application on Income Tax e-filing portal.', badge: 'Step 2' },
    { number: '03', title: 'CIT Department Review', desc: 'Commissioner of Income Tax (Exemptions) verifies charitable objectives.', badge: 'Step 3' },
    { number: '04', title: 'Certificate & URN Delivery', desc: 'Formal 12A/12AB and 80G registration order issued with unique URN.', badge: 'Step 4' }
  ],
  guide: {
    title: '12A & 80G Registration Guide',
    overview: 'Without 12A registration, an NGO is taxed like a normal commercial entity. With 80G, donors can claim 50% income tax deduction, boosting fundraising.',
    checklistTitle: 'Required NGO Documents',
    checklist: ['Trust Deed / Society MOA / Section 8 Incorporation Certificate', 'PAN Card of NGO and All Trustees / Directors', 'Bank Account Statements & Activity Photos', 'Audited Accounts of Previous 3 Years (if existing entity)']
  },
  faqs: [
    { q: 'What is the validity of 12A and 80G registration?', a: 'Provisional registration (Form 10A) is valid for 3 years. Final regular registration (Form 10AB) is valid for 5 years and renewable.' },
    { q: 'Is 12A/80G mandatory for CSR funding?', a: 'Yes! Corporate entities and CSR committees only grant funding to NGOs with active 12A, 80G, and MCA CSR-1 registrations.' }
  ],
  popularSearches: ['12A Registration Online', '80G Certificate Apply', 'Section 80G Tax Exemption NGO', 'Form 10A Form 10AB Filing', 'CSR 1 Registration India']
};

const TaxExemptionCertificatesPage = () => <UniversalServicePage config={serviceConfig} pageId="12aa-80g-certificates" />;

export default TaxExemptionCertificatesPage;
