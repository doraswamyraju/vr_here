import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'rera-registration',
  title: 'RERA Agent & Real Estate Project Registration',
  hero: {
    title: 'RERA Registration for Agents & Projects in {city}',
    subtitle: 'Mandatory Real Estate Regulatory Authority (RERA) registration for real estate brokers, agents, builders, layout developers, and apartment projects.',
    badgeText: 'STATE RERA AUTHORITY VERIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: '5-7 Days', label: 'TURNAROUND' },
    { value: '5 Years', label: 'AGENT LICENSE VALIDITY' },
    { value: '100%', label: 'LEGAL BROKERAGE' },
    { value: '4.9/5', label: 'REALTY RATING' }
  ],
  packages: [
    {
      id: 'rera-agent-individual',
      name: 'RERA Real Estate Agent License',
      price: 3999,
      isPopular: true,
      isAdjustable: false,
      description: 'For individual real estate brokers, channel partners, and property consultants.',
      features: ['State RERA Portal Profile Creation', 'RERA Agent License Number Issuance', '5-Year Certificate Validity', 'RERA Compliant Agreement Templates', 'Brokerage Legal Protection Guidelines'],
      creativeButtonText: 'Get RERA Agent License'
    },
    {
      id: 'rera-project-developer',
      name: 'RERA Project Registration (Developers)',
      price: 19999,
      isPopular: false,
      isAdjustable: false,
      description: 'Comprehensive project registration for residential layouts, commercial complexes, and apartment builders.',
      features: ['Form A / B Project Application Drafting', 'Title Deed & Encumbrance Verification', 'Quarterly Progress Report (QPR) Setup', 'RERA Escrow Account Advisory', 'Senior RERA Advocate Liaison'],
      creativeButtonText: 'Register Realty Project'
    }
  ],
  steps: [
    { number: '01', title: 'KYC & Qualification', desc: 'Verify PAN, Aadhaar, IT returns of past 3 years, and real estate training certificates.', badge: 'Step 1' },
    { number: '02', title: 'State RERA Portal Filing', desc: 'File application on state authority portal (e.g. AP RERA, TSRERA, MahaRERA, K-RERA, TNRERA).', badge: 'Step 2' },
    { number: '03', title: 'Authority Verification', desc: 'RERA regulatory officers verify applicant credentials and commercial history.', badge: 'Step 3' },
    { number: '04', title: 'RERA Number Allotment', desc: 'Official RERA Registration Certificate with unique alphanumeric license number issued.', badge: 'Step 4' }
  ],
  guide: {
    title: 'RERA Registration Guide',
    overview: 'Under Section 9 of the Real Estate (Regulation and Development) Act, 2016, no real estate agent can facilitate the sale or purchase of plots, apartments, or buildings without RERA registration.',
    checklistTitle: 'Required Documentation',
    checklist: ['PAN & Aadhaar of Applicant / Firm Partners', 'Income Tax Returns (ITR) of last 3 years', 'Office Address Proof (Rent Agreement / Utility Bill)', 'Recent Passport Photograph & Letterhead']
  },
  faqs: [
    { q: 'Is RERA mandatory for real estate channel partners?', a: 'Yes! Marketing, advertising, or selling units in any RERA-registered project without an agent registration number attracts severe penalties under Section 59/62.' }
  ],
  popularSearches: ['RERA Agent Registration Online', 'AP RERA TSRERA Broker License', 'MahaRERA Agent Apply', 'RERA License Cost']
};

const ReraRegistrationPage = () => <UniversalServicePage config={serviceConfig} pageId="rera-registration" />;

export default ReraRegistrationPage;
