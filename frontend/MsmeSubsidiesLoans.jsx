import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'msme-subsidies-loans',
  title: 'Government Subsidies & MSME Loan Schemes (PMEGP, CGTMSE, Mudra, PMFME)',
  hero: {
    title: 'Government MSME Subsidies & Loan Schemes in {city}',
    subtitle: 'Unlock 15% to 35% capital subsidies, collateral-free credit guarantees up to ₹5 Crores under CGTMSE, PMEGP, PMFME, and state industrial subsidy schemes.',
    badgeText: 'MINISTRY OF MSME & STATE INDUSTRIAL INCENTIVES',
    consultationPrice: 499
  },
  stats: [
    { value: '15% to 35%', label: 'GOVT CAPITAL SUBSIDY' },
    { value: 'Up to ₹5 Cr', label: 'COLLATERAL-FREE CGTMSE' },
    { value: '100%', label: 'SCHEME APPLICATION ASSISTANCE' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'pmegp-loan-package',
      name: 'PMEGP Subsidy Loan Application',
      price: 6999,
      isPopular: true,
      isAdjustable: false,
      description: 'Complete PMEGP portal application with project report for up to ₹50 Lakhs project cost with 15-35% subsidy.',
      features: ['PMEGP Online Application Filing', 'KVIC / DIC Bank Liaison Project Report', 'Margin Money Subsidy Claim Assistance', 'EDP Training Coordination', 'Bank Branch Sanction Follow-up'],
      creativeButtonText: 'Apply for PMEGP Subsidy'
    },
    {
      id: 'state-industrial-subsidy',
      name: 'State Industrial Incentive & Power Subsidy',
      price: 14999,
      isPopular: false,
      isAdjustable: false,
      description: 'Capital Investment Subsidy, Power Tariff Reimbursement, Stamp Duty Exemption, and State SGST Reimbursement.',
      features: ['State Industrial Policy Mapping (AP/TS/TN/KA)', 'Single Window Portal Application', 'Joint Inspection Report (JIR) Assistance', 'State Level Committee (SLC) Claim Filing', 'Subsidy Disbursement Tracking'],
      creativeButtonText: 'Select State Subsidy Plan'
    }
  ],
  steps: [
    { number: '01', title: 'Scheme Eligibility Audit', desc: 'Evaluate manufacturing/service activity against Central and State subsidy guidelines.', badge: 'Step 1' },
    { number: '02', title: 'Project Report & DPR', desc: 'Prepare scheme-specific project report meeting DIC / KVIC guidelines.', badge: 'Step 2' },
    { number: '03', title: 'Single Window Filing', desc: 'File application on state industrial / PMEGP / PMFME government portals.', badge: 'Step 3' },
    { number: '04', title: 'Sanction & Disbursement', desc: 'Assist during taskforce committee review and bank subsidy escrow account crediting.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Government Subsidies & Schemes Guide',
    overview: 'Central and State governments offer massive financial subsidies to encourage new manufacturing units, food processing ventures (PMFME), and women/SC/ST entrepreneurs.',
    checklistTitle: 'Required Applicant Data',
    checklist: ['Udyam MSME Registration Certificate', 'Aadhaar & PAN of Promoters', 'Educational Qualification & Caste Certificate (for higher subsidy)', 'Land Document / Rent Agreement & Machinery Quotes']
  },
  faqs: [
    { q: 'What is the maximum subsidy under PMEGP?', a: 'Up to 35% in rural areas (25% in urban areas) for special category applicants (SC/ST/OBC/Minority/Women/Ex-Servicemen) on projects up to ₹50 Lakhs for manufacturing and ₹20 Lakhs for services.' }
  ],
  popularSearches: ['PMEGP Subsidy Online Apply', 'PMFME Food Processing Subsidy', 'CGTMSE Collateral Free Loan', 'State Industrial Subsidies AP TS', 'MSME Government Grants']
};

const MsmeSubsidiesLoansPage = () => <UniversalServicePage config={serviceConfig} pageId="msme-subsidies-loans" />;

export default MsmeSubsidiesLoansPage;
