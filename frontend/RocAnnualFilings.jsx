import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'roc-annual-filings',
  title: 'ROC Annual Compliance & Filings (AOC-4, MGT-7, Form 11, Form 8)',
  hero: {
    title: 'ROC Annual Compliance Filings in {city}',
    subtitle: 'Mandatory Ministry of Corporate Affairs (MCA) annual filings: Form AOC-4 (Financials), MGT-7A (Annual Return), and Form 11/8 for LLPs.',
    badgeText: 'MCA21 V3 CERTIFIED CS & CA FILING',
    consultationPrice: 499
  },
  stats: [
    { value: '100%', label: 'MCA V3 COMPLIANT' },
    { value: 'Zero', label: 'DIRECTOR DISQUALIFICATION' },
    { value: 'CA/CS', label: 'CERTIFIED REVIEW' },
    { value: '4.9/5', label: 'CORPORATE RATING' }
  ],
  packages: [
    {
      id: 'roc-small-company',
      name: 'Small Pvt Ltd Annual Compliance',
      price: 6999,
      isPopular: true,
      isAdjustable: false,
      description: 'Complete annual filing package for Private Limited Companies including AOC-4, MGT-7A, and Director KYC.',
      features: ['Form AOC-4 (Financial Statements Filing)', 'Form MGT-7A (Annual Return Filing)', 'DIR-3 KYC for 2 Directors', 'Drafting Board Resolutions & AGM Minutes', 'Statutory Register Maintenance Formats'],
      creativeButtonText: 'Select Small Company Plan'
    },
    {
      id: 'roc-llp-annual',
      name: 'LLP Annual Filing (Form 11 & Form 8)',
      price: 4999,
      isPopular: false,
      isAdjustable: false,
      description: 'Complete MCA filing for LLPs covering annual return Form 11 and statement of accounts Form 8.',
      features: ['Form 11 (Annual Return of LLP - Due May 30)', 'Form 8 (Statement of Accounts & Solvency - Due Oct 30)', 'Partner KYC Verification', 'Designated Partner Digital Signature Linking', 'Zero Late Penalty Guarantee'],
      creativeButtonText: 'Select LLP Compliance'
    }
  ],
  steps: [
    { number: '01', title: 'Financials Review', desc: 'Verify audited balance sheet, profit & loss statement, and directors report.', badge: 'Step 1' },
    { number: '02', title: 'Secretarial Drafting', desc: 'Draft notice of AGM, director report, board resolutions, and shareholding schedules.', badge: 'Step 2' },
    { number: '03', title: 'MCA V3 e-Filing', desc: 'Upload AOC-4 and MGT-7 with DSC of directors and practicing CA/CS certificate.', badge: 'Step 3' },
    { number: '04', title: 'SRN Acknowledgement', desc: 'Official Service Request Number (SRN) and MCA filing approval receipts delivered.', badge: 'Step 4' }
  ],
  guide: {
    title: 'ROC Annual Compliance Guide',
    overview: 'Under the Companies Act, 2013, every incorporated company and LLP must file annual returns with the Registrar of Companies (ROC) regardless of whether business was transacted.',
    checklistTitle: 'Required Documentation',
    checklist: ['Audited Financial Statements (Balance Sheet & P&L)', 'Directors Report with Annexures', 'Digital Signature Certificates (DSC) of Directors', 'List of Shareholders & Transfer Details']
  },
  faqs: [
    { q: 'What is the penalty for non-filing of AOC-4 and MGT-7?', a: 'MCA levies a penalty of ₹100 per day per form with no upper limit, which can lead to company strike-off and director disqualification.' }
  ],
  popularSearches: ['ROC Annual Filing Cost', 'Form AOC-4 Due Date', 'Form MGT-7 Due Date', 'LLP Form 11 Filing Online', 'MCA Compliance Package']
};

const RocAnnualFilingsPage = () => <UniversalServicePage config={serviceConfig} pageId="roc-annual-filings" />;

export default RocAnnualFilingsPage;
