import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'dpr-cma-preparation',
  title: 'Detailed Project Report (DPR) & CMA Data Preparation for Bank Loans',
  hero: {
    title: 'Bank Loan DPR & CMA Data Preparation in {city}',
    subtitle: 'Professional Detailed Project Reports (DPR), Credit Monitoring Arrangement (CMA) Data, and Term Loan/Cash Credit (CC/OD) proposals prepared by senior Chartered Accountants.',
    badgeText: 'BANK CREDIT UNDERWRITING STANDARDS',
    consultationPrice: 499
  },
  stats: [
    { value: '3-5 Days', label: 'PREPARATION TIME' },
    { value: '95%+', label: 'LOAN SANCTION RATE' },
    { value: '7-10 Yrs', label: 'FINANCIAL PROJECTIONS' },
    { value: '4.9/5', label: 'FOUNDER RATING' }
  ],
  packages: [
    {
      id: 'cma-data-working-capital',
      name: 'CMA Data Plan (CC / OD Limits)',
      price: 4999,
      isPopular: true,
      isAdjustable: false,
      description: 'Comprehensive 7-statement CMA data model required by banks for sanctioning or renewing Working Capital limits.',
      features: ['7 Standard Banking CMA Statements', 'Holding Period & Operating Cycle Modeling', 'MPBF (Maximum Permissible Bank Finance) Calculations', 'Ratio Analysis (DSCR, Current Ratio, TOL/TNW)', 'CA Certified CMA Data File'],
      creativeButtonText: 'Select CMA Data Plan'
    },
    {
      id: 'comprehensive-dpr-bank-loan',
      name: 'Comprehensive DPR + CMA Bundle (Term Loans)',
      price: 11999,
      isPopular: false,
      isAdjustable: false,
      description: 'Full-fledged Detailed Project Report for new industrial setups, machinery acquisition, commercial real estate & hospital setups.',
      features: ['In-depth Industry & Market Feasibility Analysis', 'Civil & Machinery Technical Layout Valuation', '10-Year Projected Balance Sheet, P&L & Cashflows', 'Break-even Analysis & IRR/NPV Sensitivity Tables', 'Direct Support during Bank Branch Credit Meetings'],
      creativeButtonText: 'Select Full DPR + CMA'
    }
  ],
  steps: [
    { number: '01', title: 'Project Discussion', desc: 'Understand project cost, machinery quotations, promoter contribution, and requested loan limit.', badge: 'Step 1' },
    { number: '02', title: 'Financial Modeling', desc: 'Senior CA builds comprehensive 7-10 year revenue, depreciation, interest, and cashflow projections.', badge: 'Step 2' },
    { number: '03', title: 'Technical Feasibility', desc: 'Draft executive summary, market dynamics, SWOT analysis, and management background.', badge: 'Step 3' },
    { number: '04', title: 'Bank Ready Handover', desc: 'Deliver print and digital bank-formatted DPR report with CA seal and signature.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Bank Loan DPR & CMA Guide',
    overview: 'Banks require CMA data to evaluate working capital viability and Detailed Project Reports (DPRs) to approve long-term term loans and government credit subsidies (PMEGP, Stand-Up India, CGTMSE).',
    checklistTitle: 'Required Inputs for DPR / CMA',
    checklist: ['Past 3 Years Audited Financial Statements (if existing business)', 'Machinery & Civil Construction Quotations / Estimates', 'Promoter KYC, Net Worth Statements & Resumes', 'Proposed Capacity, Selling Price & Raw Material Costs']
  },
  faqs: [
    { q: 'Is this report accepted by Nationalized and Private Banks?', a: 'Yes! Our DPR and CMA files are prepared strictly according to Reserve Bank of India (RBI) and Tandon/Nayak Committee lending norms accepted by SBI, HDFC, ICICI, Canara Bank, Union Bank, and all commercial lenders.' }
  ],
  popularSearches: ['CMA Data Preparation Online', 'Detailed Project Report for Bank Loan', 'DPR for PMEGP Loan', 'Working Capital CMA Format', 'Project Finance CA India']
};

const DprCmaPreparationPage = () => <UniversalServicePage config={serviceConfig} pageId="dpr-cma-preparation" />;

export default DprCmaPreparationPage;
