import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'tds-tcs-filing',
  title: 'TDS & TCS Return Filing (24Q, 26Q, 27Q, 27EQ)',
  hero: {
    title: 'TDS & TCS Return Filing & Form 16A Issuance in {city}',
    subtitle: 'Quarterly filing of Form 24Q (Salaries), 26Q (Vendors), 27EQ (TCS), Challan ITNS 281 matching, and TRACES Form 16/16A generation.',
    badgeText: 'TRACES & INCOME TAX VERIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: '100%', label: '26AS / AIS MATCH' },
    { value: 'Zero', label: 'TDS DEFAULTS' },
    { value: 'Form 16A', label: 'TRACES GENERATED' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'tds-quarterly-filing',
      name: 'Quarterly TDS Filing (Per Form)',
      price: 1999,
      isPopular: true,
      isAdjustable: false,
      description: 'Preparation of Form 24Q / 26Q, FVU validation, CSI file verification, and TRACES submission.',
      features: ['Form 24Q (Salary) or 26Q (Vendor)', 'ITNS 281 Challan Matching', 'FVU File Validation', 'TRACES Form 16A Generation', 'Demand / Default Notice Resolution'],
      creativeButtonText: 'File TDS Return'
    },
    {
      id: 'tds-annual-package',
      name: 'Annual TDS Retainer (All 4 Quarters)',
      price: 6999,
      isPopular: false,
      isAdjustable: false,
      description: 'Comprehensive 4-quarter compliance for salary and non-salary deductions including corrections.',
      features: ['All 4 Quarters Form 24Q & 26Q', 'TCS Form 27EQ (if applicable)', 'Correction Return Filing (Form 26Q/24Q)', 'Form 16 Part A & B Certificates', 'Direct CA Advisory Support'],
      creativeButtonText: 'Select Annual Retainer'
    }
  ],
  steps: [
    { number: '01', title: 'Deduction Schedule', desc: 'Share monthly deduction details with vendor/employee PAN and payment dates.', badge: 'Step 1' },
    { number: '02', title: 'Challan Verification', desc: 'Verify Challan 281 BSR codes, challan numbers and amounts deposited.', badge: 'Step 2' },
    { number: '03', title: 'FVU File Generation', desc: 'Validate e-TDS return using NSDL e-Gov FVU utility.', badge: 'Step 3' },
    { number: '04', title: 'Filing & Certificates', desc: 'Submit return on Income Tax portal; download TRACES Form 16 / 16A.', badge: 'Step 4' }
  ],
  guide: {
    title: 'TDS Return Filing Guide',
    overview: 'Any entity deducting tax under sections 192 (Salary), 194C (Contractor), 194J (Professional), 194I (Rent), or 194Q (Purchase) must file quarterly e-TDS returns.',
    checklistTitle: 'Required Data for TDS Filing',
    checklist: ['TAN of Deductor', 'Challan ITNS 281 BSR Codes & CIN', 'Deductee Master (Name, PAN, Section, Amount)', 'TRACES Login Credentials']
  },
  faqs: [
    { q: 'What are the quarterly due dates for TDS return filing?', a: 'Q1 (Apr-Jun): July 31 | Q2 (Jul-Sep): Oct 31 | Q3 (Oct-Dec): Jan 31 | Q4 (Jan-Mar): May 31.' },
    { q: 'What is the late fee for delayed TDS filing?', a: 'Under Section 234E, a mandatory late fee of ₹200 per day is charged until the return is filed, up to the total TDS amount.' }
  ],
  popularSearches: ['TDS Return Filing Online', 'Form 26Q Filing Due Date', 'Form 24Q Salary TDS', 'TRACES Form 16A Download', 'TDS Late Fee Section 234E']
};

const TdsTcsFilingPage = () => <UniversalServicePage config={serviceConfig} pageId="tds-tcs-filing" />;

export default TdsTcsFilingPage;
