import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'audit-services',
  title: 'Internal Audit, GST Audit & Statutory Audit Services',
  hero: {
    title: 'Internal, GST & Statutory Audit Solutions in {city}',
    subtitle: 'Independent financial reviews, internal control audits, GST risk assessments, and SOX compliance by senior Chartered Accountants.',
    badgeText: 'ICAI CERTIFIED CA PRACTICE',
    consultationPrice: 499
  },
  stats: [
    { value: '100%', label: 'STATUTORY AUDIT READY' },
    { value: 'ICAI', label: 'STANDARDS COMPLIANT' },
    { value: 'Zero', label: 'LEGAL EXPOSURE' },
    { value: '4.9/5', label: 'AUDIT RATING' }
  ],
  packages: [
    {
      id: 'internal-audit-plan',
      name: 'Internal Process & Risk Audit',
      price: 9999,
      isPopular: false,
      isAdjustable: false,
      description: 'Comprehensive review of operational internal controls, revenue leakage, and SOP compliance.',
      features: ['Internal Financial Controls (IFC) Review', 'Revenue & Expense Leakage Audit', 'Procurement & Inventory Check', 'Management Letter with Action Plan'],
      creativeButtonText: 'Book Internal Audit'
    },
    {
      id: 'gst-tax-audit',
      name: 'GST & Tax Audit Support',
      price: 14999,
      isPopular: true,
      isAdjustable: false,
      description: 'Section 44AB Tax Audit and GST annual compliance verification with reconciliation reports.',
      features: ['Income Tax Section 44AB Audit Support', 'GSTR-9C Reconciliation Statement', 'ITC Verification & Risk Profiling', 'Drafting Form 3CD & 3CA/CB Annexures', 'Senior Partner Review'],
      creativeButtonText: 'Select Tax Audit Plan'
    }
  ],
  steps: [
    { number: '01', title: 'Audit Scope & Planning', desc: 'Define materiality thresholds, key risk areas, and audit program.', badge: 'Step 1' },
    { number: '02', title: 'Fieldwork & Verification', desc: 'Vouch sample transactions, test internal controls, and verify statutory ledgers.', badge: 'Step 2' },
    { number: '03', title: 'Observations & Queries', desc: 'Discuss draft observations and risk areas with company management.', badge: 'Step 3' },
    { number: '04', title: 'Audit Report Delivery', desc: 'Issue formal Independent Audit Report and statutory filing annexures.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Audit & Assurance Guide',
    overview: 'Statutory and internal audits ensure financial statement integrity, fulfill bank loan covenants, and identify operational revenue leakages.',
    checklistTitle: 'Required Audit Documentation',
    checklist: ['Trial Balance & General Ledgers', 'Bank & Party Confirmation Certificates', 'Fixed Asset & Inventory Register', 'Statutory Returns (GST, TDS, EPF, ESI)']
  },
  faqs: [
    { q: 'Who is required to undergo a Tax Audit under Section 44AB?', a: 'Businesses with turnover exceeding ₹1 Crore (or ₹10 Crores if 95%+ transactions are digital) and professionals with gross receipts exceeding ₹50 Lakhs.' },
    { q: 'What is the purpose of an internal audit?', a: 'Internal audit identifies fraud, operational inefficiencies, and compliance gaps before external statutory auditors or tax authorities inspect your records.' }
  ],
  popularSearches: ['Statutory Audit Services', 'Tax Audit Section 44AB', 'GST Audit GSTR 9C', 'Internal Audit Firm India', 'Chartered Accountant Audit Services']
};

const AuditServicesPage = () => <UniversalServicePage config={serviceConfig} pageId="audit-services" />;

export default AuditServicesPage;
