import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'cloud-accounting',
  title: 'Cloud Accounting & Bookkeeping Services',
  hero: {
    title: 'Cloud Accounting & Real-Time Bookkeeping in {city}',
    subtitle: 'Streamline your ledgers on Tally Prime, Zoho Books, QuickBooks & Marg with certified CAs and dedicated accounts managers.',
    badgeText: 'TALLY & ZOHO CERTIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: 'Daily / Mth', label: 'LEDGER UPDATES' },
    { value: '100%', label: 'TAX COMPLIANT' },
    { value: '4.9/5', label: 'CLIENT RATING' },
    { value: 'Zero', label: 'ACCOUNTING HEADACHE' }
  ],
  packages: [
    {
      id: 'startup-books',
      name: 'Startup Accounting',
      price: 2999,
      isPopular: false,
      isAdjustable: false,
      description: 'Ideal for early-stage businesses with up to 50 transactions/month.',
      features: ['Bank Reconciliation', 'Purchase & Sales Ledgers', 'Monthly P&L & Balance Sheet', 'GST Invoicing Support'],
      creativeButtonText: 'Select Startup Books'
    },
    {
      id: 'growth-books',
      name: 'Growth Business Books',
      price: 5999,
      isPopular: true,
      isAdjustable: false,
      description: 'Comprehensive accounting with dedicated account manager up to 200 txns/mo.',
      features: ['Dedicated CA Review', 'Tally / Zoho Setup', 'Vendor & Customer Ledgers', 'Monthly MIS Reports', 'TDS & GST Compliance'],
      creativeButtonText: 'Select Growth Books'
    },
    {
      id: 'enterprise-books',
      name: 'Enterprise Full-Stack',
      price: 11999,
      isPopular: false,
      isAdjustable: false,
      description: 'End-to-end CFO services, payroll ledger, and unlimited multi-branch accounting.',
      features: ['Daily Bookkeeping', 'Virtual CFO Advisory', 'Custom MIS Dashboards', 'Statutory Audit Support', 'Multi-GSTIN Ledgers'],
      creativeButtonText: 'Select Enterprise Books'
    }
  ],
  steps: [
    { number: '01', title: 'Data Handover', desc: 'Securely connect bank statements and invoice bills to our cloud portal.', badge: 'Step 1' },
    { number: '02', title: 'Ledger Categorization', desc: 'Expert accountants reconcile accounts and record journal entries.', badge: 'Step 2' },
    { number: '03', title: 'Monthly MIS & P&L', desc: 'Receive real-time balance sheets, cashflow reports and tax forecasts.', badge: 'Step 3' },
    { number: '04', title: 'Audit Ready Delivery', desc: 'All ledgers verified by practicing Chartered Accountants.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Cloud Accounting & Bookkeeping Guide',
    overview: 'Professional bookkeeping ensures strict MCA, GST, and Income Tax compliance while providing clear insight into your cashflows.',
    checklistTitle: 'Onboarding Checklist',
    checklist: ['Bank Statements (PDF / Excel)', 'Sales Invoices & Purchase Bills', 'GST Portal Login / API Access', 'Expense Receipts & Payroll Summaries']
  },
  faqs: [
    { q: 'Which accounting software do you support?', a: 'We support all major cloud and desktop platforms including Tally Prime, Zoho Books, QuickBooks, Marg ERP, and Busy.' },
    { q: 'Is my financial data secure?', a: 'Yes, all data is protected with 256-bit SSL encryption and strict Non-Disclosure Agreements (NDAs).' },
    { q: 'Can you migrate our existing desktop Tally data to Zoho Books?', a: 'Yes! Our specialists handle seamless ledger migration, chart of accounts setup, and opening balance reconciliation.' }
  ],
  popularSearches: ['Cloud Accounting', 'Bookkeeping Services India', 'Tally Prime Outsourcing', 'Zoho Books CA Partner', 'Monthly MIS Reporting', 'Virtual CFO India']
};

const CloudAccountingPage = () => <UniversalServicePage config={serviceConfig} pageId="cloud-accounting" />;

export default CloudAccountingPage;
