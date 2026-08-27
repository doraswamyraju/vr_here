import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'gst-return-filing',
  title: 'GST Return Filing (GSTR-1, GSTR-3B, GSTR-9)',
  hero: {
    title: 'Hassle-Free GST Return Filing Online in {city}',
    subtitle: 'Timely filing of GSTR-1, GSTR-3B, GSTR-9 annual returns with 100% ITC matching and zero penalty guarantee.',
    badgeText: 'GSTN AUTHORIZED FILING',
    consultationPrice: 499
  },
  stats: [
    { value: '100%', label: 'ITC RECONCILIATION' },
    { value: 'Zero', label: 'LATE PENALTY' },
    { value: '4.9/5', label: 'RATING' },
    { value: 'CA Verified', label: 'ACCURACY' }
  ],
  packages: [
    {
      id: 'gst-nil',
      name: 'Nil Return Plan',
      price: 499,
      isPopular: false,
      isAdjustable: false,
      description: 'For registered entities with zero sales or purchase transactions in the month.',
      features: ['GSTR-1 Nil Filing', 'GSTR-3B Nil Filing', 'Acknowledgement ARN', 'SMS Confirmation'],
      creativeButtonText: 'Select Nil Plan'
    },
    {
      id: 'gst-monthly-regular',
      name: 'Monthly Regular Filing',
      price: 1499,
      isPopular: true,
      isAdjustable: false,
      description: 'Complete GSTR-1 & 3B filing with B2B/B2C invoice upload and ITC 2B matching.',
      features: ['GSTR-1 & 3B Filing', 'GSTR-2B ITC Matching', 'E-Way Bill Advisory', 'Tax Liability Optimization', 'Dedicated CA Review'],
      creativeButtonText: 'Select Regular Filing'
    },
    {
      id: 'gst-annual-audit',
      name: 'Annual Return (GSTR-9)',
      price: 4999,
      isPopular: false,
      isAdjustable: false,
      description: 'Comprehensive annual consolidation, reconciliation with books, and GSTR-9 filing.',
      features: ['Annual Table-by-Table Filing', 'Turnover Reconciliation', 'ITC Reversal Audit', 'CA Certification'],
      creativeButtonText: 'Select GSTR-9 Plan'
    }
  ],
  steps: [
    { number: '01', title: 'Invoice Upload', desc: 'Share your sales summaries and purchase bills or sync your cloud accounting.', badge: 'Step 1' },
    { number: '02', title: 'ITC 2B Matching', desc: 'Our algorithms match purchase registers with GSTR-2B to maximize input credit.', badge: 'Step 2' },
    { number: '03', title: 'Tax Approval', desc: 'Review calculated tax liability and input credits before filing.', badge: 'Step 3' },
    { number: '04', title: 'Challan & ARN', desc: 'Return submitted on GST portal; instant ARN and challan receipt generated.', badge: 'Step 4' }
  ],
  guide: {
    title: 'GST Return Filing Guide & Deadlines',
    overview: 'Regular filing of monthly and quarterly GST returns is legally mandatory to avoid heavy daily late fees and input tax credit blocking.',
    checklistTitle: 'Documents for Monthly Filing',
    checklist: ['Sales Invoice Register (B2B & B2C)', 'Purchase Register with GSTINs', 'E-Way Bills & Credit Notes', 'Bank Statements with GST Payments']
  },
  faqs: [
    { q: 'What is the due date for GSTR-1 and GSTR-3B?', a: 'GSTR-1 is due on the 11th of the succeeding month (or 13th for QRMP). GSTR-3B is due on the 20th of every month.' },
    { q: 'What happens if I miss the filing deadline?', a: 'A daily late fee of ₹50/day (₹20/day for Nil) plus 18% p.a. interest is levied on unpaid tax amounts.' },
    { q: 'How do you maximize our Input Tax Credit (ITC)?', a: 'We perform automated GSTR-2B cross-verification against your purchase registers to ensure not a single rupee of eligible credit is missed.' }
  ],
  popularSearches: ['GST Return Filing Online', 'GSTR 3B Due Date', 'GSTR 1 Filing CA', 'GSTR 9 Annual Return', 'Input Tax Credit Reconciliation', 'GST Late Fee Calculator']
};

const GSTReturnFilingPage = () => <UniversalServicePage config={serviceConfig} pageId="gst-return-filing" />;

export default GSTReturnFilingPage;
