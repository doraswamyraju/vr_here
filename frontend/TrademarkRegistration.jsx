import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'trademark-registration',
  title: 'Trademark Registration & Brand Name Protection (TM & ®)',
  hero: {
    title: 'Online Trademark Registration (TM) in {city}',
    subtitle: 'Protect your brand name, logo, slogan, and packaging under the Trademarks Act, 1999. Use ™ instantly in 24 hours with certified Trademark Attorney filing.',
    badgeText: 'CONTROLLER GENERAL OF PATENTS, DESIGNS & TRADEMARKS APPROVED',
    consultationPrice: 499
  },
  stats: [
    { value: '24 Hours', label: 'USE ™ SYMBOL' },
    { value: '10 Years', label: 'PROTECTION PERIOD' },
    { value: '100%', label: 'LEGAL BRAND OWNERSHIP' },
    { value: '4.9/5', label: 'IP RATING' }
  ],
  packages: [
    {
      id: 'trademark-filing-plan',
      name: 'Trademark Registration Plan (Per Class)',
      price: 1999,
      isPopular: true,
      isAdjustable: false,
      description: 'Comprehensive trademark search, class classification, Form TM-A drafting, and instant filing.',
      features: ['Deep Trademark Search Report (Vienna & Phonetic)', 'Form TM-A Drafting by Trademark Attorney', 'Instant Application Number & Right to use ™', 'Class Classification (1 to 45 Classes)', 'Hearing & Examination Report Alert System'],
      creativeButtonText: 'Protect Brand Name'
    },
    {
      id: 'trademark-objection-reply',
      name: 'Trademark Objection Reply Plan',
      price: 3499,
      isPopular: false,
      isAdjustable: false,
      description: 'Professional legal reply drafting to Section 9 (Absolute Grounds) or Section 11 (Relative Grounds) objections.',
      features: ['Comprehensive Legal Examination Analysis', 'Case Law Precedents & Legal Affidavit Drafting', 'Formal Form TM-M / Objection Reply Filing', 'Follow-up with Trademark Examiner', 'Senior IP Advocate Drafting'],
      creativeButtonText: 'File Objection Reply'
    }
  ],
  steps: [
    { number: '01', title: 'Trademark Search', desc: 'Conduct thorough phonetic, wordmark, and visual search on IP India registry database.', badge: 'Step 1' },
    { number: '02', title: 'Class & Power of Attorney', desc: 'Map products/services to appropriate Nice Classification classes and execute Form TM-48.', badge: 'Step 2' },
    { number: '03', title: 'Form TM-A Filing', desc: 'File electronic application on IP India portal with digital signature of TM attorney.', badge: 'Step 3' },
    { number: '04', title: 'Use ™ Instantly', desc: 'Receive instant government filing acknowledgement receipt and start using ™ on your brand.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Trademark Registration Guide',
    overview: 'Registering a trademark gives you exclusive legal rights to use your brand name, logo, or tagline across India and prevents competitors from copying your brand identity.',
    checklistTitle: 'Required Trademark Documents',
    checklist: ['Logo / Brand Name Wordmark Artwork', 'Applicant PAN & Aadhaar (or Company Certificate of Incorporation)', 'Udyam MSME Certificate (for 50% govt fee rebate)', 'Date of First Use in Commerce (or Proposed to be used)']
  },
  faqs: [
    { q: 'When can I use the ™ and ® symbols?', a: 'You can use the ™ symbol immediately after the application is filed and an application number is generated (within 24 hours). The ® symbol can only be used once the trademark registration certificate is officially granted.' },
    { q: 'What is the validity of a trademark registration?', a: 'A trademark is registered for 10 years and can be renewed indefinitely every 10 years.' }
  ],
  popularSearches: ['Trademark Registration Online', 'Brand Name Registration India', 'TM Symbol Online Apply', 'Trademark Search IP India', 'Trademark Objection Reply Section 9 11']
};

const TrademarkRegistrationPage = () => <UniversalServicePage config={serviceConfig} pageId="trademark-registration" />;

export default TrademarkRegistrationPage;
