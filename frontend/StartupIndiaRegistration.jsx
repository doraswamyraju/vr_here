import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'startup-india-registration',
  title: 'Startup India DPIIT Recognition & Tax Exemption (Section 80-IAC)',
  hero: {
    title: 'Startup India DPIIT Recognition in {city}',
    subtitle: 'Obtain DPIIT Recognition Certificate, unlock 3 consecutive years 100% income tax exemption (Section 80-IAC), and Angel Tax exemption under Section 56(2)(viib).',
    badgeText: 'DPIIT MINISTRY OF COMMERCE VERIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: '3 Years', label: '100% TAX HOLIDAY (80-IAC)' },
    { value: 'Angel Tax', label: 'EXEMPTION' },
    { value: '80% Off', label: 'PATENT & IP REBATES' },
    { value: '4.9/5', label: 'STARTUP RATING' }
  ],
  packages: [
    {
      id: 'dpiit-recognition-only',
      name: 'DPIIT Recognition Certificate Plan',
      price: 3499,
      isPopular: true,
      isAdjustable: false,
      description: 'Official DPIIT startup certificate, pitch deck summary drafting, and priority govt tender access.',
      features: ['Official DPIIT Recognition Certificate', 'Startup India Portal Profile Setup', '80% Rebate on Patent / 50% on Trademark', 'Relaxed Norms in Govt Public Procurement (No EMD/Turnover Requirement)', 'Self-Certification under 6 Labour & 3 Environmental Laws'],
      creativeButtonText: 'Get DPIIT Recognition'
    },
    {
      id: 'dpiit-80iac-taxholiday',
      name: 'DPIIT + Section 80-IAC Tax Exemption Plan',
      price: 11999,
      isPopular: false,
      isAdjustable: false,
      description: 'Comprehensive application for Inter-Ministerial Board (IMB) approval for 3-year 100% income tax exemption.',
      features: ['DPIIT Recognition Certificate', 'Detailed Pitch Deck & Business Plan for IMB', 'Section 80-IAC Tax Exemption Application', 'Section 56 Angel Tax Exemption Filing', 'Dedicated Startup Advisory Support'],
      creativeButtonText: 'Select 80-IAC Tax Holiday'
    }
  ],
  steps: [
    { number: '01', title: 'Business Profile Review', desc: 'Assess entity incorporation date (<10 yrs), turnover (<₹100 Cr), and innovative model.', badge: 'Step 1' },
    { number: '02', title: 'Pitch Deck & Write-up', desc: 'Draft product innovation writeup, scalability roadmap, and employment generation potential.', badge: 'Step 2' },
    { number: '03', title: 'DPIIT Submission', desc: 'Submit application on Startup India portal with statutory declarations.', badge: 'Step 3' },
    { number: '04', title: 'Recognition Delivery', desc: 'Official DPIIT recognition certificate issued with unique DIPP number.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Startup India DPIIT Recognition Guide',
    overview: 'The Startup India initiative by DPIIT offers massive tax holidays, intellectual property fee subsidies, fast-track patent examinations, and government tender exemptions.',
    checklistTitle: 'Required Startup Data',
    checklist: ['Certificate of Incorporation (Pvt Ltd / LLP)', 'Company Website / Mobile App Link / Demo Video', 'Pitch Deck / Business Model Presentation', 'Founder Brief Profile & Problem-Solving Statement']
  },
  faqs: [
    { q: 'Who is eligible for Startup India DPIIT recognition?', a: 'Private Limited Companies, LLPs, and Registered Partnership Firms incorporated within the last 10 years with annual turnover not exceeding ₹100 Crores.' },
    { q: 'Can a sole proprietorship apply for Startup India?', a: 'No, DPIIT recognition is only available to Private Limited Companies, LLPs, and Registered Partnership Firms.' }
  ],
  popularSearches: ['Startup India Registration Online', 'DPIIT Certificate Apply', 'Section 80-IAC Tax Exemption', 'Angel Tax Exemption Startup', 'Patent Rebate for Startups']
};

const StartupIndiaRegistrationPage = () => <UniversalServicePage config={serviceConfig} pageId="startup-india-registration" />;

export default StartupIndiaRegistrationPage;
