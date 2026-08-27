import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'udyam-registration',
  title: 'Udyam Registration (MSME Certificate) Online',
  hero: {
    title: 'Instant Udyam MSME Registration in {city}',
    subtitle: 'Obtain your official Ministry of MSME Udyam Registration Certificate in 24 hours. Unlock collateral-free bank loans, electricity subsidies, and priority tenders.',
    badgeText: 'MINISTRY OF MSME GOVT VERIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: '24 Hours', label: 'CERTIFICATE ISSUED' },
    { value: '100%', label: 'GOVT SUBSIDY READY' },
    { value: 'Lifetime', label: 'VALIDITY' },
    { value: '4.9/5', label: 'MSME RATING' }
  ],
  packages: [
    {
      id: 'udyam-instant',
      name: 'Udyam Certificate Plan',
      price: 999,
      isPopular: true,
      isAdjustable: false,
      description: 'Complete online application, NIC code classification, Aadhaar OTP verification, and certificate delivery.',
      features: ['Official Udyam Registration Certificate', 'NIC 5-Digit Business Activity Classification', 'Priority Sector Bank Lending Benefits', 'MSME Samadhaan Delayed Payment Protection', 'Lifetime Validity with Digital QR Code'],
      creativeButtonText: 'Get Udyam Certificate'
    }
  ],
  steps: [
    { number: '01', title: 'Aadhaar & PAN Submission', desc: 'Provide proprietor/director Aadhaar linked to mobile number and business PAN.', badge: 'Step 1' },
    { number: '02', title: 'NIC Code Selection', desc: 'Our experts map your manufacturing/service activities to appropriate 5-digit NIC codes.', badge: 'Step 2' },
    { number: '03', title: 'Portal Submission', desc: 'Application submitted on official udyamregistration.gov.in portal.', badge: 'Step 3' },
    { number: '04', title: 'Instant Delivery', desc: 'Official Udyam certificate with dynamic QR code delivered to your WhatsApp & Email.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Udyam MSME Registration Guide',
    overview: 'Udyam Registration is the official government identity for Micro, Small, and Medium Enterprises in India, providing statutory benefits under the MSMED Act.',
    checklistTitle: 'Required Data',
    checklist: ['Aadhaar Card of Applicant (Mobile Linked)', 'PAN Card of Business / Proprietor', 'Bank Account Number & IFSC Code', 'Business Address & Employee Count']
  },
  faqs: [
    { q: 'What are the main benefits of Udyam registration?', a: 'Collateral-free CGTMSE bank loans, 1% interest rate exemption, 50% discount on Trademark and Patent filings, electricity bill subsidies, and protection against delayed buyer payments under MSME Samadhaan.' },
    { q: 'Is Udyam registration permanent?', a: 'Yes! Udyam registration comes with lifetime validity and does not require periodic renewals.' }
  ],
  popularSearches: ['Udyam Registration Online', 'MSME Certificate Apply', 'Udyam Portal Login', 'MSME Loan Benefits', 'NIC Code for MSME']
};

const UdyamRegistrationPage = () => <UniversalServicePage config={serviceConfig} pageId="udyam-registration" />;

export default UdyamRegistrationPage;
