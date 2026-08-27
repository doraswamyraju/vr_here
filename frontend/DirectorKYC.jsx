import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'director-kyc',
  title: 'DIR-3 KYC Online Filing (Web-based & eForm DIR-3 KYC)',
  hero: {
    title: 'Director KYC (DIR-3 KYC) Online in {city}',
    subtitle: 'Annual mandatory Director KYC filing on MCA portal to keep your Director Identification Number (DIN) active and avoid ₹5,000 late penalties.',
    badgeText: 'MCA21 V3 APPROVED FILING',
    consultationPrice: 499
  },
  stats: [
    { value: '10 Mins', label: 'OTP FILING TIME' },
    { value: 'Active', label: 'DIN STATUS' },
    { value: 'Zero', label: 'MCA LATE FEE' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'dir3-kyc-web',
      name: 'DIR-3 KYC Web (OTP Based)',
      price: 499,
      isPopular: true,
      isAdjustable: false,
      description: 'For directors with unchanged mobile number and email who filed KYC in the previous financial year.',
      features: ['MCA V3 Portal Access & Verification', 'Aadhaar & Mobile OTP Authentication', 'Instant SRN Challan Generation', 'DIN Status Confirmation as Approved'],
      creativeButtonText: 'File Web KYC'
    },
    {
      id: 'dir3-kyc-form',
      name: 'eForm DIR-3 KYC (First-time / Update)',
      price: 1499,
      isPopular: false,
      isAdjustable: false,
      description: 'For first-time DIN holders or directors updating mobile number, email, address, or passport details.',
      features: ['Form DIR-3 KYC Drafting', 'Class 3 DSC Affixation & Verification', 'Address Proof & Passport Verification', 'Practicing CA / CS Certification', 'Reactivation of Deactivated DIN (if overdue)'],
      creativeButtonText: 'Select eForm KYC'
    }
  ],
  steps: [
    { number: '01', title: 'DIN & Contact Check', desc: 'Provide DIN, registered mobile number, email address, and PAN card.', badge: 'Step 1' },
    { number: '02', title: 'Dual OTP Verification', desc: 'Verify OTP sent to your registered mobile and email simultaneously.', badge: 'Step 2' },
    { number: '03', title: 'MCA V3 Submission', desc: 'Submit application on MCA21 V3 portal with digital verification.', badge: 'Step 3' },
    { number: '04', title: 'Instant SRN Receipt', desc: 'Download official MCA SRN receipt confirming approved DIN status.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Director KYC (DIR-3 KYC) Guide',
    overview: 'Every individual who holds a Director Identification Number (DIN) as of March 31 must complete DIR-3 KYC on or before September 30 annually.',
    checklistTitle: 'Required Details',
    checklist: ['8-Digit DIN Number', 'Personal Mobile Number & Email ID', 'PAN Card of Director', 'Class 3 DSC (for eForm filing only)']
  },
  faqs: [
    { q: 'What happens if I miss the September 30 DIR-3 KYC deadline?', a: 'Your DIN will be deactivated with the status "Deactivated due to non-filing of DIR-3 KYC", and a mandatory MCA government penalty of ₹5,000 must be paid to reactivate it.' }
  ],
  popularSearches: ['DIR-3 KYC Online Filing', 'Director KYC Due Date', 'MCA DIN Reactivation', 'DIR 3 KYC Fee Penalty', 'Web KYC for Directors']
};

const DirectorKYCPage = () => <UniversalServicePage config={serviceConfig} pageId="director-kyc" />;

export default DirectorKYCPage;
