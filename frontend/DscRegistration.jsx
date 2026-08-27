import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'dsc-registration',
  title: 'Class 3 Digital Signature Certificate (DSC) Online with USB Token',
  hero: {
    title: 'Class 3 Digital Signature (DSC) in {city}',
    subtitle: 'Paperless online issuance of Class 3 Signing & Encryption Digital Signature Certificates with FIPS certified USB crypto token (ePass 2003 / ProxKey).',
    badgeText: 'CCA GOVT OF INDIA APPROVED (EMUDHRA / CAPRICORN)',
    consultationPrice: 499
  },
  stats: [
    { value: '15 Mins', label: 'VIDEO VERIFICATION TIME' },
    { value: '2 or 3 Yrs', label: 'VALIDITY' },
    { value: 'FIPS 140-2', label: 'USB CRYPTO TOKEN' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'dsc-individual-2yr',
      name: 'Class 3 Individual DSC (2 Years + Token)',
      price: 1499,
      isPopular: true,
      isAdjustable: false,
      description: 'Signing certificate for MCA, Income Tax, GST, PF, Trademark & ICEGATE for individuals/directors.',
      features: ['Class 3 Signing Certificate', '2-Year Certificate Validity', 'Free FIPS Certified USB Token', '10-Minute Paperless Video KYC', 'Doorstep Courier Delivery of Token'],
      creativeButtonText: 'Get Individual DSC'
    },
    {
      id: 'dsc-combo-combo',
      name: 'Class 3 Organization Combo (Signing + Encryption)',
      price: 2999,
      isPopular: false,
      isAdjustable: false,
      description: 'Dual Signing + Encryption certificate mandatory for GeM, E-Tendering, Railways & CPWD tenders.',
      features: ['Class 3 Signing + Encryption Certificates', 'Organization Name Embedded in DSC', '2-Year Validity + USB Token', 'E-Tendering & GeM Portal Ready', 'Assistance with Portal DSC Registration'],
      creativeButtonText: 'Get Combo DSC for Tenders'
    }
  ],
  steps: [
    { number: '01', title: 'Aadhaar / PAN KYC', desc: 'Complete paperless Aadhaar e-KYC using registered mobile OTP.', badge: 'Step 1' },
    { number: '02', title: 'Video Verification', desc: 'Record a quick 20-second selfie video holding your original PAN card.', badge: 'Step 2' },
    { number: '03', title: 'Certifying Authority Approval', desc: 'eMudhra / Capricorn Certifying Authority approves and downloads certificate.', badge: 'Step 3' },
    { number: '04', title: 'Token Dispatch', desc: 'Secure USB token dispatched via express courier with PIN configuration guide.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Class 3 Digital Signature (DSC) Guide',
    overview: 'A Digital Signature Certificate (DSC) is the digital equivalent of a physical signature, providing legal validity under the Information Technology Act, 2000.',
    checklistTitle: 'Required Details for Paperless DSC',
    checklist: ['Aadhaar Number with Linked Mobile', 'PAN Card of Applicant', 'Passport Photo (Selfie Upload)', 'Company GST / Board Resolution (for Org DSC only)']
  },
  faqs: [
    { q: 'What is the difference between Signing and Encryption DSC?', a: 'Signing DSC is used to sign PDF documents and MCA/Tax forms. Encryption DSC is used to encrypt commercial bids in online e-tendering portals so competitors cannot view your price before bid opening.' }
  ],
  popularSearches: ['Class 3 DSC Online', 'Digital Signature Certificate Cost', 'eMudhra DSC Apply Online', 'DSC for e Tendering', 'USB Token for DSC']
};

const DscRegistrationPage = () => <UniversalServicePage config={serviceConfig} pageId="dsc-registration" />;

export default DscRegistrationPage;
