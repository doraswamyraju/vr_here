import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'gmp-haccp-certification',
  title: 'GMP & HACCP Certification Services',
  hero: {
    title: 'GMP & HACCP Certification in {city}',
    subtitle: 'Good Manufacturing Practice (GMP) and Hazard Analysis Critical Control Point (HACCP) certification for Pharma, Food, Cosmetics & Ayush units.',
    badgeText: 'WHO-GMP & CODEX ALIMENTARIUS COMPLIANT',
    consultationPrice: 499
  },
  stats: [
    { value: '5-7 Days', label: 'CERTIFICATION TIME' },
    { value: 'WHO-GMP', label: 'PHARMA & FOOD READY' },
    { value: '100%', label: 'AUDIT SUCCESS' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'gmp-certificate',
      name: 'GMP Certification Plan',
      price: 6499,
      isPopular: true,
      isAdjustable: false,
      description: 'Complete Good Manufacturing Practices audit and certificate issuance for manufacturing units.',
      features: ['GMP Certificate (3 Yrs)', 'Factory Hygiene & Cleanroom Review', 'Sanitation & Equipment Validation SOPs', 'Batch Record Keeping Templates', 'Audit Compliance Report'],
      creativeButtonText: 'Select GMP Plan'
    },
    {
      id: 'haccp-certificate',
      name: 'HACCP + GMP Combo Plan',
      price: 9999,
      isPopular: false,
      isAdjustable: false,
      description: 'Combined Hazard Analysis & GMP certification for food processors, kitchens, and packaging units.',
      features: ['Both GMP & HACCP Certificates', 'Complete CCP Hazard Plan', 'Biological & Chemical Risk Matrix', 'Recall & Traceability SOPs', 'Dedicated Lead Auditor Support'],
      creativeButtonText: 'Select GMP + HACCP Combo'
    }
  ],
  steps: [
    { number: '01', title: 'Facility Inspection', desc: 'Inspect factory floor, raw material storage, air handling, and hygiene facilities.', badge: 'Step 1' },
    { number: '02', title: 'SOP Documentation', desc: 'Draft cleanroom procedures, pest control, equipment calibration, and batch logs.', badge: 'Step 2' },
    { number: '03', title: 'Compliance Audit', desc: 'Auditor verifies batch records, water testing, and personal hygiene practices.', badge: 'Step 3' },
    { number: '04', title: 'Certificate Delivery', desc: 'Official GMP / HACCP certificate issued with QR authenticity verification.', badge: 'Step 4' }
  ],
  guide: {
    title: 'GMP & HACCP Certification Guide',
    overview: 'GMP ensures products are consistently produced according to quality standards, while HACCP identifies and controls food safety hazards.',
    checklistTitle: 'Required Documentation',
    checklist: ['Factory License / FSSAI / Drug License', 'Plant Layout & Machinery List', 'Water & Air Quality Testing Reports', 'Staff Medical & Training Records']
  },
  faqs: [
    { q: 'Who needs GMP certification in India?', a: 'Pharmaceutical manufacturers, Ayurvedic/Ayush units, cosmetic processors, and food processing facilities.' }
  ],
  popularSearches: ['GMP Certification Online', 'HACCP Certificate Cost India', 'WHO GMP Consultant', 'Food Hygiene Certification']
};

const GmpHaccpCertificationPage = () => <UniversalServicePage config={serviceConfig} pageId="gmp-haccp-certification" />;

export default GmpHaccpCertificationPage;
