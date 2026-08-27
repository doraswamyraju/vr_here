import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'iso-9001-certification',
  title: 'ISO 9001:2015 Quality Management System Certification',
  hero: {
    title: 'ISO 9001:2015 Certification in {city}',
    subtitle: 'Globally recognized IAF & Non-IAF accredited Quality Management System (QMS) certification with full audit support and documentation kits.',
    badgeText: 'IAF & NABCB ACCREDITED',
    consultationPrice: 499
  },
  stats: [
    { value: '5-7 Days', label: 'CERTIFICATION TIME' },
    { value: 'IAF / Non-IAF', label: 'ACCREDITATION OPTIONS' },
    { value: '3 Years', label: 'CERTIFICATE VALIDITY' },
    { value: '4.9/5', label: 'CLIENT RATING' }
  ],
  packages: [
    {
      id: 'iso-non-iaf',
      name: 'ISO 9001 (Non-IAF / Fast Track)',
      price: 3499,
      isPopular: false,
      isAdjustable: false,
      description: 'Ideal for basic tenders, client credibility, and internal quality benchmarking.',
      features: ['ISO 9001:2015 QMS Certificate', '3-Year Certificate Validity', 'Fast Track 3-5 Days Issuance', 'Digital Certificate + QR Verification', 'Basic Quality Manual Template'],
      creativeButtonText: 'Select Non-IAF Plan'
    },
    {
      id: 'iso-iaf-accredited',
      name: 'ISO 9001 (IAF Accredited)',
      price: 6499,
      isPopular: true,
      isAdjustable: false,
      description: 'Global recognition with International Accreditation Forum (IAF) stamp for govt tenders & MNC exports.',
      features: ['IAF Recognized Certificate', 'Global Tender & Export Compliance', 'Complete QMS Manual & SOPs', 'Internal Audit Documentation', 'Official Registrar Portal Listing'],
      creativeButtonText: 'Select IAF Accredited'
    },
    {
      id: 'iso-integrated-combo',
      name: 'Integrated IMS (ISO 9001 + 14001 + 45001)',
      price: 14999,
      isPopular: false,
      isAdjustable: false,
      description: 'Triple certification combo covering Quality (9001), Environment (14001), and Safety (45001).',
      features: ['All 3 ISO Standard Certificates', 'Integrated Management System Manual', 'Hazard & Risk Analysis Templates', 'Dedicated Lead Auditor Support', 'Maximum Tender Evaluation Marks'],
      creativeButtonText: 'Select IMS Combo'
    }
  ],
  steps: [
    { number: '01', title: 'Gap Analysis', desc: 'Review existing business processes, quality objectives, and organizational structure.', badge: 'Step 1' },
    { number: '02', title: 'QMS Documentation', desc: 'Draft quality policies, Standard Operating Procedures (SOPs), and quality manuals.', badge: 'Step 2' },
    { number: '03', title: 'Audit Verification', desc: 'Lead auditor conducts Stage 1 document review and Stage 2 compliance audit.', badge: 'Step 3' },
    { number: '04', title: 'Certificate Issuance', desc: 'Official ISO 9001:2015 certificate issued with online QR and serial number verification.', badge: 'Step 4' }
  ],
  guide: {
    title: 'ISO 9001:2015 Certification Guide',
    overview: 'ISO 9001 is the international gold standard for Quality Management Systems, demonstrating to clients and tender authorities that your processes consistently meet high standards.',
    checklistTitle: 'Required Application Data',
    checklist: ['Company Registration / GST Certificate', 'Business Letterhead & Scope of Activities', 'List of Key Products / Services', 'Organizational Chart & Key Personnel']
  },
  faqs: [
    { q: 'What is the difference between IAF and Non-IAF certificates?', a: 'IAF (International Accreditation Forum) certificates are globally recognized and mandatory for government tenders, PSUs, and export markets. Non-IAF is suitable for internal branding and domestic private contracts.' },
    { q: 'What is the validity of the ISO 9001 certificate?', a: 'The certificate is valid for 3 years, subject to annual surveillance audits.' }
  ],
  popularSearches: ['ISO 9001 Certification Online', 'IAF ISO Certificate India', 'ISO 9001 Cost in India', 'Quality Management System QMS', 'ISO Certificate for Tenders']
};

const ISO9001CertificationPage = () => <UniversalServicePage config={serviceConfig} pageId="iso-9001-certification" />;

export default ISO9001CertificationPage;
