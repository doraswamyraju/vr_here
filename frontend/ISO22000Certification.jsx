import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'iso-22000-certification',
  title: 'ISO 22000:2018 Food Safety Management System (FSMS)',
  hero: {
    title: 'ISO 22000:2018 FSMS Certification in {city}',
    subtitle: 'Ensure international food safety standards across your processing, packaging, cold storage, and export food supply chain.',
    badgeText: 'FOOD SAFETY & HACCP ALIGNED',
    consultationPrice: 499
  },
  stats: [
    { value: '5-7 Days', label: 'TURNAROUND' },
    { value: 'HACCP', label: 'INTEGRATED' },
    { value: 'FSSAI & Global', label: 'RECOGNITION' },
    { value: '4.9/5', label: 'CLIENT RATING' }
  ],
  packages: [
    {
      id: 'iso-22000-standard',
      name: 'ISO 22000 FSMS Certification',
      price: 6999,
      isPopular: true,
      isAdjustable: false,
      description: 'Complete FSMS certification incorporating HACCP principles, Prerequisite Programmes (PRPs), and traceability.',
      features: ['ISO 22000:2018 FSMS Certificate', 'HACCP Plan & Critical Control Points (CCP)', 'Food Safety Manual & Hygiene SOPs', 'Supplier & Raw Material Traceability Guidelines', '3-Year Certificate Validity'],
      creativeButtonText: 'Select ISO 22000'
    }
  ],
  steps: [
    { number: '01', title: 'Food Chain Assessment', desc: 'Review ingredients, storage conditions, cooking/processing, and packaging stages.', badge: 'Step 1' },
    { number: '02', title: 'HACCP & PRP Setup', desc: 'Identify Critical Control Points (CCPs) and establish monitoring thresholds.', badge: 'Step 2' },
    { number: '03', title: 'FSMS Audit', desc: 'Lead food auditor verifies hygiene protocols, temperature logs, and recall plans.', badge: 'Step 3' },
    { number: '04', title: 'Certificate Issuance', desc: 'Official ISO 22000 certificate issued for domestic trade and international export.', badge: 'Step 4' }
  ],
  guide: {
    title: 'ISO 22000 Food Safety Guide',
    overview: 'ISO 22000 combines HACCP principles with ISO management architecture to guarantee food safety from farm to fork.',
    checklistTitle: 'Required Documentation',
    checklist: ['FSSAI License Copy & Unit Layout Plan', 'Process Flow Diagram & Machinery List', 'Pest Control & Water Testing Reports', 'Staff Health & Hygiene Certificates']
  },
  faqs: [
    { q: 'Is ISO 22000 mandatory for food export from India?', a: 'Yes, international buyers, supermarket chains, and overseas customs authorities mandate ISO 22000 or BRCGS certification.' }
  ],
  popularSearches: ['ISO 22000 Certification Online', 'Food Safety Management FSMS', 'HACCP vs ISO 22000', 'Food Export Certification India']
};

const ISO22000CertificationPage = () => <UniversalServicePage config={serviceConfig} pageId="iso-22000-certification" />;

export default ISO22000CertificationPage;
