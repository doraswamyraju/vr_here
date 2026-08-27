import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'iso-45001-certification',
  title: 'ISO 45001:2018 Occupational Health & Safety (OH&SMS)',
  hero: {
    title: 'ISO 45001:2018 Certification in {city}',
    subtitle: 'Ensure maximum workplace safety, reduce occupational injuries, and qualify for high-value industrial and construction contracts.',
    badgeText: 'WORKPLACE SAFETY STANDARD',
    consultationPrice: 499
  },
  stats: [
    { value: '5-7 Days', label: 'TURNAROUND' },
    { value: 'Zero', label: 'SAFETY COMPLIANCE RISK' },
    { value: '3 Years', label: 'VALIDITY' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'iso-45001-standard',
      name: 'ISO 45001 (OH&S Standard)',
      price: 5999,
      isPopular: true,
      isAdjustable: false,
      description: 'Complete Occupational Health & Safety certification with Hazard Identification & Risk Assessment (HIRA).',
      features: ['ISO 45001:2018 Certificate', 'HIRA Risk Assessment Template', 'Safety Manual & Emergency SOPs', '3-Year Certificate Validity', 'Lead Auditor Audit Verification'],
      creativeButtonText: 'Select ISO 45001'
    }
  ],
  steps: [
    { number: '01', title: 'Hazard Identification', desc: 'Identify operational hazards, machinery risks, and worker safety protocols.', badge: 'Step 1' },
    { number: '02', title: 'Safety Policies', desc: 'Draft OH&S policy, PPE requirements, and incident reporting SOPs.', badge: 'Step 2' },
    { number: '03', title: 'Safety Audit', desc: 'Auditor verifies implementation of safety controls and emergency preparedness.', badge: 'Step 3' },
    { number: '04', title: 'Certificate Delivery', desc: 'Official ISO 45001 certificate issued with online registry verification.', badge: 'Step 4' }
  ],
  guide: {
    title: 'ISO 45001:2018 OH&S Guide',
    overview: 'ISO 45001 replaces the old OHSAS 18001 standard and is mandatory for construction, engineering, oil & gas, and heavy manufacturing contracts.',
    checklistTitle: 'Required Safety Documentation',
    checklist: ['Business Registration & Premises Details', 'List of Machinery, Equipment & Chemicals Used', 'PPE Distribution & Safety Incident Logbooks', 'Emergency Evacuation & Fire Safety Plan']
  },
  faqs: [
    { q: 'Is ISO 45001 required for government infrastructure tenders?', a: 'Yes, most NHAI, Railways, CPWD, and PSU tenders mandate ISO 45001 certification.' }
  ],
  popularSearches: ['ISO 45001 Certification India', 'Occupational Health and Safety Certificate', 'OHSAS 18001 to ISO 45001', 'ISO Safety Certificate Cost']
};

const ISO45001CertificationPage = () => <UniversalServicePage config={serviceConfig} pageId="iso-45001-certification" />;

export default ISO45001CertificationPage;
