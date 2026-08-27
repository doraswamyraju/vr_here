import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'iso-14001-certification',
  title: 'ISO 14001:2015 Environmental Management System (EMS)',
  hero: {
    title: 'ISO 14001:2015 Certification in {city}',
    subtitle: 'Demonstrate environmental responsibility, reduce waste, and meet statutory ESG compliance with IAF accredited EMS certification.',
    badgeText: 'GREEN & ESG COMPLIANT',
    consultationPrice: 499
  },
  stats: [
    { value: '5-7 Days', label: 'TURNAROUND' },
    { value: '100%', label: 'POLLUTION BOARD SYNC' },
    { value: '3 Years', label: 'VALIDITY' },
    { value: '4.9/5', label: 'CLIENT RATING' }
  ],
  packages: [
    {
      id: 'iso-14001-standard',
      name: 'ISO 14001 (EMS Standard)',
      price: 5499,
      isPopular: true,
      isAdjustable: false,
      description: 'Full Environmental Management System certification with environmental aspect-impact register.',
      features: ['ISO 14001:2015 EMS Certificate', 'Aspect-Impact Assessment Register', 'Environmental Policy Drafting', '3-Year Certificate Validity', 'Audit Documentation Kit'],
      creativeButtonText: 'Select ISO 14001'
    }
  ],
  steps: [
    { number: '01', title: 'Environmental Review', desc: 'Identify energy consumption, waste streams, and environmental risks.', badge: 'Step 1' },
    { number: '02', title: 'EMS SOP Drafting', desc: 'Prepare waste management protocols and emergency response plans.', badge: 'Step 2' },
    { number: '03', title: 'Compliance Audit', desc: 'Lead auditor evaluates environmental compliance against ISO 14001 standard.', badge: 'Step 3' },
    { number: '04', title: 'EMS Certificate Issuance', desc: 'Certificate published with QR code verification and registrar listing.', badge: 'Step 4' }
  ],
  guide: {
    title: 'ISO 14001:2015 EMS Guide',
    overview: 'ISO 14001 helps organizations systematically manage environmental aspects, comply with Pollution Control Board norms, and enhance green credentials.',
    checklistTitle: 'Required Documentation',
    checklist: ['Business Registration & Factory/Office Address', 'Consent to Establish/Operate (CTE/CTO) if manufacturing', 'Waste Disposal & Energy Consumption Logs', 'Key Environmental Objectives']
  },
  faqs: [
    { q: 'Who needs ISO 14001 certification?', a: 'Manufacturing units, infrastructure companies, chemical processors, waste handlers, and corporate entities bidding for ESG tenders.' }
  ],
  popularSearches: ['ISO 14001 Certification India', 'Environmental Management System EMS', 'ISO 14001 Cost', 'Green Certification for Tenders']
};

const ISO14001CertificationPage = () => <UniversalServicePage config={serviceConfig} pageId="iso-14001-certification" />;

export default ISO14001CertificationPage;
