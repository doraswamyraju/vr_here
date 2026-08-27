import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'iso-27001-certification',
  title: 'ISO/IEC 27001:2022 Information Security Management (ISMS)',
  hero: {
    title: 'ISO 27001:2022 ISMS Certification in {city}',
    subtitle: 'Protect confidential data, safeguard intellectual property, and satisfy enterprise IT client security vendor risk assessments.',
    badgeText: 'CYBERSECURITY & DATA PRIVACY GOLD STANDARD',
    consultationPrice: 499
  },
  stats: [
    { value: '7-10 Days', label: 'CERTIFICATION TIME' },
    { value: 'Annex A', label: 'CONTROLS AUDITED' },
    { value: 'Global MNC', label: 'VENDOR COMPLIANT' },
    { value: '4.9/5', label: 'TECH RATING' }
  ],
  packages: [
    {
      id: 'iso-27001-standard',
      name: 'ISO 27001:2022 ISMS Certification',
      price: 8999,
      isPopular: true,
      isAdjustable: false,
      description: 'Complete Information Security Management System certification mapped to latest 2022 Annex A controls.',
      features: ['ISO/IEC 27001:2022 Certificate', 'Statement of Applicability (SoA) Matrix', 'Information Security Policy & SOPs', 'Vulnerability & Risk Assessment Register', '3-Year Validity with Online Portal Entry'],
      creativeButtonText: 'Select ISO 27001'
    },
    {
      id: 'iso-27001-soc2-combo',
      name: 'ISMS + SOC 2 Readiness Bundle',
      price: 19999,
      isPopular: false,
      isAdjustable: false,
      description: 'Dual certification bundle designed for SaaS, fintech, and IT services companies serving US & EU clients.',
      features: ['ISO 27001:2022 Certificate', 'SOC 2 Type I/II Readiness Audit', 'GDPR & DPDP Act Data Privacy Mapping', 'Access Control & Incident Response Playbooks', 'Dedicated CISSP / Lead Auditor Support'],
      creativeButtonText: 'Select SaaS Security Bundle'
    }
  ],
  steps: [
    { number: '01', title: 'Asset & Risk Inventory', desc: 'Catalog IT infrastructure, cloud hosting (AWS/GCP), customer databases, and software repositories.', badge: 'Step 1' },
    { number: '02', title: 'ISMS Policies & SoA', desc: 'Draft access control policies, encryption standards, disaster recovery SOPs, and Statement of Applicability.', badge: 'Step 2' },
    { number: '03', title: 'Security Audit', desc: 'Certified cybersecurity auditor evaluates implementation of physical, technical, and organizational controls.', badge: 'Step 3' },
    { number: '04', title: 'Certification Delivery', desc: 'Official ISO/IEC 27001:2022 certificate issued with verifiable QR registry listing.', badge: 'Step 4' }
  ],
  guide: {
    title: 'ISO 27001 Cybersecurity Guide',
    overview: 'ISO 27001 is mandatory for IT service providers, SaaS companies, fintechs, and healthcare software vendors to win enterprise contracts.',
    checklistTitle: 'Required IT & Security Data',
    checklist: ['Company Registration & Office Locations', 'Cloud Architecture Diagram & Data Flow Maps', 'Employee Access Control & Password Policies', 'Data Backup & Incident Response Procedures']
  },
  faqs: [
    { q: 'What is new in the ISO 27001:2022 version?', a: 'The 2022 version consolidates Annex A controls into 4 categories (Organizational, People, Physical, Technological) and introduces cloud security and data leakage prevention controls.' },
    { q: 'Is ISO 27001 required for SaaS startups?', a: 'Yes! US and European enterprise buyers routinely require ISO 27001 or SOC 2 before signing software procurement contracts.' }
  ],
  popularSearches: ['ISO 27001 Certification Online', 'ISMS Certification Cost India', 'ISO 27001 2022 Revision', 'SaaS Security Certification', 'SOC 2 vs ISO 27001']
};

const ISO27001CertificationPage = () => <UniversalServicePage config={serviceConfig} pageId="iso-27001-certification" />;

export default ISO27001CertificationPage;
