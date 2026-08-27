import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'ce-marking-certification',
  title: 'CE Marking Certification for European Export Compliance',
  hero: {
    title: 'CE Marking Certification in {city}',
    subtitle: 'Conformity assessment, Technical Construction File (TCF) preparation, and CE Marking for European Union (EU) export compliance.',
    badgeText: 'EUROPEAN UNION CONFORMITY COMPLIANT',
    consultationPrice: 499
  },
  stats: [
    { value: 'EU Market', label: 'EXPORT READY' },
    { value: '100%', label: 'DIRECTIVE COMPLIANT' },
    { value: '3 Years', label: 'VALIDITY' },
    { value: '4.9/5', label: 'EXPORTER RATING' }
  ],
  packages: [
    {
      id: 'ce-marking-plan',
      name: 'CE Marking Certification Plan',
      price: 12499,
      isPopular: true,
      isAdjustable: false,
      description: 'End-to-end CE Marking conformity for Machinery, Electronics (EMC/LVD), Medical Devices & PPE.',
      features: ['EU Directives Identification', 'Technical Construction File (TCF) Drafting', 'Declaration of Conformity (DoC)', 'CE Marking Certificate & Label Guidelines', 'Lab Test Report Coordination'],
      creativeButtonText: 'Select CE Marking Plan'
    }
  ],
  steps: [
    { number: '01', title: 'EU Directive Mapping', desc: 'Identify applicable EU directives (EMC, LVD, MDD/MDR, Machinery Directive).', badge: 'Step 1' },
    { number: '02', title: 'TCF Compilation', desc: 'Prepare Technical Construction File including schematics, bills of materials, and safety specs.', badge: 'Step 2' },
    { number: '03', title: 'Testing & Verification', desc: 'Review accredited lab test reports against harmonized European standards.', badge: 'Step 3' },
    { number: '04', title: 'CE Certificate & DoC', desc: 'Issue formal CE Certificate and Declaration of Conformity for customs clearance.', badge: 'Step 4' }
  ],
  guide: {
    title: 'CE Marking Guide for Exporters',
    overview: 'CE Marking is mandatory for selling industrial machinery, electronics, medical equipment, and consumer goods in the European Economic Area (EEA).',
    checklistTitle: 'Required Product Data',
    checklist: ['Product Technical Specifications & User Manual', 'Circuit Diagrams & Component Bill of Materials (BOM)', 'Factory Test Reports & Safety Data Sheets', 'Manufacturer Authorization & Letterhead']
  },
  faqs: [
    { q: 'Is CE Marking mandatory for all exports to Europe?', a: 'Yes, any product covered by European Union safety directives cannot be cleared by EU customs without valid CE Marking.' }
  ],
  popularSearches: ['CE Marking India', 'CE Certificate Cost India', 'EU Export Certification', 'CE Mark Consultant Machinery']
};

const CeMarkingCertificationPage = () => <UniversalServicePage config={serviceConfig} pageId="ce-marking-certification" />;

export default CeMarkingCertificationPage;
