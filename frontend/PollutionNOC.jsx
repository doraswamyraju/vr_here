import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'pollution-noc',
  title: 'State Pollution Control Board NOC (CTE & CTO Certification)',
  hero: {
    title: 'Pollution Control Board NOC (CTE & CTO) in {city}',
    subtitle: 'Obtain Consent to Establish (CTE) and Consent to Operate (CTO) under the Water & Air Acts from State Pollution Control Boards (SPCB).',
    badgeText: 'STATE POLLUTION CONTROL BOARD (SPCB) APPROVED',
    consultationPrice: 499
  },
  stats: [
    { value: 'White / Green / Orange / Red', label: 'CATEGORIES COVERED' },
    { value: '100%', label: 'ENVIRONMENTAL COMPLIANT' },
    { value: 'CTE & CTO', label: 'CERTIFICATES' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'spcb-green-white-noc',
      name: 'Pollution NOC (White & Green Category)',
      price: 9999,
      isPopular: true,
      isAdjustable: false,
      description: 'Consent application for low-pollution, IT, assembly, packaging, and green category units.',
      features: ['Pollution Category Mapping (CPCB Norms)', 'CTE / CTO Online Application Filing', 'Effluent & Emission Declaration Drafting', 'SPCB Regional Office Liaison', 'Official Consent Certificate Issuance'],
      creativeButtonText: 'Apply for Green/White NOC'
    },
    {
      id: 'spcb-orange-red-noc',
      name: 'Pollution NOC (Orange & Red Category)',
      price: 19999,
      isPopular: false,
      isAdjustable: false,
      description: 'Comprehensive consent for manufacturing, chemical, food processing, and heavy industrial plants.',
      features: ['ETP / STP Wastewater Treatment Guidance', 'Stack Emission & Noise Level Review', 'Hazardous Waste Authorization (Form 1)', 'Environmental Engineer Site Inspection Support', 'Full Compliance & Renewal Handholding'],
      creativeButtonText: 'Select Industrial SPCB Plan'
    }
  ],
  steps: [
    { number: '01', title: 'Category Classification', desc: 'Classify manufacturing unit into White, Green, Orange, or Red category under CPCB guidelines.', badge: 'Step 1' },
    { number: '02', title: 'Technical Project Report', desc: 'Prepare manufacturing process flowchart, water balance, and waste treatment specs.', badge: 'Step 2' },
    { number: '03', title: 'SPCB Portal Submission', desc: 'Submit application with capital investment proof on state OCMMS portal.', badge: 'Step 3' },
    { number: '04', title: 'Consent Issuance', desc: 'Pollution Control Board issues formal Consent to Establish (CTE) / Operate (CTO).', badge: 'Step 4' }
  ],
  guide: {
    title: 'Pollution Control Board (SPCB) NOC Guide',
    overview: 'Under the Water (Prevention & Control of Pollution) Act and Air Act, industrial and commercial units must obtain Consent to Establish before starting construction, and Consent to Operate before running machinery.',
    checklistTitle: 'Required Documentation',
    checklist: ['Site Plan & Land Document / Factory Rent Agreement', 'Project Report with Capital Investment Value', 'Manufacturing Process Flowchart & Raw Material Data', 'Effluent / Sewage Treatment Plant (ETP/STP) Layout']
  },
  faqs: [
    { q: 'What is the difference between CTE and CTO?', a: 'CTE (Consent to Establish) is required prior to setting up machinery or starting factory construction. CTO (Consent to Operate) is required before commercial production commences.' }
  ],
  popularSearches: ['Pollution NOC Online', 'State Pollution Control Board CTE CTO', 'SPCB Consent Fees Calculator', 'APPCB TSPCB Pollution NOC']
};

const PollutionNOCPage = () => <UniversalServicePage config={serviceConfig} pageId="pollution-noc" />;

export default PollutionNOCPage;
