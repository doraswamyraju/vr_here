import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'machinery-sourcing',
  title: 'Turnkey Machinery Sourcing, Industrial Setup & Plant Engineering',
  hero: {
    title: 'Industrial Machinery Sourcing & Factory Setup in {city}',
    subtitle: 'End-to-end industrial plant engineering: Domestic & global machinery procurement, factory layout optimization, ETP/STP design, and trial batch production.',
    badgeText: 'INDUSTRIAL CONSULTING & PLANT ENGINEERING',
    consultationPrice: 499
  },
  stats: [
    { value: 'Turnkey', label: 'FACTORY SETUP' },
    { value: 'Domestic & Global', label: 'MACHINERY VENDORS' },
    { value: '100%', label: 'POLLUTION & SPCB SYNC' },
    { value: '4.9/5', label: 'INDUSTRY RATING' }
  ],
  packages: [
    {
      id: 'machinery-vendor-selection',
      name: 'Machinery Vendor Sourcing & Evaluation',
      price: 9999,
      isPopular: true,
      isAdjustable: false,
      description: 'Vendor identification, competitive techno-commercial bidding, machinery inspection, and contract drafting.',
      features: ['Domestic & Global OEM Vendor Shortlisting', 'Technical Specifications & Capacity Matching', 'Price Negotiation & Payment Escrow Terms', 'Customs Duty & Freight Logistics Advisory', 'Factory Acceptance Test (FAT) Checklist'],
      creativeButtonText: 'Source Industrial Machinery'
    },
    {
      id: 'turnkey-plant-setup',
      name: 'Turnkey Industrial Plant Setup Retainer',
      price: 24999,
      isPopular: false,
      isAdjustable: false,
      description: 'Full-service factory engineering from land layout, civil construction specs, power load approval, and trial production.',
      features: ['Factory Floor CAD Layout & Workflow Optimization', 'Connected Power Load & Transformer Estimation', 'Pollution Board (SPCB) CTE/CTO Technical Specs', 'Factory License & Fire NOC Integration', 'Dedicated Industrial Project Manager'],
      creativeButtonText: 'Select Turnkey Factory Plan'
    }
  ],
  steps: [
    { number: '01', title: 'Product & Capacity Sizing', desc: 'Define output units per day, automation level, raw material inputs, and power requirements.', badge: 'Step 1' },
    { number: '02', title: 'Vendor Techno-Commercial Bids', desc: 'Receive and benchmark quotations from verified OEM machinery manufacturers.', badge: 'Step 2' },
    { number: '03', title: 'Plant Engineering & Civil Layout', desc: 'Draft electrical single line diagrams (SLD), water piping, and machine foundations.', badge: 'Step 3' },
    { number: '04', title: 'Installation & Trial Run', desc: 'Oversee machine erection, calibration, trial batch output, and operator training.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Industrial Plant & Machinery Guide',
    overview: 'Setting up a manufacturing plant requires tight coordination between machinery procurement, factory licensing, power clearances, and environmental consents.',
    checklistTitle: 'Required Project Information',
    checklist: ['Finished Product Technical Specifications', 'Proposed Daily / Monthly Output Capacity', 'Land Plot Size & Industrial Zone Details', 'Available Power Connected Load (KVA/HP)']
  },
  faqs: [
    { q: 'Do you help with imported machinery customs clearance?', a: 'Yes! We coordinate with customs house agents (CHA), EPCG scheme duty exemptions, and port clearance.' }
  ],
  popularSearches: ['Industrial Machinery Sourcing India', 'Turnkey Factory Setup Consultant', 'Manufacturing Plant Layout Engineering', 'EPCG Scheme Machinery Import']
};

const MachinerySourcingPage = () => <UniversalServicePage config={serviceConfig} pageId="machinery-sourcing" />;

export default MachinerySourcingPage;
