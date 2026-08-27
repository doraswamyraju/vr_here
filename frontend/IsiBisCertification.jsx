import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'isi-bis-certification',
  title: 'ISI Mark & BIS Registration Services (Bureau of Indian Standards)',
  hero: {
    title: 'ISI Mark & BIS Certification in {city}',
    subtitle: 'Obtain ISI Mark (Scheme I) and BIS CRS Registration (Scheme II) for electronics, chemicals, steel, toys, footwear, and consumer goods.',
    badgeText: 'BUREAU OF INDIAN STANDARDS VERIFIED',
    consultationPrice: 499
  },
  stats: [
    { value: '100%', label: 'MANDATORY QCO COMPLIANT' },
    { value: 'BIS / CRS', label: 'SCHEMES COVERED' },
    { value: 'Indian / Foreign', label: 'MANUFACTURERS (FMCS)' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'bis-crs-registration',
      name: 'BIS CRS Registration (Scheme II)',
      price: 14999,
      isPopular: true,
      isAdjustable: false,
      description: 'Compulsory Registration Scheme (CRS) for IT goods, batteries, solar panels, and consumer electronics.',
      features: ['BIS Portal Profile & Application Filing', 'BIS Approved Lab Test Coordination', 'Query Handling with Technical Officers', 'BIS Registration Grant Letter', 'Validity & Renewal Guidance'],
      creativeButtonText: 'Select BIS CRS Plan'
    },
    {
      id: 'isi-mark-scheme1',
      name: 'ISI Mark Certification (Scheme I)',
      price: 24999,
      isPopular: false,
      isAdjustable: false,
      description: 'Comprehensive ISI mark license including factory in-house lab setup and factory audit support.',
      features: ['Indian Standard (IS) Code Mapping', 'Factory Lab & Testing Equipment Guidance', 'BIS Officer Factory Audit Assistance', 'Sample Testing & License Grant', 'ISI Mark Logo Usage Approval'],
      creativeButtonText: 'Select ISI Mark Scheme'
    }
  ],
  steps: [
    { number: '01', title: 'IS Code Identification', desc: 'Identify relevant Indian Standard (IS) and Quality Control Order (QCO) requirements.', badge: 'Step 1' },
    { number: '02', title: 'Sample Lab Testing', desc: 'Send product samples to NABL & BIS approved testing laboratories.', badge: 'Step 2' },
    { number: '03', title: 'Portal Filing & Audit', desc: 'Submit test report on Manakonline portal; coordinate factory inspection (Scheme I).', badge: 'Step 3' },
    { number: '04', title: 'Grant of License', desc: 'BIS issues formal Registration Number / CML Number for ISI mark stamping.', badge: 'Step 4' }
  ],
  guide: {
    title: 'BIS & ISI Mark Guide',
    overview: 'The Government of India has made BIS certification mandatory under various Quality Control Orders (QCOs) for manufacturing or importing hundreds of products.',
    checklistTitle: 'Required Documentation',
    checklist: ['Factory Registration / Manufacturing License', 'List of Manufacturing Machinery & In-house Testing Gear', 'Product PCB Layout, Circuit Diagrams & Specs', 'Authorized Indian Representative (AIR) for Foreign Units']
  },
  faqs: [
    { q: 'What products require mandatory BIS CRS registration?', a: 'Laptops, mobile phones, power adapters, LED lamps, solar inverters, smart watches, Bluetooth devices, and power banks.' },
    { q: 'Can foreign manufacturers get BIS certification?', a: 'Yes, under the Foreign Manufacturers Certification Scheme (FMCS), overseas factories can obtain ISI mark licenses.' }
  ],
  popularSearches: ['BIS Registration Online', 'ISI Mark Certification Cost', 'BIS CRS Portal Manakonline', 'BIS Certification for Electronics', 'FMCS BIS License']
};

const IsiBisCertificationPage = () => <UniversalServicePage config={serviceConfig} pageId="isi-bis-certification" />;

export default IsiBisCertificationPage;
