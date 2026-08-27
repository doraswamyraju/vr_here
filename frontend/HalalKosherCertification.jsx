import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'halal-kosher-certification',
  title: 'Halal & Kosher Certification Services',
  hero: {
    title: 'Halal & Kosher Certification in {city}',
    subtitle: 'Accredited Halal and Kosher certification for food processing, pharmaceuticals, cosmetics, and agricultural exports to Middle East, US & global markets.',
    badgeText: 'INTERNATIONAL RELIGIOUS CONFORMITY ACCREDITED',
    consultationPrice: 499
  },
  stats: [
    { value: '5-7 Days', label: 'CERTIFICATION TIME' },
    { value: 'GCC / Middle East', label: 'EXPORT ACCEPTED' },
    { value: '3 Years', label: 'VALIDITY' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'halal-certification-plan',
      name: 'Halal Certification Plan',
      price: 7999,
      isPopular: true,
      isAdjustable: false,
      description: 'Accredited Halal certification for domestic food businesses and Middle East / GCC export compliance.',
      features: ['Halal Compliance Audit', 'Raw Material & Ingredient Verification', 'Halal Slaughter / Processing Review', 'Certificate Issuance with QR Code', 'Annual Renewal Support'],
      creativeButtonText: 'Select Halal Plan'
    },
    {
      id: 'kosher-certification-plan',
      name: 'Kosher Certification Plan',
      price: 11999,
      isPopular: false,
      isAdjustable: false,
      description: 'Rabbinical Kosher certification for food, chemicals, and ingredients for US, European, and Israeli exports.',
      features: ['Rabbinical Kosher Ingredient Audit', 'Equipment Kosherization Protocols', 'Kosher Certificate & Logo Usage Approval', 'International Exporter Registry Entry'],
      creativeButtonText: 'Select Kosher Plan'
    }
  ],
  steps: [
    { number: '01', title: 'Ingredient Audit', desc: 'Screen raw materials, additives, flavorings, and processing aids for conformity.', badge: 'Step 1' },
    { number: '02', title: 'Facility Inspection', desc: 'Inspect production lines, cleaning protocols, and cross-contamination risks.', badge: 'Step 2' },
    { number: '03', title: 'Sharia / Rabbinical Review', desc: 'Board scholars verify religious compliance standards.', badge: 'Step 3' },
    { number: '04', title: 'Certificate Delivery', desc: 'Formal Halal / Kosher certificate issued with global export authentication.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Halal & Kosher Certification Guide',
    overview: 'Halal and Kosher certifications guarantee that food, beverages, supplements, and cosmetics are manufactured strictly according to Islamic and Jewish dietary laws.',
    checklistTitle: 'Required Documentation',
    checklist: ['Business Registration & FSSAI License', 'Complete Bill of Ingredients & Source Certificates', 'Manufacturing Process Flowchart & Cleaning Protocols', 'Product Packaging Artwork with Logo Placement']
  },
  faqs: [
    { q: 'Is Halal certification mandatory for export to UAE and Saudi Arabia?', a: 'Yes, food, cosmetics, and pharma products imported into Gulf Cooperation Council (GCC) countries require certified Halal compliance.' }
  ],
  popularSearches: ['Halal Certification India', 'Kosher Certificate Apply Online', 'Halal Export Certificate UAE', 'Halal Food Compliance']
};

const HalalKosherCertificationPage = () => <UniversalServicePage config={serviceConfig} pageId="halal-kosher-certification" />;

export default HalalKosherCertificationPage;
