import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'gem-registration',
  title: 'GeM Portal Seller Registration, OEM Panel & Tender Management',
  hero: {
    title: 'GeM Portal Seller & OEM Registration in {city}',
    subtitle: 'Sell your goods and services directly to Government Ministries, PSUs, and Defence departments on Government e-Marketplace (GeM).',
    badgeText: 'GOVERNMENT E-MARKETPLACE (GEM) SPECIALIST',
    consultationPrice: 499
  },
  stats: [
    { value: '₹4 Lakh Cr+', label: 'ANNUAL GEM PROCUREMENT' },
    { value: '100%', label: 'DIRECT GOVT SALES' },
    { value: 'Zero EMD', label: 'FOR MSMEs' },
    { value: '4.9/5', label: 'RATING' }
  ],
  packages: [
    {
      id: 'gem-seller-basic',
      name: 'GeM Primary Seller Account',
      price: 2999,
      isPopular: false,
      isAdjustable: false,
      description: 'Primary seller account registration, Aadhaar/PAN linking, and Caution Money deposit setup.',
      features: ['Primary Seller Profile Creation', 'Bank PFMS Validation & Caution Money Setup', 'GeM Organization Category Mapping', 'MSME / Startup India Exemption Tagging', 'Account Verification Handholding'],
      creativeButtonText: 'Register as GeM Seller'
    },
    {
      id: 'gem-oem-catalog',
      name: 'OEM Panel + Brand Listing Plan',
      price: 7999,
      isPopular: true,
      isAdjustable: false,
      description: 'Original Equipment Manufacturer (OEM) vendor assessment, brand approval, and catalog publishing.',
      features: ['OEM Panel Approval Assistance', 'Brand Approval on GeM Portal', '10 Product / Service Catalog Listings', 'GeM Vendor Assessment Exemption Handling', 'Reseller Authorization Management'],
      creativeButtonText: 'Select OEM & Brand Plan'
    },
    {
      id: 'gem-tender-bidding',
      name: 'GeM Bid Participation & Tender Retainer',
      price: 14999,
      isPopular: false,
      isAdjustable: false,
      description: 'Full-service government tender identification, technical bid compilation, and L1 bidding management.',
      features: ['Daily GeM Tender & Direct Purchase Alerts', 'Technical & Financial Bid Documentation', 'Reverse Auction (RA) Participation Support', 'L1 Strategy & Negotiation Guidance', 'Dedicated GeM Tender Specialist'],
      creativeButtonText: 'Select Tender Retainer'
    }
  ],
  steps: [
    { number: '01', title: 'Aadhaar & Entity Setup', desc: 'Verify business PAN, Udyam MSME certificate, and Aadhaar linked to mobile.', badge: 'Step 1' },
    { number: '02', title: 'Caution Money Deposit', desc: 'Create GeM pool account and deposit mandatory caution money via PFMS.', badge: 'Step 2' },
    { number: '03', title: 'Brand & Catalog Upload', desc: 'Upload trademarks, product specifications, images, and MRP pricing.', badge: 'Step 3' },
    { number: '04', title: 'Live on GeM', desc: 'Your products and services are live for direct purchase and government bidding.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Government e-Marketplace (GeM) Guide',
    overview: 'GeM is the mandatory national public procurement portal for all Central & State Government departments, PSUs, Railways, and Defence establishments.',
    checklistTitle: 'Required GeM Documents',
    checklist: ['PAN Card of Business & Authorized Signatory', 'Udyam MSME Registration & GST Certificate', 'Cancelled Cheque & Bank Account Details', 'Class 3 Organization DSC (Signing + Encryption)']
  },
  faqs: [
    { q: 'What is Caution Money on GeM?', a: 'GeM mandates a refundable caution money deposit (₹5,000 for turnover <1 Cr, ₹10,000 for 1-10 Cr, ₹25,000 for >10 Cr) to ensure seller commitment.' },
    { q: 'Can service providers (IT, manpower, cleaning, transport) register on GeM?', a: 'Yes! GeM features thousands of service categories where contractors bid for government service tenders.' }
  ],
  popularSearches: ['GeM Seller Registration Online', 'GeM Portal Login', 'GeM OEM Dashboard', 'Brand Approval on GeM', 'GeM Tender Bidding Service']
};

const GemRegistrationPage = () => <UniversalServicePage config={serviceConfig} pageId="gem-registration" />;

export default GemRegistrationPage;
