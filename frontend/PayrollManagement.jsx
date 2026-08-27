import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'payroll-management',
  title: 'Payroll Management, Payslips & Form 16',
  hero: {
    title: 'Automated Payroll & Statutory Compliance in {city}',
    subtitle: 'End-to-end salary processing, digital payslips, PF/ESI deductions, Professional Tax and Form 16 issuance.',
    badgeText: '100% STATUTORY COMPLIANT',
    consultationPrice: 499
  },
  stats: [
    { value: '100%', label: 'ON-TIME PAYSLIPS' },
    { value: 'PF / ESI', label: 'STATUTORY SYNC' },
    { value: 'Form 16', label: 'YEAR-END READY' },
    { value: '4.9/5', label: 'HR RATING' }
  ],
  packages: [
    {
      id: 'payroll-startup',
      name: 'Startup Team (Up to 10 Employees)',
      price: 2499,
      isPopular: false,
      isAdjustable: false,
      description: 'Monthly payroll calculation, digital payslips, and basic tax deductions.',
      features: ['Automated Salary Calculations', 'PDF Payslip Generation', 'Attendance & Leave Tracking', 'PF / ESI Challan Prep'],
      creativeButtonText: 'Select Startup Team'
    },
    {
      id: 'payroll-growth',
      name: 'Growth Enterprise (Up to 25 Employees)',
      price: 4999,
      isPopular: true,
      isAdjustable: false,
      description: 'Full-fledged payroll management with statutory filings and employee tax computations.',
      features: ['Dedicated Payroll Specialist', 'PF, ESI & PT Returns Filing', 'Employee Reimbursements', 'Annual Form 16 Generation', 'HR Compliance Audit'],
      creativeButtonText: 'Select Growth Enterprise'
    },
    {
      id: 'payroll-corporate',
      name: 'Corporate Custom (50+ Employees)',
      price: 9999,
      isPopular: false,
      isAdjustable: false,
      description: 'Enterprise HRMS integration, gratuity calculations, and multi-state labour compliance.',
      features: ['HRMS Portal Setup', 'Multi-State PT Compliance', 'Gratuity & Bonus Ledgers', 'Contract Labour Registers', 'Custom HR Policy Drafting'],
      creativeButtonText: 'Select Corporate Plan'
    }
  ],
  steps: [
    { number: '01', title: 'Employee Onboarding', desc: 'Provide employee master data, CTC structures, PAN, and bank accounts.', badge: 'Step 1' },
    { number: '02', title: 'Monthly Attendance', desc: 'Submit monthly leaves, overtime, and incentive data by month-end.', badge: 'Step 2' },
    { number: '03', title: 'Salary & Tax Computation', desc: 'Our payroll engine calculates TDS, PF, ESI, and net disbursements.', badge: 'Step 3' },
    { number: '04', title: 'Disbursement & Payslips', desc: 'Download bank upload file and instant branded payslips for all staff.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Payroll Compliance Guide',
    overview: 'Accurate payroll processing ensures employee satisfaction and guards against heavy penalties under EPF, ESIC, and Payment of Wages Acts.',
    checklistTitle: 'Required Employee Data',
    checklist: ['Employee Offer Letters & CTC Breakup', 'Aadhaar, PAN & Bank Account Details', 'UAN (EPF) and IP (ESIC) Numbers', 'Monthly Attendance & LOP Register']
  },
  faqs: [
    { q: 'Can you generate Form 16 Part A and Part B for employees?', a: 'Yes! At the end of the financial year, we generate TRACES-certified Form 16 with accurate TDS deductions.' },
    { q: 'Do you handle EPF and ESI monthly challan payment?', a: 'Yes, we calculate exact contributions, prepare Electronic Challan cum Return (ECR) files, and file them on the EPFO/ESIC portals.' },
    { q: 'Is Professional Tax (PT) calculated per state?', a: 'Yes, our payroll system automatically handles state-specific Professional Tax slabs across Andhra Pradesh, Telangana, Karnataka, Tamil Nadu, Maharashtra, etc.' }
  ],
  popularSearches: ['Payroll Outsourcing Services', 'Online Payslip Generator', 'PF ESI Return Filing', 'Form 16 Generation CA', 'Salary TDS Calculation India', 'Payroll Compliance Company']
};

const PayrollManagementPage = () => <UniversalServicePage config={serviceConfig} pageId="payroll-management" />;

export default PayrollManagementPage;
