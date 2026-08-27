import React from 'react';
import UniversalServicePage from './components/UniversalServicePage';

const serviceConfig = {
  pageId: 'mis-reporting',
  title: 'Monthly MIS & Financial Management Reporting',
  hero: {
    title: 'Executive MIS & Financial Dashboards in {city}',
    subtitle: 'Transform raw accounting ledgers into actionable executive reports: Monthly P&L, Cashflow Forecasts, Unit Economics & Budget Variance.',
    badgeText: 'MANAGEMENT & CFO DASHBOARDS',
    consultationPrice: 499
  },
  stats: [
    { value: 'Monthly', label: 'EXECUTIVE REPORTS' },
    { value: '100%', label: 'CASHFLOW VISIBILITY' },
    { value: '4.9/5', label: 'C-LEVEL RATING' },
    { value: 'Virtual CFO', label: 'GUIDANCE' }
  ],
  packages: [
    {
      id: 'mis-standard',
      name: 'Standard Financial MIS',
      price: 3999,
      isPopular: false,
      isAdjustable: false,
      description: 'Monthly balance sheet, P&L, accounts receivable/payable aging, and gross margin analysis.',
      features: ['Monthly Income Statement (P&L)', 'Balance Sheet Summary', 'Debtor & Creditor Aging Analysis', 'Expense Variance vs Budget'],
      creativeButtonText: 'Select Standard MIS'
    },
    {
      id: 'mis-cfo',
      name: 'Executive CFO Pack',
      price: 7999,
      isPopular: true,
      isAdjustable: false,
      description: 'Custom KPIs, 12-month rolling cash flow forecast, customer acquisition unit economics, and 1-on-1 CFO review.',
      features: ['Interactive KPI Dashboard', '12-Month Rolling Cashflow Model', 'Customer LTV / CAC Unit Economics', '1-Hour Monthly Strategy Call with CA', 'Investor Ready Presentation Decks'],
      creativeButtonText: 'Select Executive CFO Pack'
    }
  ],
  steps: [
    { number: '01', title: 'Ledger Audit', desc: 'Verify closing balances and monthly journal entries for accuracy.', badge: 'Step 1' },
    { number: '02', title: 'Data Modeling', desc: 'Consolidate numbers into custom business unit and revenue stream models.', badge: 'Step 2' },
    { number: '03', title: 'Variance Analysis', desc: 'Benchmark actual performance against business budgets and prior periods.', badge: 'Step 3' },
    { number: '04', title: 'Executive Briefing', desc: 'Deliver interactive deck with strategic insights and risk alerts.', badge: 'Step 4' }
  ],
  guide: {
    title: 'Management Information System (MIS) Guide',
    overview: 'MIS reporting gives business owners, directors, and investors accurate, timely financial intelligence to make confident expansion and hiring decisions.',
    checklistTitle: 'Required Data Sources',
    checklist: ['Monthly P&L and Trial Balance', 'Sales & CRM Revenue Metrics', 'Outstanding AR/AP Aging Schedules', 'Bank & Cash Position Summaries']
  },
  faqs: [
    { q: 'How is an MIS report different from standard Tally P&L?', a: 'Standard accounting shows statutory figures. An MIS report breaks down customer acquisition costs, gross margins per product line, cash burn rates, and forward-looking forecasts.' },
    { q: 'Can this report be shared directly with startup investors or banks?', a: 'Yes! Our executive MIS reports are formatted to top venture capital and bank credit underwriting standards.' }
  ],
  popularSearches: ['MIS Reporting Services', 'Virtual CFO Services India', 'Cashflow Modeling CA', 'Financial Dashboard For Founders', 'Monthly P&L Variance Analysis']
};

const MisReportingPage = () => <UniversalServicePage config={serviceConfig} pageId="mis-reporting" />;

export default MisReportingPage;
