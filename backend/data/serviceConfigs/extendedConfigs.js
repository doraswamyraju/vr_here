export const EXTENDED_SERVICE_CONFIGS = {
    'cloud-accounting': {
        pageId: 'cloud-accounting',
        title: 'Cloud Accounting & Bookkeeping Services',
        description: 'Streamline your ledgers on Tally Prime, Zoho Books, QuickBooks & Marg with certified CAs and dedicated accounts managers.',
        iconKey: 'Calculator',
        hero: {
            title: 'Cloud Accounting & Real-Time Bookkeeping in {city}',
            subtitle: 'Streamline your ledgers on Tally Prime, Zoho Books, QuickBooks & Marg with certified CAs and dedicated accounts managers.',
            badgeText: 'TALLY & ZOHO CERTIFIED',
            consultationPrice: 499
        },
        stats: [
            { value: 'Daily / Mth', label: 'LEDGER UPDATES' },
            { value: '100%', label: 'TAX COMPLIANT' },
            { value: '4.9/5', label: 'CLIENT RATING' },
            { value: 'Zero', label: 'ACCOUNTING HEADACHE' }
        ],
        packages: [
            { id: 'startup-books', name: 'Startup Accounting', price: 2999, description: 'Up to 50 transactions/month with monthly P&L and Balance Sheet.', features: ['Bank Reconciliation', 'Purchase & Sales Ledgers', 'Monthly P&L & Balance Sheet', 'GST Invoicing Support'], creativeButtonText: 'Select Startup Books' },
            { id: 'growth-books', name: 'Growth Business Books', price: 5999, isPopular: true, description: 'Up to 200 transactions/mo with dedicated CA review.', features: ['Dedicated CA Review', 'Tally / Zoho Setup', 'Vendor & Customer Ledgers', 'Monthly MIS Reports', 'TDS & GST Compliance'], creativeButtonText: 'Select Growth Books' },
            { id: 'enterprise-books', name: 'Enterprise Full-Stack', price: 11999, description: 'Virtual CFO advisory, payroll ledger, and unlimited accounting.', features: ['Daily Bookkeeping', 'Virtual CFO Advisory', 'Custom MIS Dashboards', 'Statutory Audit Support', 'Multi-GSTIN Ledgers'], creativeButtonText: 'Select Enterprise Books' }
        ]
    },
    'gst-return-filing': {
        pageId: 'gst-return-filing',
        title: 'GST Return Filing (GSTR-1, GSTR-3B, GSTR-9)',
        description: 'Timely filing of GSTR-1, GSTR-3B, GSTR-9 annual returns with 100% ITC matching and zero penalty guarantee.',
        iconKey: 'Percent',
        hero: {
            title: 'Hassle-Free GST Return Filing Online in {city}',
            subtitle: 'Timely filing of GSTR-1, GSTR-3B, GSTR-9 annual returns with 100% ITC matching and zero penalty guarantee.',
            badgeText: 'GSTN AUTHORIZED FILING',
            consultationPrice: 499
        },
        stats: [
            { value: '100%', label: 'ITC RECONCILIATION' },
            { value: 'Zero', label: 'LATE PENALTY' },
            { value: '4.9/5', label: 'RATING' },
            { value: 'CA Verified', label: 'ACCURACY' }
        ],
        packages: [
            { id: 'gst-nil', name: 'Nil Return Plan', price: 499, description: 'For registered entities with zero sales or purchases.', features: ['GSTR-1 Nil Filing', 'GSTR-3B Nil Filing', 'Acknowledgement ARN', 'SMS Confirmation'], creativeButtonText: 'Select Nil Plan' },
            { id: 'gst-monthly-regular', name: 'Monthly Regular Filing', price: 1499, isPopular: true, description: 'Complete monthly filing with GSTR-2B ITC reconciliation.', features: ['GSTR-1 & 3B Filing', 'GSTR-2B ITC Matching', 'E-Way Bill Advisory', 'Tax Liability Optimization', 'Dedicated CA Review'], creativeButtonText: 'Select Regular Filing' },
            { id: 'gst-annual-audit', name: 'Annual Return (GSTR-9)', price: 4999, description: 'Annual consolidation and turnover reconciliation.', features: ['Annual Table-by-Table Filing', 'Turnover Reconciliation', 'ITC Reversal Audit', 'CA Certification'], creativeButtonText: 'Select GSTR-9 Plan' }
        ]
    },
    'payroll-management': {
        pageId: 'payroll-management',
        title: 'Payroll Management, Payslips & Form 16',
        description: 'End-to-end salary processing, digital payslips, PF/ESI deductions, Professional Tax and Form 16 issuance.',
        iconKey: 'Users',
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
            { id: 'payroll-startup', name: 'Startup Team (Up to 10 Employees)', price: 2499, description: 'Monthly payroll calculation, digital payslips, and PF/ESI calculations.', features: ['Automated Salary Calculations', 'PDF Payslip Generation', 'Attendance & Leave Tracking', 'PF / ESI Challan Prep'], creativeButtonText: 'Select Startup Team' },
            { id: 'payroll-growth', name: 'Growth Enterprise (Up to 25 Employees)', price: 4999, isPopular: true, description: 'Full-fledged payroll management with statutory returns.', features: ['Dedicated Payroll Specialist', 'PF, ESI & PT Returns Filing', 'Employee Reimbursements', 'Annual Form 16 Generation', 'HR Compliance Audit'], creativeButtonText: 'Select Growth Enterprise' }
        ]
    },
    'professional-tax': {
        pageId: 'professional-tax',
        title: 'Professional Tax (PT) Registration & Returns',
        description: 'Obtain PT Enrollment Certificate (PTEC) & PT Registration Certificate (PTRC) with timely monthly and annual return filing.',
        iconKey: 'Building2',
        hero: {
            title: 'Professional Tax (PT) Registration & Filing in {city}',
            subtitle: 'Obtain PT Enrollment Certificate (PTEC) & PT Registration Certificate (PTRC) with timely monthly and annual return filing.',
            badgeText: 'STATE TAX DEPARTMENT VERIFIED',
            consultationPrice: 499
        },
        stats: [
            { value: '2-3 Days', label: 'REGISTRATION TIME' },
            { value: '100%', label: 'SLAB COMPLIANT' },
            { value: '4.9/5', label: 'CLIENT RATING' },
            { value: 'All States', label: 'SUPPORTED' }
        ],
        packages: [
            { id: 'pt-registration-only', name: 'PT Registration (PTEC/PTRC)', price: 1999, isPopular: true, description: 'Registration of establishment with state commercial tax department.', features: ['PTEC / PTRC Registration', 'Certificate Issuance', 'Slab Assessment Advisory', 'Online Portal Setup'], creativeButtonText: 'Register for PT' },
            { id: 'pt-annual-filing', name: 'Annual PT Filing & Returns', price: 3499, description: 'Monthly deduction compliance and annual return submission.', features: ['Monthly PT Deduction Schedules', 'Annual Form Filing', 'Challan Preparation & Payment', 'Penalty Protection'], creativeButtonText: 'Select PT Filing' }
        ]
    },
    'epf-esi-returns': {
        pageId: 'epf-esi-returns',
        title: 'EPF & ESIC Registration & Monthly Return Filing',
        description: 'Provident Fund (PF) and Employee State Insurance (ESI) registration, UAN generation, and monthly ECR challans.',
        iconKey: 'ShieldCheck',
        hero: {
            title: 'EPF & ESIC Registration & ECR Filing in {city}',
            subtitle: 'Provident Fund (PF) and Employee State Insurance (ESI) registration, UAN generation, monthly ECR challans, and inspection assistance.',
            badgeText: 'EPFO & ESIC STATUTORY CERTIFIED',
            consultationPrice: 499
        },
        stats: [
            { value: '100%', label: 'ECR ACCURACY' },
            { value: '2-3 Days', label: 'REGISTRATION' },
            { value: 'Zero', label: 'INSPECTION RISK' },
            { value: '4.9/5', label: 'RATING' }
        ],
        packages: [
            { id: 'pf-esi-registration', name: 'PF & ESI Registration Code', price: 2999, description: 'Establishment code generation under EPFO & ESIC portals.', features: ['EPFO Employer Code', 'ESIC Sub-Code Issuance', 'Digital Signature (DSC) Linking', 'Portal Master Setup'], creativeButtonText: 'Get PF & ESI Codes' },
            { id: 'pf-esi-monthly-filing', name: 'Monthly ECR Return Filing', price: 1999, isPopular: true, description: 'Monthly ECR preparation, challan generation, employee additions & exit marking.', features: ['Monthly ECR Upload & Filing', 'UAN Generation for New Joinees', 'ESI Insurance Card (TIC) Issuance', 'Member KYC Approval Support', 'Inspection & Notice Advisory'], creativeButtonText: 'Select Monthly Filing' }
        ]
    },
    'tds-tcs-filing': {
        pageId: 'tds-tcs-filing',
        title: 'TDS & TCS Return Filing (24Q, 26Q, 27Q, 27EQ)',
        description: 'Quarterly filing of Form 24Q, 26Q, Challan ITNS 281 matching, and TRACES Form 16/16A generation.',
        iconKey: 'FileText',
        hero: {
            title: 'TDS & TCS Return Filing & Form 16A Issuance in {city}',
            subtitle: 'Quarterly filing of Form 24Q (Salaries), 26Q (Vendors), 27EQ (TCS), Challan ITNS 281 matching, and TRACES Form 16/16A generation.',
            badgeText: 'TRACES & INCOME TAX VERIFIED',
            consultationPrice: 499
        },
        stats: [
            { value: '100%', label: '26AS / AIS MATCH' },
            { value: 'Zero', label: 'TDS DEFAULTS' },
            { value: 'Form 16A', label: 'TRACES GENERATED' },
            { value: '4.9/5', label: 'RATING' }
        ],
        packages: [
            { id: 'tds-quarterly-filing', name: 'Quarterly TDS Filing (Per Form)', price: 1999, isPopular: true, description: 'Preparation of Form 24Q / 26Q and TRACES submission.', features: ['Form 24Q (Salary) or 26Q (Vendor)', 'ITNS 281 Challan Matching', 'FVU File Validation', 'TRACES Form 16A Generation', 'Demand / Default Notice Resolution'], creativeButtonText: 'File TDS Return' },
            { id: 'tds-annual-package', name: 'Annual TDS Retainer (All 4 Quarters)', price: 6999, description: 'Comprehensive 4-quarter compliance for salary and non-salary deductions.', features: ['All 4 Quarters Form 24Q & 26Q', 'TCS Form 27EQ (if applicable)', 'Correction Return Filing', 'Form 16 Part A & B Certificates', 'Direct CA Advisory Support'], creativeButtonText: 'Select Annual Retainer' }
        ]
    },
    'mis-reporting': {
        pageId: 'mis-reporting',
        title: 'Monthly MIS & Financial Management Reporting',
        description: 'Monthly balance sheet, P&L, cashflow forecasts, and unit economics for founders and investors.',
        iconKey: 'TrendingUp',
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
            { id: 'mis-standard', name: 'Standard Financial MIS', price: 3999, description: 'Monthly balance sheet, P&L, accounts receivable/payable aging.', features: ['Monthly Income Statement (P&L)', 'Balance Sheet Summary', 'Debtor & Creditor Aging Analysis', 'Expense Variance vs Budget'], creativeButtonText: 'Select Standard MIS' },
            { id: 'mis-cfo', name: 'Executive CFO Pack', price: 7999, isPopular: true, description: 'Custom KPIs, 12-month rolling cash flow forecast, and 1-on-1 CA review.', features: ['Interactive KPI Dashboard', '12-Month Rolling Cashflow Model', 'Customer LTV / CAC Unit Economics', '1-Hour Monthly Strategy Call with CA', 'Investor Ready Presentation Decks'], creativeButtonText: 'Select Executive CFO Pack' }
        ]
    },
    'audit-services': {
        pageId: 'audit-services',
        title: 'Internal Audit, GST Audit & Statutory Audit Services',
        description: 'Independent financial reviews, internal control audits, GST risk assessments, and Section 44AB tax audit.',
        iconKey: 'Award',
        hero: {
            title: 'Internal, GST & Statutory Audit Solutions in {city}',
            subtitle: 'Independent financial reviews, internal control audits, GST risk assessments, and SOX compliance by senior Chartered Accountants.',
            badgeText: 'ICAI CERTIFIED CA PRACTICE',
            consultationPrice: 499
        },
        stats: [
            { value: '100%', label: 'STATUTORY AUDIT READY' },
            { value: 'ICAI', label: 'STANDARDS COMPLIANT' },
            { value: 'Zero', label: 'LEGAL EXPOSURE' },
            { value: '4.9/5', label: 'AUDIT RATING' }
        ],
        packages: [
            { id: 'internal-audit-plan', name: 'Internal Process & Risk Audit', price: 9999, description: 'Review of operational internal controls and revenue leakage.', features: ['Internal Financial Controls (IFC) Review', 'Revenue & Expense Leakage Audit', 'Procurement & Inventory Check', 'Management Letter with Action Plan'], creativeButtonText: 'Book Internal Audit' },
            { id: 'gst-tax-audit', name: 'GST & Tax Audit Support', price: 14999, isPopular: true, description: 'Section 44AB Tax Audit and GSTR-9C reconciliation statement.', features: ['Income Tax Section 44AB Audit Support', 'GSTR-9C Reconciliation Statement', 'ITC Verification & Risk Profiling', 'Drafting Form 3CD & 3CA/CB Annexures', 'Senior Partner Review'], creativeButtonText: 'Select Tax Audit Plan' }
        ]
    },
    '12aa-80g-certificates': {
        pageId: '12aa-80g-certificates',
        title: '12A & 80G Tax Exemption Certificates for NGOs & Trusts',
        description: 'Obtain 100% tax exemption on trust income under Section 12A/12AB and enable 50% tax deduction for donors under Section 80G.',
        iconKey: 'Gift',
        hero: {
            title: '12A & 80G Tax Exemption Registration in {city}',
            subtitle: 'Obtain 100% tax exemption on trust income under Section 12A/12AB and enable 50% tax deduction for your donors under Section 80G.',
            badgeText: 'INCOME TAX DEPT VERIFIED',
            consultationPrice: 499
        },
        stats: [
            { value: '100%', label: 'TAX EXEMPT INCOME' },
            { value: '50%', label: 'DONOR TAX REBATE' },
            { value: 'CSR & FCRA', label: 'ELIGIBILITY' },
            { value: '4.9/5', label: 'NGO RATING' }
        ],
        packages: [
            { id: '12a-provisional', name: 'Provisional 12A & 80G (New NGOs)', price: 6999, isPopular: true, description: 'Fast-track Form 10A provisional registration valid for 3 years.', features: ['Form 10A Drafting & Online Filing', 'Provisional 12A Certificate (3 Yrs)', 'Provisional 80G Certificate (3 Yrs)', 'Unique Registration Number (URN) Issuance', 'Basic DARPAN Registration'], creativeButtonText: 'Get Provisional 12A/80G' },
            { id: '12a-regular', name: 'Regular 12AB & 80G (5-Year Final)', price: 11999, description: 'Form 10AB application for permanent 5-year registration.', features: ['Form 10AB Drafting & Verification', 'Activity Report & Donation Ledgers Preparation', 'CIT (Exemptions) Query Handling', 'Final 5-Year 12AB & 80G Approval', 'CSR-1 Registration Included'], creativeButtonText: 'Select Final 12AB/80G' }
        ]
    },
    'iso-9001-certification': {
        pageId: 'iso-9001-certification',
        title: 'ISO 9001:2015 Quality Management System Certification',
        description: 'IAF & Non-IAF accredited Quality Management System certification with full documentation kits and audit support.',
        iconKey: 'Award',
        hero: {
            title: 'ISO 9001:2015 Certification in {city}',
            subtitle: 'Globally recognized IAF & Non-IAF accredited Quality Management System (QMS) certification with full audit support and documentation kits.',
            badgeText: 'IAF & NABCB ACCREDITED',
            consultationPrice: 499
        },
        stats: [
            { value: '5-7 Days', label: 'CERTIFICATION TIME' },
            { value: 'IAF / Non-IAF', label: 'ACCREDITATION' },
            { value: '3 Years', label: 'VALIDITY' },
            { value: '4.9/5', label: 'CLIENT RATING' }
        ],
        packages: [
            { id: 'iso-non-iaf', name: 'ISO 9001 (Non-IAF / Fast Track)', price: 3499, description: 'Ideal for basic tenders and internal quality benchmarking.', features: ['ISO 9001:2015 QMS Certificate', '3-Year Certificate Validity', 'Fast Track 3-5 Days Issuance', 'Digital Certificate + QR Verification', 'Basic Quality Manual Template'], creativeButtonText: 'Select Non-IAF Plan' },
            { id: 'iso-iaf-accredited', name: 'ISO 9001 (IAF Accredited)', price: 6499, isPopular: true, description: 'International Accreditation Forum (IAF) stamp for govt tenders & exports.', features: ['IAF Recognized Certificate', 'Global Tender & Export Compliance', 'Complete QMS Manual & SOPs', 'Internal Audit Documentation', 'Official Registrar Portal Listing'], creativeButtonText: 'Select IAF Accredited' }
        ]
    },
    'iso-14001-certification': {
        pageId: 'iso-14001-certification',
        title: 'ISO 14001:2015 Environmental Management System (EMS)',
        description: 'Demonstrate environmental responsibility and meet statutory ESG compliance with IAF accredited EMS certification.',
        iconKey: 'Leaf',
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
            { id: 'iso-14001-standard', name: 'ISO 14001 (EMS Standard)', price: 5499, isPopular: true, description: 'Full Environmental Management System certification with aspect-impact register.', features: ['ISO 14001:2015 EMS Certificate', 'Aspect-Impact Assessment Register', 'Environmental Policy Drafting', '3-Year Certificate Validity', 'Audit Documentation Kit'], creativeButtonText: 'Select ISO 14001' }
        ]
    },
    'iso-45001-certification': {
        pageId: 'iso-45001-certification',
        title: 'ISO 45001:2018 Occupational Health & Safety (OH&SMS)',
        description: 'Workplace safety and hazard management certification for manufacturing and construction contracts.',
        iconKey: 'ShieldCheck',
        hero: {
            title: 'ISO 45001:2018 Certification in {city}',
            subtitle: 'Ensure maximum workplace safety, reduce occupational injuries, and qualify for high-value industrial and construction contracts.',
            badgeText: 'WORKPLACE SAFETY STANDARD',
            consultationPrice: 499
        },
        stats: [
            { value: '5-7 Days', label: 'TURNAROUND' },
            { value: 'Zero', label: 'SAFETY RISK' },
            { value: '3 Years', label: 'VALIDITY' },
            { value: '4.9/5', label: 'RATING' }
        ],
        packages: [
            { id: 'iso-45001-standard', name: 'ISO 45001 (OH&S Standard)', price: 5999, isPopular: true, description: 'Complete OH&S certification with Hazard Identification & Risk Assessment (HIRA).', features: ['ISO 45001:2018 Certificate', 'HIRA Risk Assessment Template', 'Safety Manual & Emergency SOPs', '3-Year Certificate Validity', 'Lead Auditor Audit Verification'], creativeButtonText: 'Select ISO 45001' }
        ]
    },
    'iso-22000-certification': {
        pageId: 'iso-22000-certification',
        title: 'ISO 22000:2018 Food Safety Management System (FSMS)',
        description: 'International food safety standards across food processing, packaging, and supply chain.',
        iconKey: 'CheckCircle',
        hero: {
            title: 'ISO 22000:2018 FSMS Certification in {city}',
            subtitle: 'Ensure international food safety standards across your processing, packaging, cold storage, and export food supply chain.',
            badgeText: 'FOOD SAFETY & HACCP ALIGNED',
            consultationPrice: 499
        },
        stats: [
            { value: '5-7 Days', label: 'TURNAROUND' },
            { value: 'HACCP', label: 'INTEGRATED' },
            { value: 'FSSAI & Global', label: 'RECOGNITION' },
            { value: '4.9/5', label: 'CLIENT RATING' }
        ],
        packages: [
            { id: 'iso-22000-standard', name: 'ISO 22000 FSMS Certification', price: 6999, isPopular: true, description: 'Complete FSMS certification incorporating HACCP principles and traceability.', features: ['ISO 22000:2018 FSMS Certificate', 'HACCP Plan & Critical Control Points (CCP)', 'Food Safety Manual & Hygiene SOPs', 'Supplier & Raw Material Traceability Guidelines', '3-Year Certificate Validity'], creativeButtonText: 'Select ISO 22000' }
        ]
    },
    'iso-27001-certification': {
        pageId: 'iso-27001-certification',
        title: 'ISO/IEC 27001:2022 Information Security Management (ISMS)',
        description: 'Protect confidential data, safeguard intellectual property, and satisfy enterprise IT client security risk assessments.',
        iconKey: 'Lock',
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
            { id: 'iso-27001-standard', name: 'ISO 27001:2022 ISMS Certification', price: 8999, isPopular: true, description: 'Complete Information Security Management System mapped to 2022 Annex A controls.', features: ['ISO/IEC 27001:2022 Certificate', 'Statement of Applicability (SoA) Matrix', 'Information Security Policy & SOPs', 'Vulnerability & Risk Assessment Register', '3-Year Validity with Online Portal Entry'], creativeButtonText: 'Select ISO 27001' }
        ]
    },
    'gmp-haccp-certification': {
        pageId: 'gmp-haccp-certification',
        title: 'GMP & HACCP Certification Services',
        description: 'Good Manufacturing Practice and Hazard Analysis Critical Control Point certification for Pharma, Food, and Ayush.',
        iconKey: 'Award',
        hero: {
            title: 'GMP & HACCP Certification in {city}',
            subtitle: 'Good Manufacturing Practice (GMP) and Hazard Analysis Critical Control Point (HACCP) certification for Pharma, Food, Cosmetics & Ayush units.',
            badgeText: 'WHO-GMP & CODEX ALIMENTARIUS COMPLIANT',
            consultationPrice: 499
        },
        stats: [
            { value: '5-7 Days', label: 'CERTIFICATION TIME' },
            { value: 'WHO-GMP', label: 'PHARMA & FOOD READY' },
            { value: '100%', label: 'AUDIT SUCCESS' },
            { value: '4.9/5', label: 'RATING' }
        ],
        packages: [
            { id: 'gmp-certificate', name: 'GMP Certification Plan', price: 6499, isPopular: true, description: 'Complete Good Manufacturing Practices audit and certificate issuance.', features: ['GMP Certificate (3 Yrs)', 'Factory Hygiene & Cleanroom Review', 'Sanitation & Equipment Validation SOPs', 'Batch Record Keeping Templates', 'Audit Compliance Report'], creativeButtonText: 'Select GMP Plan' }
        ]
    },
    'ce-marking-certification': {
        pageId: 'ce-marking-certification',
        title: 'CE Marking Certification for European Export Compliance',
        description: 'Technical Construction File (TCF) preparation, Declaration of Conformity (DoC), and CE Marking for European Union exports.',
        iconKey: 'Globe',
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
            { id: 'ce-marking-plan', name: 'CE Marking Certification Plan', price: 12499, isPopular: true, description: 'End-to-end CE Marking conformity for Machinery, Electronics (EMC/LVD) & Medical Devices.', features: ['EU Directives Identification', 'Technical Construction File (TCF) Drafting', 'Declaration of Conformity (DoC)', 'CE Marking Certificate & Label Guidelines', 'Lab Test Report Coordination'], creativeButtonText: 'Select CE Marking Plan' }
        ]
    },
    'isi-bis-certification': {
        pageId: 'isi-bis-certification',
        title: 'ISI Mark & BIS Registration Services',
        description: 'Obtain ISI Mark (Scheme I) and BIS CRS Registration (Scheme II) for electronics, chemicals, steel, and consumer goods.',
        iconKey: 'CheckCircle',
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
            { id: 'bis-crs-registration', name: 'BIS CRS Registration (Scheme II)', price: 14999, isPopular: true, description: 'Compulsory Registration Scheme (CRS) for IT goods, batteries, and solar panels.', features: ['BIS Portal Profile & Application Filing', 'BIS Approved Lab Test Coordination', 'Query Handling with Technical Officers', 'BIS Registration Grant Letter', 'Validity & Renewal Guidance'], creativeButtonText: 'Select BIS CRS Plan' }
        ]
    },
    'halal-kosher-certification': {
        pageId: 'halal-kosher-certification',
        title: 'Halal & Kosher Certification Services',
        description: 'Accredited Halal and Kosher certification for food processing, pharmaceuticals, cosmetics, and agricultural exports.',
        iconKey: 'Award',
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
            { id: 'halal-certification-plan', name: 'Halal Certification Plan', price: 7999, isPopular: true, description: 'Accredited Halal certification for domestic food businesses and Middle East export.', features: ['Halal Compliance Audit', 'Raw Material & Ingredient Verification', 'Halal Slaughter / Processing Review', 'Certificate Issuance with QR Code', 'Annual Renewal Support'], creativeButtonText: 'Select Halal Plan' }
        ]
    },
    'udyam-registration': {
        pageId: 'udyam-registration',
        title: 'Udyam Registration (MSME Certificate) Online',
        description: 'Instant Udyam MSME Registration Certificate in 24 hours. Unlock collateral-free bank loans and electricity subsidies.',
        iconKey: 'Zap',
        hero: {
            title: 'Instant Udyam MSME Registration in {city}',
            subtitle: 'Obtain your official Ministry of MSME Udyam Registration Certificate in 24 hours. Unlock collateral-free bank loans, electricity subsidies, and priority tenders.',
            badgeText: 'MINISTRY OF MSME GOVT VERIFIED',
            consultationPrice: 499
        },
        stats: [
            { value: '24 Hours', label: 'CERTIFICATE ISSUED' },
            { value: '100%', label: 'GOVT SUBSIDY READY' },
            { value: 'Lifetime', label: 'VALIDITY' },
            { value: '4.9/5', label: 'MSME RATING' }
        ],
        packages: [
            { id: 'udyam-instant', name: 'Udyam Certificate Plan', price: 999, isPopular: true, description: 'Complete online application, NIC code classification, and instant certificate.', features: ['Official Udyam Registration Certificate', 'NIC 5-Digit Business Activity Classification', 'Priority Sector Bank Lending Benefits', 'MSME Samadhaan Delayed Payment Protection', 'Lifetime Validity with Digital QR Code'], creativeButtonText: 'Get Udyam Certificate' }
        ]
    },
    'shops-establishment-license': {
        pageId: 'shops-establishment-license',
        title: 'Shops & Establishment Act Registration (Gumasta)',
        description: 'Mandatory state labour department registration for commercial offices, retail shops, IT firms, and restaurants.',
        iconKey: 'Building2',
        hero: {
            title: 'Shops & Establishment Registration in {city}',
            subtitle: 'Mandatory state labour department registration for commercial offices, retail shops, IT firms, restaurants, and warehouses.',
            badgeText: 'STATE LABOUR DEPARTMENT VERIFIED',
            consultationPrice: 499
        },
        stats: [
            { value: '2-3 Days', label: 'CERTIFICATE TIME' },
            { value: '100%', label: 'LEGAL COMMERCE' },
            { value: 'Bank A/c', label: 'MANDATORY PROOF' },
            { value: '4.9/5', label: 'CLIENT RATING' }
        ],
        packages: [
            { id: 'shops-establishment-plan', name: 'Shops & Establishment Certificate', price: 1499, isPopular: true, description: 'Complete registration application, address proof verification, and certificate delivery.', features: ['Official State Labour Dept Certificate', 'Current Bank Account Opening Proof', 'Working Hours & Holiday Compliance Setup', 'Employee Register Formats Provided', 'Annual Renewal Reminder'], creativeButtonText: 'Register Shop / Office' }
        ]
    },
    'import-export-code': {
        pageId: 'import-export-code',
        title: 'Import Export Code (IEC) Online Registration',
        description: 'Obtain your 10-digit DGFT Import Export Code with lifetime validity in 24 hours. Clear customs and initiate global trade.',
        iconKey: 'Globe',
        hero: {
            title: 'Import Export Code (IEC Code) Online in {city}',
            subtitle: 'Obtain your 10-digit DGFT Import Export Code with lifetime validity in 24 hours. Clear customs and initiate international cross-border trade.',
            badgeText: 'DGFT MINISTRY OF COMMERCE VERIFIED',
            consultationPrice: 499
        },
        stats: [
            { value: '24 Hours', label: 'IEC ISSUED' },
            { value: 'Lifetime', label: 'VALIDITY' },
            { value: 'Zero', label: 'EXPORT RESTRICTIONS' },
            { value: '4.9/5', label: 'EXPORTER RATING' }
        ],
        packages: [
            { id: 'iec-registration-plan', name: 'IEC Code Registration Plan', price: 2199, isPopular: true, description: 'Complete DGFT online portal registration, DSC linking, and IEC certificate issuance.', features: ['Official DGFT 10-Digit IEC Certificate', 'Customs ICEGATE Integration Guidance', 'RCMC Council Advisory', 'Authorized Dealer (AD) Code Registration Support', 'Annual DGFT IEC Update Guidance'], creativeButtonText: 'Get IEC Code' }
        ]
    },
    'startup-india-registration': {
        pageId: 'startup-india-registration',
        title: 'Startup India DPIIT Recognition & Tax Exemption (Section 80-IAC)',
        description: 'DPIIT Recognition Certificate, 3-year 100% income tax exemption (Section 80-IAC), and Angel Tax exemption.',
        iconKey: 'Zap',
        hero: {
            title: 'Startup India DPIIT Recognition in {city}',
            subtitle: 'Obtain DPIIT Recognition Certificate, unlock 3 consecutive years 100% income tax exemption (Section 80-IAC), and Angel Tax exemption under Section 56(2)(viib).',
            badgeText: 'DPIIT MINISTRY OF COMMERCE VERIFIED',
            consultationPrice: 499
        },
        stats: [
            { value: '3 Years', label: '100% TAX HOLIDAY (80-IAC)' },
            { value: 'Angel Tax', label: 'EXEMPTION' },
            { value: '80% Off', label: 'PATENT & IP REBATES' },
            { value: '4.9/5', label: 'STARTUP RATING' }
        ],
        packages: [
            { id: 'dpiit-recognition-only', name: 'DPIIT Recognition Certificate Plan', price: 3499, isPopular: true, description: 'Official DPIIT startup certificate, pitch deck summary, and priority govt tender access.', features: ['Official DPIIT Recognition Certificate', 'Startup India Portal Profile Setup', '80% Rebate on Patent / 50% on Trademark', 'Relaxed Norms in Govt Public Procurement (No EMD/Turnover Requirement)', 'Self-Certification under 6 Labour & 3 Environmental Laws'], creativeButtonText: 'Get DPIIT Recognition' }
        ]
    },
    'fssai-license': {
        pageId: 'fssai-license',
        title: 'FSSAI Food License & Registration (Basic, State & Central)',
        description: 'Obtain 14-digit FSSAI Registration, State License, or Central License on FoSCoS portal for restaurants, kitchens, and food brands.',
        iconKey: 'Award',
        hero: {
            title: 'FSSAI Food Safety License Online in {city}',
            subtitle: 'Obtain 14-digit FSSAI Registration, State License, or Central License on FoSCoS portal for restaurants, cloud kitchens, manufacturers, and food traders.',
            badgeText: 'FSSAI & FOSCOS GOVT AUTHORIZED',
            consultationPrice: 499
        },
        stats: [
            { value: '3-5 Days', label: 'TURNAROUND' },
            { value: '14-Digit', label: 'FSSAI LICENSE NO.' },
            { value: '1 to 5 Yrs', label: 'VALIDITY OPTIONS' },
            { value: '4.9/5', label: 'FOOD RATING' }
        ],
        packages: [
            { id: 'fssai-basic', name: 'FSSAI Basic Registration', price: 1999, isPopular: true, description: 'For small food businesses and kitchens with turnover up to ₹12 Lakhs/year.', features: ['14-Digit FSSAI Registration Certificate', 'FoSCoS Portal Filing & Tracking', 'Food Category Selection Support', 'Swiggy / Zomato Onboarding Proof', '1-Year License Validity'], creativeButtonText: 'Select Basic FSSAI' }
        ]
    },
    'trade-license': {
        pageId: 'trade-license',
        title: 'Municipal Trade License Online Registration',
        description: 'Mandatory municipal corporation trade license and health trade certificates for commercial or industrial operations.',
        iconKey: 'Building2',
        hero: {
            title: 'Municipal Trade License Registration in {city}',
            subtitle: 'Obtain mandatory municipal corporation trade licenses and health trade certificates to legally operate commercial, retail, or industrial businesses.',
            badgeText: 'MUNICIPAL CORPORATION CERTIFIED',
            consultationPrice: 499
        },
        stats: [
            { value: '3-5 Days', label: 'TURNAROUND' },
            { value: '100%', label: 'MUNICIPAL COMPLIANT' },
            { value: 'Annual / Multi-Yr', label: 'VALIDITY' },
            { value: '4.9/5', label: 'RATING' }
        ],
        packages: [
            { id: 'trade-license-plan', name: 'Trade License Registration Plan', price: 2499, isPopular: true, description: 'Municipal trade license application, zone clearance, and official trade certificate delivery.', features: ['Municipal Corporation Application Filing', 'Health & Hygiene Verification Support', 'Zone / Ward Mapping', 'Trade License Certificate Issuance', 'Annual Renewal Notification'], creativeButtonText: 'Apply for Trade License' }
        ]
    },
    'labour-license': {
        pageId: 'labour-license',
        title: 'Contract Labour License & Registration (CLRA Act)',
        description: 'Principal Employer Registration (Form I) and Contractor Labour License (Form IV) under the CLRA Act.',
        iconKey: 'Users',
        hero: {
            title: 'Contract Labour License (CLRA) in {city}',
            subtitle: 'Principal Employer Registration (Form I) and Contractor Labour License (Form IV) under the Contract Labour (Regulation & Abolition) Act.',
            badgeText: 'STATE LABOUR COMMISSIONER APPROVED',
            consultationPrice: 499
        },
        stats: [
            { value: '5-7 Days', label: 'TURNAROUND' },
            { value: 'Form I & IV', label: 'SCHEMES COVERED' },
            { value: '100%', label: 'STATUTORY COMPLIANT' },
            { value: '4.9/5', label: 'RATING' }
        ],
        packages: [
            { id: 'contractor-labour-license', name: 'Contractor Labour License Plan', price: 5499, isPopular: true, description: 'For contractors employing 20 or more contract workers on site.', features: ['Form IV License Application', 'Form V Principal Employer Certificate Validation', 'Security Deposit Calculation Guidance', 'Mandatory Labour Registers Formats', 'Labour Commissioner Query Handling'], creativeButtonText: 'Get Labour License' }
        ]
    },
    'pollution-noc': {
        pageId: 'pollution-noc',
        title: 'State Pollution Control Board NOC (CTE & CTO Certification)',
        description: 'Consent to Establish (CTE) and Consent to Operate (CTO) from State Pollution Control Boards (SPCB).',
        iconKey: 'ShieldCheck',
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
            { id: 'spcb-green-white-noc', name: 'Pollution NOC (White & Green Category)', price: 9999, isPopular: true, description: 'Consent application for low-pollution, IT, assembly, and green category units.', features: ['Pollution Category Mapping (CPCB Norms)', 'CTE / CTO Online Application Filing', 'Effluent & Emission Declaration Drafting', 'SPCB Regional Office Liaison', 'Official Consent Certificate Issuance'], creativeButtonText: 'Apply for Green/White NOC' }
        ]
    },
    'roc-annual-filings': {
        pageId: 'roc-annual-filings',
        title: 'ROC Annual Compliance & Filings (AOC-4, MGT-7, Form 11, Form 8)',
        description: 'Mandatory MCA annual filings: Form AOC-4 (Financials), MGT-7A (Annual Return), and Form 11/8 for LLPs.',
        iconKey: 'FileText',
        hero: {
            title: 'ROC Annual Compliance Filings in {city}',
            subtitle: 'Mandatory Ministry of Corporate Affairs (MCA) annual filings: Form AOC-4 (Financials), MGT-7A (Annual Return), and Form 11/8 for LLPs.',
            badgeText: 'MCA21 V3 CERTIFIED CS & CA FILING',
            consultationPrice: 499
        },
        stats: [
            { value: '100%', label: 'MCA V3 COMPLIANT' },
            { value: 'Zero', label: 'DIRECTOR DISQUALIFICATION' },
            { value: 'CA/CS', label: 'CERTIFIED REVIEW' },
            { value: '4.9/5', label: 'CORPORATE RATING' }
        ],
        packages: [
            { id: 'roc-small-company', name: 'Small Pvt Ltd Annual Compliance', price: 6999, isPopular: true, description: 'Complete annual filing package for Private Limited Companies including AOC-4, MGT-7A, and Director KYC.', features: ['Form AOC-4 (Financial Statements Filing)', 'Form MGT-7A (Annual Return Filing)', 'DIR-3 KYC for 2 Directors', 'Drafting Board Resolutions & AGM Minutes', 'Statutory Register Maintenance Formats'], creativeButtonText: 'Select Small Company Plan' }
        ]
    },
    'director-kyc': {
        pageId: 'director-kyc',
        title: 'DIR-3 KYC Online Filing (Web-based & eForm DIR-3 KYC)',
        description: 'Annual mandatory Director KYC filing on MCA portal to keep your DIN active and avoid ₹5,000 late penalties.',
        iconKey: 'Users',
        hero: {
            title: 'Director KYC (DIR-3 KYC) Online in {city}',
            subtitle: 'Annual mandatory Director KYC filing on MCA portal to keep your Director Identification Number (DIN) active and avoid ₹5,000 late penalties.',
            badgeText: 'MCA21 V3 APPROVED FILING',
            consultationPrice: 499
        },
        stats: [
            { value: '10 Mins', label: 'OTP FILING TIME' },
            { value: 'Active', label: 'DIN STATUS' },
            { value: 'Zero', label: 'MCA LATE FEE' },
            { value: '4.9/5', label: 'RATING' }
        ],
        packages: [
            { id: 'dir3-kyc-web', name: 'DIR-3 KYC Web (OTP Based)', price: 499, isPopular: true, description: 'For directors with unchanged mobile number and email.', features: ['MCA V3 Portal Access & Verification', 'Aadhaar & Mobile OTP Authentication', 'Instant SRN Challan Generation', 'DIN Status Confirmation as Approved'], creativeButtonText: 'File Web KYC' }
        ]
    },
    'dsc-registration': {
        pageId: 'dsc-registration',
        title: 'Class 3 Digital Signature Certificate (DSC) Online with USB Token',
        description: 'Class 3 Signing & Encryption Digital Signature Certificates with FIPS certified USB crypto token.',
        iconKey: 'Lock',
        hero: {
            title: 'Class 3 Digital Signature (DSC) in {city}',
            subtitle: 'Paperless online issuance of Class 3 Signing & Encryption Digital Signature Certificates with FIPS certified USB crypto token (ePass 2003 / ProxKey).',
            badgeText: 'CCA GOVT OF INDIA APPROVED',
            consultationPrice: 499
        },
        stats: [
            { value: '15 Mins', label: 'VIDEO VERIFICATION TIME' },
            { value: '2 or 3 Yrs', label: 'VALIDITY' },
            { value: 'FIPS 140-2', label: 'USB CRYPTO TOKEN' },
            { value: '4.9/5', label: 'RATING' }
        ],
        packages: [
            { id: 'dsc-individual-2yr', name: 'Class 3 Individual DSC (2 Years + Token)', price: 1499, isPopular: true, description: 'Signing certificate for MCA, Income Tax, GST, PF, Trademark & ICEGATE.', features: ['Class 3 Signing Certificate', '2-Year Certificate Validity', 'Free FIPS Certified USB Token', '10-Minute Paperless Video KYC', 'Doorstep Courier Delivery of Token'], creativeButtonText: 'Get Individual DSC' }
        ]
    },
    'gem-registration': {
        pageId: 'gem-registration',
        title: 'GeM Portal Seller Registration, OEM Panel & Tender Management',
        description: 'Sell your goods and services directly to Government Ministries, PSUs, and Defence departments on Government e-Marketplace (GeM).',
        iconKey: 'Globe',
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
            { id: 'gem-seller-basic', name: 'GeM Primary Seller Account', price: 2999, description: 'Primary seller account registration, Aadhaar/PAN linking, and Caution Money setup.', features: ['Primary Seller Profile Creation', 'Bank PFMS Validation & Caution Money Setup', 'GeM Organization Category Mapping', 'MSME / Startup India Exemption Tagging', 'Account Verification Handholding'], creativeButtonText: 'Register as GeM Seller' }
        ]
    },
    'treds-registration': {
        pageId: 'treds-registration',
        title: 'TReDS Platform Registration (RXIL, M1xchange, Invoicemart)',
        description: 'Discount unpaid corporate & PSU trade invoices in 48 hours without collateral on RBI regulated TReDS platforms.',
        iconKey: 'Zap',
        hero: {
            title: 'TReDS Invoice Discounting Registration in {city}',
            subtitle: 'Get your MSME registered on RBI regulated TReDS platforms (RXIL, M1xchange, Invoicemart) to get unpaid corporate & PSU trade invoices discounted in 48 hours.',
            badgeText: 'RBI AUTHORIZED TREDS PLATFORM INTEGRATION',
            consultationPrice: 499
        },
        stats: [
            { value: '48 Hours', label: 'INVOICE DISCOUNTING' },
            { value: 'Without', label: 'COLLATERAL SECURITY' },
            { value: 'Lowest', label: 'BANK BIDDING RATES' },
            { value: '4.9/5', label: 'MSME RATING' }
        ],
        packages: [
            { id: 'treds-onboarding-plan', name: 'TReDS Multi-Platform Onboarding', price: 3499, isPopular: true, description: 'Complete registration on RBI authorized TReDS platforms with escrow setup.', features: ['Registration on RXIL / M1xchange / Invoicemart', 'Udyam & Corporate Master Linking', 'NACH Mandate & Escrow Setup', 'Digital Signature Linking', 'First Invoice Factoring Handholding'], creativeButtonText: 'Register on TReDS' }
        ]
    },
    'rera-registration': {
        pageId: 'rera-registration',
        title: 'RERA Agent & Real Estate Project Registration',
        description: 'Mandatory RERA registration for real estate brokers, channel partners, and project builders.',
        iconKey: 'Building2',
        hero: {
            title: 'RERA Registration for Agents & Projects in {city}',
            subtitle: 'Mandatory Real Estate Regulatory Authority (RERA) registration for real estate brokers, agents, builders, layout developers, and apartment projects.',
            badgeText: 'STATE RERA AUTHORITY VERIFIED',
            consultationPrice: 499
        },
        stats: [
            { value: '5-7 Days', label: 'TURNAROUND' },
            { value: '5 Years', label: 'AGENT LICENSE VALIDITY' },
            { value: '100%', label: 'LEGAL BROKERAGE' },
            { value: '4.9/5', label: 'REALTY RATING' }
        ],
        packages: [
            { id: 'rera-agent-individual', name: 'RERA Real Estate Agent License', price: 3999, isPopular: true, description: 'For individual real estate brokers and channel partners.', features: ['State RERA Portal Profile Creation', 'RERA Agent License Number Issuance', '5-Year Certificate Validity', 'RERA Compliant Agreement Templates', 'Brokerage Legal Protection Guidelines'], creativeButtonText: 'Get RERA Agent License' }
        ]
    },
    'dpr-cma-preparation': {
        pageId: 'dpr-cma-preparation',
        title: 'Detailed Project Report (DPR) & CMA Data Preparation for Bank Loans',
        description: 'Professional Detailed Project Reports (DPR), CMA Data, and Term Loan/Cash Credit proposals by senior Chartered Accountants.',
        iconKey: 'TrendingUp',
        hero: {
            title: 'Bank Loan DPR & CMA Data Preparation in {city}',
            subtitle: 'Professional Detailed Project Reports (DPR), Credit Monitoring Arrangement (CMA) Data, and Term Loan/Cash Credit (CC/OD) proposals prepared by senior Chartered Accountants.',
            badgeText: 'BANK CREDIT UNDERWRITING STANDARDS',
            consultationPrice: 499
        },
        stats: [
            { value: '3-5 Days', label: 'PREPARATION TIME' },
            { value: '95%+', label: 'LOAN SANCTION RATE' },
            { value: '7-10 Yrs', label: 'FINANCIAL PROJECTIONS' },
            { value: '4.9/5', label: 'FOUNDER RATING' }
        ],
        packages: [
            { id: 'cma-data-working-capital', name: 'CMA Data Plan (CC / OD Limits)', price: 4999, isPopular: true, description: '7-statement CMA data model required by banks for Working Capital limits.', features: ['7 Standard Banking CMA Statements', 'Holding Period & Operating Cycle Modeling', 'MPBF Calculations', 'Ratio Analysis (DSCR, Current Ratio)', 'CA Certified CMA Data File'], creativeButtonText: 'Select CMA Data Plan' }
        ]
    },
    'msme-subsidies-loans': {
        pageId: 'msme-subsidies-loans',
        title: 'Government Subsidies & MSME Loan Schemes (PMEGP, CGTMSE, Mudra, PMFME)',
        description: 'Unlock 15% to 35% capital subsidies, collateral-free credit guarantees up to ₹5 Crores under CGTMSE and PMEGP.',
        iconKey: 'Gift',
        hero: {
            title: 'Government MSME Subsidies & Loan Schemes in {city}',
            subtitle: 'Unlock 15% to 35% capital subsidies, collateral-free credit guarantees up to ₹5 Crores under CGTMSE, PMEGP, PMFME, and state industrial subsidy schemes.',
            badgeText: 'MINISTRY OF MSME & STATE INDUSTRIAL INCENTIVES',
            consultationPrice: 499
        },
        stats: [
            { value: '15% to 35%', label: 'GOVT CAPITAL SUBSIDY' },
            { value: 'Up to ₹5 Cr', label: 'COLLATERAL-FREE CGTMSE' },
            { value: '100%', label: 'SCHEME APPLICATION ASSISTANCE' },
            { value: '4.9/5', label: 'RATING' }
        ],
        packages: [
            { id: 'pmegp-loan-package', name: 'PMEGP Subsidy Loan Application', price: 6999, isPopular: true, description: 'Complete PMEGP portal application with project report for 15-35% subsidy.', features: ['PMEGP Online Application Filing', 'KVIC / DIC Bank Liaison Project Report', 'Margin Money Subsidy Claim Assistance', 'EDP Training Coordination', 'Bank Branch Sanction Follow-up'], creativeButtonText: 'Apply for PMEGP Subsidy' }
        ]
    },
    'trademark-registration': {
        pageId: 'trademark-registration',
        title: 'Trademark Registration & Brand Name Protection (TM & ®)',
        description: 'Protect your brand name, logo, slogan, and packaging under the Trademarks Act, 1999 with certified Trademark Attorney filing.',
        iconKey: 'ShieldCheck',
        hero: {
            title: 'Online Trademark Registration (TM) in {city}',
            subtitle: 'Protect your brand name, logo, slogan, and packaging under the Trademarks Act, 1999. Use ™ instantly in 24 hours with certified Trademark Attorney filing.',
            badgeText: 'CONTROLLER GENERAL OF PATENTS, DESIGNS & TRADEMARKS APPROVED',
            consultationPrice: 499
        },
        stats: [
            { value: '24 Hours', label: 'USE ™ SYMBOL' },
            { value: '10 Years', label: 'PROTECTION PERIOD' },
            { value: '100%', label: 'LEGAL BRAND OWNERSHIP' },
            { value: '4.9/5', label: 'IP RATING' }
        ],
        packages: [
            { id: 'trademark-filing-plan', name: 'Trademark Registration Plan (Per Class)', price: 1999, isPopular: true, description: 'Comprehensive trademark search, class classification, and instant filing.', features: ['Deep Trademark Search Report', 'Form TM-A Drafting by Trademark Attorney', 'Instant Application Number & Right to use ™', 'Class Classification (1 to 45 Classes)', 'Hearing & Examination Report Alert System'], creativeButtonText: 'Protect Brand Name' }
        ]
    },
    'machinery-sourcing': {
        pageId: 'machinery-sourcing',
        title: 'Turnkey Machinery Sourcing, Industrial Setup & Plant Engineering',
        description: 'End-to-end industrial plant engineering: Domestic & global machinery procurement, factory layout, and trial batch production.',
        iconKey: 'Settings',
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
            { id: 'machinery-vendor-selection', name: 'Machinery Vendor Sourcing & Evaluation', price: 9999, isPopular: true, description: 'Vendor identification, competitive techno-commercial bidding, and machinery inspection.', features: ['Domestic & Global OEM Vendor Shortlisting', 'Technical Specifications & Capacity Matching', 'Price Negotiation & Payment Escrow Terms', 'Customs Duty & Freight Logistics Advisory', 'Factory Acceptance Test (FAT) Checklist'], creativeButtonText: 'Source Industrial Machinery' }
        ]
    }
};
