// Header Version: 1.5 - Logo + Menu Merge + Dropdown Fix
import React, { useState, useEffect, useRef } from 'react';
import {
    Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
    Phone, Menu, X, ChevronDown, Clock, Award, Search,
    Mail, User as UsersIcon, CheckCircle, LogIn, ArrowUp, List, MessageSquare
} from 'lucide-react';

/* --- MENU DATA WITH LINKS --- */
export const getServiceLink = (serviceName) => {
    const raw = String(serviceName || '').trim();
    const normalized = raw.toLowerCase();
    
    // Core Specific Overrides
    if (normalized.includes('public limited')) return '/public-limited-company';
    if (normalized.includes('private limited') || normalized.includes('pvt ltd')) return '/pvt-ltd-registration';
    if (normalized.includes('llp')) return '/llp-registration';
    if (normalized.includes('partnership')) return '/partnership-firm-registration';
    if (normalized.includes('proprietorship')) return '/proprietorship-setup';
    if (normalized.includes('section 8') || normalized.includes('ngo')) return '/section-8-company';
    if (normalized.includes('one person company') || normalized.includes('opc')) return '/one-person-company';
    if (normalized.includes('society') || normalized.includes('trust')) return '/society-trust-registration';
    if (normalized.includes('income tax return') || normalized === 'income tax') return '/income-tax-return';
    if (normalized.includes('compliance scheme 2026') || normalized.includes('ccfs')) return '/compliance-scheme-2026';
    if (normalized.includes('accounting-as-a-service') || normalized.includes('cloud accounting')) return '/cloud-accounting';
    if (normalized.includes('gst return')) return '/gst-return-filing';
    if (normalized.includes('gst registration')) return '/gst-registration';
    
    // ISO Standard Slugs
    if (normalized.includes('9001')) return '/iso-9001-certification';
    if (normalized.includes('14001')) return '/iso-14001-certification';
    if (normalized.includes('45001')) return '/iso-45001-certification';
    if (normalized.includes('22000')) return '/iso-22000-certification';
    if (normalized.includes('27001')) return '/iso-27001-certification';
    if (normalized.includes('50001')) return '/iso-50001-certification';
    if (normalized.includes('13485')) return '/iso-13485-certification';
    if (normalized.includes('20000')) return '/iso-20000-certification';
    if (normalized.includes('22301')) return '/iso-22301-certification';
    if (normalized.includes('gmp') || normalized.includes('haccp')) return '/gmp-haccp-certification';
    if (normalized.includes('ce marking') || normalized.includes('ce mark')) return '/ce-marking-certification';
    if (normalized.includes('isi') || normalized.includes('bis')) return '/isi-bis-certification';
    if (normalized.includes('fda')) return '/fda-compliance-support';
    if (normalized.includes('brcgs')) return '/brcgs-certification';
    if (normalized.includes('kosher')) return '/kosher-certification';
    if (normalized.includes('halal')) return '/halal-kosher-certification';

    // Mandatory Registrations & Licensing
    if (normalized.includes('udyam') || normalized.includes('msme registration')) return '/udyam-registration';
    if (normalized.includes('shops & establishment') || normalized.includes('gumasta')) return '/shops-establishment-license';
    if (normalized.includes('epfo') || normalized.includes('pf registration')) return '/epfo-pf-registration';
    if (normalized.includes('esic registration')) return '/esic-registration';
    if (normalized.includes('professional tax registration')) return '/professional-tax-registration';
    if (normalized.includes('professional tax') || normalized.includes('pt returns')) return '/professional-tax';
    if (normalized.includes('startup india')) return '/startup-india-registration';
    if (normalized.includes('import export') || normalized.includes('iec')) return '/import-export-code';
    if (normalized.includes('fssai')) return '/fssai-license';
    if (normalized.includes('lei')) return '/lei-certificate';
    if (normalized.includes('trade license')) return '/trade-license';
    if (normalized.includes('contract labour') || normalized.includes('labour license')) return '/labour-license';
    if (normalized.includes('pollution') || normalized.includes('noc') || normalized.includes('cfe') || normalized.includes('cfo')) return '/pollution-noc';
    if (normalized.includes('factory license')) return '/factory-license';
    if (normalized.includes('fcra')) return '/fcra-registration';
    if (normalized.includes('darpan')) return '/ngo-darpan-registration';

    // Corporate Compliances
    if (normalized.includes('roc annual') || normalized.includes('aoc-4') || normalized.includes('mgt-7')) return '/roc-annual-filings';
    if (normalized.includes('dir-3') || normalized.includes('director kyc')) return '/director-kyc';
    if (normalized.includes('search certificate')) return '/roc-search-certificate';
    if (normalized.includes('charge creation')) return '/roc-charge-creation';
    if (normalized.includes('change in shareholding')) return '/change-in-shareholding';
    if (normalized.includes('change in directorship')) return '/change-in-directorship';
    if (normalized.includes('merger') || normalized.includes('winding up')) return '/merger-demerger-winding-up';
    if (normalized.includes('buyback') || normalized.includes('bonus')) return '/bonus-loans-buyback';
    if (normalized.includes('share allotment')) return '/share-allotment-transfer';
    if (normalized.includes('share capital')) return '/increase-share-capital';
    if (normalized.includes('name, address') || normalized.includes('objective')) return '/company-name-address-change';
    if (normalized.includes('digital signature') || normalized.includes('dsc')) return '/dsc-registration';

    // Govt & MSME Portals
    if (normalized.includes('gem seller')) return '/gem-registration';
    if (normalized.includes('oem panel')) return '/gem-oem-panel';
    if (normalized.includes('brand approval')) return '/gem-brand-approval';
    if (normalized.includes('product listing')) return '/gem-product-listing';
    if (normalized.includes('tender management') || normalized.includes('bid participation')) return '/gem-tender-bidding';
    if (normalized.includes('treds')) return '/treds-registration';
    if (normalized.includes('rera')) return '/rera-registration';
    if (normalized.includes('single window')) return '/single-window-registration';
    if (normalized.includes('npci')) return '/npci-registration';
    if (normalized.includes('amazon') || normalized.includes('flipkart')) return '/ecommerce-seller-registration';
    if (normalized.includes('dpr preparation')) return '/dpr-cma-preparation';
    if (normalized.includes('cma data')) return '/cma-data-preparation';
    if (normalized.includes('bank loan')) return '/bank-loans-support';
    if (normalized.includes('cgtmse')) return '/cgtmse-loan-support';
    if (normalized.includes('pmegp')) return '/pmegp-loan-support';
    if (normalized.includes('mudra')) return '/mudra-loans-support';
    if (normalized.includes('stand-up') || normalized.includes('standup')) return '/standup-india-loans';
    if (normalized.includes('zed scheme') || normalized.includes('clcss')) return '/zed-scheme-support';
    if (normalized.includes('pmfme')) return '/pmfme-subsidy-scheme';
    if (normalized.includes('nsic')) return '/nsic-schemes-registration';
    if (normalized.includes('nabard')) return '/nabard-subsidy-schemes';
    if (normalized.includes('cold chain')) return '/cold-chain-subsidy';
    if (normalized.includes('subsidy schemes') || normalized.includes('subsidies')) return '/msme-subsidies-loans';

    // Branding & Industrial Setup
    if (normalized.includes('business plan')) return '/business-plan-preparation';
    if (normalized.includes('pitch deck')) return '/pitch-deck-preparation';
    if (normalized.includes('website & branding')) return '/website-branding-consulting';
    if (normalized.includes('vendor empanelment')) return '/vendor-empanelment-docs';
    if (normalized.includes('hr policy')) return '/hr-policy-documentation';
    if (normalized.includes('sop creation') || normalized === 'sop creation') return '/sop-creation-services';
    if (normalized.includes('loan file')) return '/loan-file-documentation';
    if (normalized.includes('insurance')) return '/commercial-business-insurance';
    if (normalized.includes('digital marketing')) return '/digital-marketing-support';
    if (normalized.includes('pan / tan') || normalized.includes('pan application')) return '/pan-tan-applications';
    if (normalized.includes('trademark') || normalized.includes('ip services')) return '/trademark-registration';
    if (normalized.includes('wealth portfolio')) return '/wealth-portfolio-management';
    if (normalized.includes('machinery sourcing')) return '/machinery-sourcing';
    if (normalized.includes('vendor identification') || normalized.includes('supplier verification')) return '/vendor-verification-services';
    if (normalized.includes('turnkey machinery')) return '/turnkey-plant-engineering';
    if (normalized.includes('technology upgradation')) return '/technology-upgradation-consulting';
    if (normalized.includes('feasibility analysis') || normalized.includes('industry selection')) return '/industrial-feasibility-analysis';

    // Clean fallback slug generator
    const slug = raw
        .toLowerCase()
        .replace(/\(.*?\)/g, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
    return `/${slug}`;
};

export const MENU_DATA = [
    {
        id: 'accounting-compliance-taxation',
        title: 'Accounting, Compliance & Taxation Services',
        iconKey: 'Calculator',
        icon: Calculator,
        columns: [
            {
                title: 'Accounting-as-a-Service (AaaS)',
                items: [
                    'Cloud Accounting (Tally Prime, Zoho Books, QuickBooks, Marg)',
                    'GST Return Filing',
                    'Payroll Management (Payslips, Leave, Form 16)',
                    'Professional Tax (PT) Returns',
                    'EPF / ESI Returns',
                    'Gratuity Management',
                    'TDS/TCS Filing',
                    'Inventory & Stock Management',
                    'Invoice Generation Support',
                    'Expense Tracking Consultancy',
                    'Monthly MIS Reports',
                ],
            },
            {
                title: 'Taxation & Legal Compliance',
                items: [
                    'Companies Compliance Scheme 2026 (CCFS)',
                    'GST Registration',
                    'Income Tax Return Filing (ITR 1-7)',
                    '12AA/80G Certificates',
                    'Tax Planning Support',
                    '15CA Certification',
                ],
            },
            {
                title: 'Audit Services',
                items: ['Internal Audit', 'GST Audit', 'SOX Audit', 'Stock & Compliance Audit', 'Other Audits (Need Basis)'],
            },
        ],
        offers: [],
    },
    {
        id: 'certification-quality-management',
        title: 'Certification & Quality Management Services',
        iconKey: 'Stamp',
        icon: Stamp,
        columns: [
            {
                title: 'ISO Services',
                items: [
                    'ISO 9001:2015 - Quality Management',
                    'ISO 14001:2015 - Environmental Management',
                    'ISO 45001:2018 - Occupational Health & Safety',
                    'ISO 22000:2018 - Food Safety',
                    'ISO 27001:2022 - Information Security',
                    'ISO 50001:2018 - Energy Management',
                    'ISO 13485:2016 - Medical Devices',
                    'ISO 20000-1:2018 - IT Service Management',
                    'ISO 22301:2019 - Business Continuity',
                ],
            },
            {
                title: 'Quality & Compliance',
                items: ['GMP / HACCP', 'CE Marking', 'ISI / BIS Certification', 'FDA Compliance Support'],
            },
            {
                title: 'Product & System Certifications',
                items: ['BRCGS', 'Kosher Certification', 'Halal Certification'],
            },
        ],
        offers: [],
    },
    {
        id: 'business-registration-licensing-corporate',
        title: 'Business Registrations, Licensing & Corporate Services',
        iconKey: 'Briefcase',
        icon: Briefcase,
        columns: [
            {
                title: 'Company / Business Entity Registrations',
                items: [
                    'Private Limited Company',
                    'Public Limited Company',
                    'LLP Registration',
                    'Partnership Firm Registration',
                    'Proprietorship Setup',
                    'Section 8 Company (NGO)',
                    'One Person Company',
                    'Society / Trust Registration',
                ],
            },
            {
                title: 'Mandatory Registrations',
                items: [
                    'Udyam Registration (MSME)',
                    'Shops & Establishment Registration',
                    'EPFO (PF) Registration',
                    'ESIC Registration',
                    'Professional Tax Registration',
                    'Startup India Registration',
                    'Import Export Code (IEC)',
                ],
            },
            {
                title: 'Licensing Services',
                items: [
                    'FSSAI Registration / License',
                    'LEI Certificate',
                    'Trade License',
                    'Labour / Contract Labour License',
                    'Pollution Control Board NOC / CFE / CFO',
                    'Factory License',
                    'FCRA',
                    'DARPAN for NGO',
                ],
            },
            {
                title: 'Corporate Compliances',
                items: [
                    'ROC Annual Filings (AOC-4, MGT-7)',
                    'Companies Compliance Scheme 2026 (CCFS)',
                    'Director KYC (DIR-3 KYC)',
                    'ROC Search Certificate',
                    'Charge Creation',
                    'Change in Shareholding',
                    'Change in Directorship',
                    'Merger / Demerger / Winding Up Compliance',
                    'Bonus / Loans / Buyback Compliance',
                    'Share Allotment & Transfer',
                    'Increase in Share Capital',
                    'Change in Name, Address, Objective',
                    'Digital Signatures (DSC Class 3)',
                ],
            },
        ],
        offers: [],
    },
    {
        id: 'government-msme-services',
        title: 'Government & MSME Services',
        iconKey: 'Globe',
        icon: Globe,
        columns: [
            {
                title: 'GeM (Govt e-Marketplace)',
                items: [
                    'GeM Seller Registration',
                    'OEM Panel Registration',
                    'Brand Approval',
                    'Product Listing',
                    'Bid Participation & Tender Management',
                ],
            },
            {
                title: 'Other Portal Registrations',
                items: [
                    'TReDS Registration',
                    'RERA Registration',
                    'AP/TS Single Window',
                    'NPCI Registrations',
                    'Amazon/Flipkart Seller Registration Support',
                ],
            },
            {
                title: 'Project & Finance Support',
                items: [
                    'DPR Preparation',
                    'CMA Data Preparation',
                    'Bank Loans - Term Loan + Working Capital',
                    'CGTMSE Loan Support',
                    'PMEGP Loan Support',
                    'Mudra Loans',
                    'Stand-Up India Loan Assistance',
                ],
            },
            {
                title: 'MSME & Subsidy Schemes',
                items: [
                    'CLCSS / ZED Scheme Support',
                    'PMFME (Food Processing Units)',
                    'NSIC Schemes',
                    'NABARD Schemes',
                    'Cold Chain & Food Processing Subsidy',
                    'AP/TS State Industrial Subsidy Schemes',
                ],
            },
        ],
        offers: [],
    },
    {
        id: 'branding-industrial-setup',
        title: 'Branding & Industrial Setup',
        iconKey: 'Lightbulb',
        icon: Lightbulb,
        columns: [
            {
                title: 'Startup & Branding Support',
                items: [
                    'Business Plan Preparation',
                    'Pitch Decks for Funding',
                    'Website & Branding Consulting',
                    'Vendor Empanelment Documentation',
                    'HR Policy Documentation',
                    'SOP Creation',
                ],
            },
            {
                title: 'Additional Services',
                items: [
                    'Loan File Documentation & Follow-up',
                    'Insurance Services (Business, Fire, Marine)',
                    'Digital Marketing Support',
                    'PAN / TAN Applications',
                    'Trademark & IP Services',
                    'Wealth Portfolio Management',
                ],
            },
            {
                title: 'Industrial Support',
                items: [
                    'Machinery Sourcing & Imports',
                    'Vendor Identification & Supplier Verification',
                    'Turnkey Machinery Setup Assistance',
                    'Technology Upgradation Consulting',
                    'Industry Selection & Feasibility Analysis',
                ],
            },
        ],
        offers: [],
    }
];

const ICON_MAP = {
    Factory,
    Stamp,
    Calculator,
    Briefcase,
    Globe,
    IndianRupee,
    Lightbulb,
    MoreHorizontal,
};

const REQUIRED_CATEGORY_IDS = MENU_DATA.map((service) => service.id);
const TAB_LABEL_LINES = {
    'accounting-compliance-taxation': ['Accounting &', 'Taxation'],
    'certification-quality-management': ['Certifications &', 'Quality'],
    'business-registration-licensing-corporate': ['Business', 'Registrations'],
    'government-msme-services': ['Govt & MSME', 'Services'],
    'branding-industrial-setup': ['Branding &', 'Industrial Setup'],
};
const SAMPLE_OFFERS_BY_CATEGORY = {
    'accounting-compliance-taxation': [
        { title: 'GST + ITR Combo Offer', imageUrl: 'https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?auto=format&fit=crop&w=1200&q=80', ctaLink: '/contact?service=GST%20and%20ITR%20Combo' },
    ],
    'certification-quality-management': [
        { title: 'ISO Certification Starter Pack', imageUrl: 'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?auto=format&fit=crop&w=1200&q=80', ctaLink: '/contact?service=ISO%20Starter%20Pack' },
    ],
    'business-registration-licensing-corporate': [
        { title: 'Private Limited Launch Deal', imageUrl: 'https://images.unsplash.com/photo-1559136555-9303baea8ebd?auto=format&fit=crop&w=1200&q=80', ctaLink: '/pvt-ltd-registration' },
    ],
    'government-msme-services': [
        { title: 'GeM Fast-Track Enrollment', imageUrl: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=1200&q=80', ctaLink: '/contact?service=GeM%20Fast%20Track' },
    ],
    'branding-industrial-setup': [
        { title: 'Startup Branding Booster', imageUrl: 'https://images.unsplash.com/photo-1542744173-8e7e53415bb0?auto=format&fit=crop&w=1200&q=80', ctaLink: '/contact?service=Startup%20Branding%20Booster' },
    ],
};

const normalizeServiceConfig = (services = []) => services.map((service) => ({
    ...service,
    iconKey: service.iconKey || 'Briefcase',
    icon: ICON_MAP[service.iconKey] || Briefcase,
    columns: Array.isArray(service.columns)
        ? service.columns
        : Array.isArray(service.items)
            ? [{ title: 'Services', items: service.items }]
            : [],
    offers: Array.isArray(service.offers) ? service.offers : [],
}));

const hasCompleteCategorySet = (services = []) =>
    REQUIRED_CATEGORY_IDS.every((id) => services.some((service) => service.id === id));

export const SharedHeader = ({ isScrolled: externalIsScrolled }) => {
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    const [activeMobileCategory, setActiveMobileCategory] = useState(null);
    const [activeDesktopServiceId, setActiveDesktopServiceId] = useState(null);
    const [localIsScrolled, setLocalIsScrolled] = useState(false);
    const closeMenuTimeout = useRef(null);

    const openMenu = (serviceId) => {
        if (closeMenuTimeout.current) clearTimeout(closeMenuTimeout.current);
        setActiveDesktopServiceId(serviceId);
    };
    const closeMenuWithDelay = () => {
        closeMenuTimeout.current = setTimeout(() => setActiveDesktopServiceId(null), 200);
    };
    const cancelClose = () => {
        if (closeMenuTimeout.current) clearTimeout(closeMenuTimeout.current);
    };
    const [menuConfig, setMenuConfig] = useState(normalizeServiceConfig(MENU_DATA));
    const [tickerMessages, setTickerMessages] = useState([
        'New: Income Tax return filing support now available.',
        'Startup consultation fee is adjustable against package purchase.',
        'Get faster support for registrations and certifications.',
    ]);

    // Use external scroll state if provided, otherwise handle internally
    const isScrolled = externalIsScrolled !== undefined ? externalIsScrolled : localIsScrolled;

    useEffect(() => {
        if (externalIsScrolled === undefined) {
            const handleScroll = () => {
                setLocalIsScrolled(window.scrollY > 20);
                if (activeDesktopServiceId) setActiveDesktopServiceId(null);
            };
            window.addEventListener('scroll', handleScroll);
            return () => window.removeEventListener('scroll', handleScroll);
        }
    }, [externalIsScrolled, activeDesktopServiceId]);

    useEffect(() => {
        const fetchMenu = async () => {
            try {
                const res = await fetch('/api/services/header-config');
                if (!res.ok) {
                    setMenuConfig(normalizeServiceConfig(MENU_DATA));
                    return;
                }
                const data = await res.json();
                const fetched = Array.isArray(data?.services) ? normalizeServiceConfig(data.services) : [];
                if (fetched.length === 0 || !hasCompleteCategorySet(fetched)) {
                    setMenuConfig(normalizeServiceConfig(MENU_DATA));
                    if (Array.isArray(data?.tickerMessages) && data.tickerMessages.length > 0) {
                        setTickerMessages(data.tickerMessages);
                    }
                    return;
                }
                setMenuConfig(fetched);
                if (Array.isArray(data?.tickerMessages) && data.tickerMessages.length > 0) {
                    setTickerMessages(data.tickerMessages);
                }
            } catch (error) {
                console.error('Unable to load header service config', error);
                setMenuConfig(normalizeServiceConfig(MENU_DATA));
            }
        };
        fetchMenu();
    }, []);

    const activeDesktopService = menuConfig.find((service) => service.id === activeDesktopServiceId);
    const activeDesktopOffers =
        activeDesktopService && Array.isArray(activeDesktopService.offers) && activeDesktopService.offers.length > 0
            ? activeDesktopService.offers
            : SAMPLE_OFFERS_BY_CATEGORY[activeDesktopService?.id] || [];
    const handleSearchClick = () => {
        if (window.location.pathname !== '/') {
            window.location.href = '/?focusSearch=1';
            return;
        }
        const searchSection = document.getElementById('hero-search');
        const searchInput = document.getElementById('hero-search-input');
        if (searchSection) searchSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
        setTimeout(() => searchInput?.focus(), 350);
    };

    return (
        <>
            {/* 1. TOP TICKER & ANNOUNCEMENT BAR */}
            <div className="bg-slate-950 text-slate-300 text-xs py-1.5 px-4 hidden lg:block border-b border-slate-800/80 fixed top-0 left-0 right-0 z-[60] backdrop-blur-md">
                <div className="max-w-[1400px] mx-auto flex justify-between items-center text-[11px]">
                    <div className="flex items-center gap-4 min-w-0 flex-1">
                        <span className="flex items-center text-slate-300 hover:text-white transition cursor-default">
                            <Clock className="w-3.5 h-3.5 mr-1.5 text-red-500" /> Mon - Sat: 10AM - 7PM
                        </span>
                        <span className="flex items-center text-slate-300 hover:text-white transition cursor-default">
                            <Award className="w-3.5 h-3.5 mr-1.5 text-emerald-400" /> ISO 9001:2015 Certified
                        </span>
                        <div className="min-w-0 flex-1 overflow-hidden rounded-full border border-slate-800 bg-slate-900/80 h-6">
                            <div className="ticker-track h-full flex items-center gap-10 px-4 text-[11px] font-semibold text-slate-200 whitespace-nowrap">
                                {[...tickerMessages, ...tickerMessages].map((msg, idx) => (
                                    <span key={`ticker-msg-${idx}`} className="inline-flex items-center">
                                        <span className="w-1.5 h-1.5 rounded-full bg-red-500 mr-2 animate-pulse"></span>
                                        {msg}
                                    </span>
                                ))}
                            </div>
                        </div>
                    </div>
                    <div className="flex items-center space-x-6 pl-4 font-medium">
                        <a href="mailto:vrherebms@gmail.com" className="flex items-center text-slate-300 hover:text-red-400 transition">
                            <Mail className="w-3.5 h-3.5 mr-1.5 text-slate-400" /> vrherebms@gmail.com
                        </a>
                        <a href="tel:+918008530606" className="flex items-center text-slate-200 hover:text-emerald-400 font-bold transition">
                            <Phone className="w-3.5 h-3.5 mr-1.5 text-emerald-400" /> +91 80085 30606
                        </a>
                    </div>
                </div>
            </div>

            {/* 2. MAIN HEADER NAVBAR */}
            <header className={`fixed left-0 right-0 top-0 lg:top-[33px] z-[55] transition-all duration-300 w-full ${isScrolled ? 'bg-white/95 backdrop-blur-xl shadow-lg shadow-slate-900/5 py-2.5 border-b border-slate-200/80' : 'bg-white/95 backdrop-blur-md border-b border-slate-100 py-3.5'}`}>
                <div className={`absolute inset-x-0 bottom-0 h-[2px] bg-gradient-to-r from-transparent via-red-500/50 to-transparent transition-opacity ${isScrolled ? 'opacity-100' : 'opacity-0'}`}></div>
                <div className="max-w-[1400px] mx-auto px-4 sm:px-6">
                    <div className="grid grid-cols-[auto_1fr_auto] items-center gap-4 relative">
                        {/* LOGO */}
                        <a href="/" className="flex items-center flex-shrink-0 group cursor-pointer">
                            <img src="/logo.png" alt="VR Here" className="h-11 w-auto object-contain mr-2.5 group-hover:scale-105 transition-transform duration-300" />
                            <div className="flex flex-col">
                                <span className="text-2xl font-black text-slate-900 leading-none tracking-tight group-hover:text-red-600 transition-colors">VR Here</span>
                                <span className="text-[9.5px] font-extrabold text-red-600 uppercase tracking-widest mt-0.5">Business Management Solutions</span>
                            </div>
                        </a>

                        {/* DESKTOP MEGA-MENU NAVIGATION */}
                        <nav className="hidden lg:flex items-center justify-center min-w-0">
                            <div className="relative" onMouseLeave={closeMenuWithDelay}>
                                <div className="max-w-[980px]">
                                    <div className="flex items-stretch gap-1 rounded-2xl border border-slate-200/90 bg-slate-50/90 p-1 shadow-inner shadow-slate-200/40">
                                    {menuConfig.map((service) => (
                                        <div
                                            key={service.id}
                                            className="relative"
                                            onMouseEnter={() => openMenu(service.id)}
                                        >
                                            <button className={`h-full flex items-center px-3 py-2 text-[11.5px] font-bold rounded-xl transition-all duration-300 min-w-[108px] ${activeDesktopServiceId === service.id ? 'bg-gradient-to-r from-red-600 to-rose-600 text-white shadow-md shadow-red-600/30 -translate-y-0.5' : 'text-slate-700 hover:text-red-600 hover:bg-white'}`}>
                                                <span className="text-left leading-[1.1]">
                                                    {(TAB_LABEL_LINES[service.id] || [service.title]).map((line, idx) => (
                                                        <span key={`${service.id}-line-${idx}`} className="block">{line}</span>
                                                    ))}
                                                </span>
                                                <ChevronDown className={`ml-1.5 w-3.5 h-3.5 shrink-0 transition-transform duration-300 ${activeDesktopServiceId === service.id ? 'rotate-180' : ''}`} />
                                            </button>
                                        </div>
                                    ))}
                                    </div>
                                </div>

                                {/* DROPDOWN PANEL */}
                                <div onMouseEnter={cancelClose} onMouseLeave={closeMenuWithDelay} className={`absolute top-full left-1/2 -translate-x-1/2 w-[92vw] max-w-[1240px] bg-white/98 backdrop-blur-2xl rounded-3xl shadow-[0_30px_90px_-20px_rgba(0,0,0,0.35)] border border-slate-200/90 overflow-hidden transition-all duration-300 origin-top z-50 mt-1.5 ${activeDesktopService ? 'opacity-100 translate-y-0 visible' : 'opacity-0 translate-y-4 invisible pointer-events-none'}`}>
                                    {activeDesktopService && (
                                        <div className="flex min-h-[360px]">
                                            <div className="flex-1 p-8 bg-gradient-to-br from-white via-white to-slate-50/50">
                                                <div className={`grid gap-4 ${activeDesktopService.columns.length >= 3 ? 'xl:grid-cols-3' : 'xl:grid-cols-2'} grid-cols-1`}>
                                                    {activeDesktopService.columns.map((column, columnIndex) => (
                                                        <div key={`${activeDesktopService.id}-col-${columnIndex}`} className="rounded-2xl border border-slate-200/90 bg-white p-5 hover:border-red-300 hover:shadow-lg hover:shadow-red-100/40 transition-all">
                                                            <h4 className="text-sm font-black text-slate-900 mb-3.5 flex items-center gap-2">
                                                                <span className="w-2 h-2 rounded-full bg-red-600"></span>
                                                                {column.title}
                                                            </h4>
                                                            <div className="space-y-2">
                                                                {(column.items || []).map((item, i) => (
                                                                    <a
                                                                        href={getServiceLink(item)}
                                                                        key={`${activeDesktopService.id}-${columnIndex}-${i}`}
                                                                        className="block text-xs font-medium text-slate-600 hover:text-red-600 transition-colors hover:translate-x-1 duration-200"
                                                                    >
                                                                        {item}
                                                                    </a>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                                <div className="mt-5 pt-3 border-t border-slate-100 flex items-center justify-between">
                                                    <a href={`/all-services?category=${encodeURIComponent(activeDesktopService.id)}`} className="text-xs font-black text-red-600 hover:text-red-700 uppercase tracking-wider flex items-center gap-1.5 group">
                                                        <span>View all services in this category</span>
                                                        <span className="group-hover:translate-x-1 transition-transform">&rarr;</span>
                                                    </a>
                                                    <span className="text-[11px] text-slate-400 font-semibold">100% Online MCA & CA Execution</span>
                                                </div>
                                            </div>
                                            <div className="w-[320px] bg-slate-50 p-6 border-l border-slate-100 flex flex-col justify-between">
                                                <div>
                                                    <div className="flex items-center justify-between mb-4">
                                                        <h4 className="text-xs font-black uppercase tracking-wider text-slate-900">Featured Offer</h4>
                                                        <span className="text-[10px] font-bold text-red-600 bg-red-50 px-2 py-0.5 rounded-full border border-red-200">Limited Period</span>
                                                    </div>
                                                    <div className="space-y-3">
                                                        {activeDesktopOffers.slice(0, 2).map((offer) => (
                                                            <a key={offer._id || `${offer.title}-${offer.imageUrl}`} href={offer.ctaLink || '/contact'} className="block overflow-hidden rounded-2xl border border-slate-200 bg-white hover:shadow-xl hover:-translate-y-0.5 transition-all group">
                                                                <img src={offer.imageUrl} alt={offer.title} className="w-full h-28 object-cover group-hover:scale-105 transition-transform duration-500" />
                                                                <div className="p-3">
                                                                    <div className="text-xs font-bold text-slate-900 line-clamp-2">{offer.title}</div>
                                                                    <div className="mt-1 text-[11px] font-black text-red-600 flex items-center gap-1">
                                                                        Explore Offer &rarr;
                                                                    </div>
                                                                </div>
                                                            </a>
                                                        ))}
                                                        {activeDesktopOffers.length === 0 && (
                                                            <div className="text-xs text-slate-500 bg-white border border-dashed border-slate-300 rounded-2xl p-4 text-center">
                                                                Special compliance packages available on request.
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>

                                                <div className="mt-4 pt-4 border-t border-slate-200/80">
                                                    <a href="/contact" className="w-full bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 transition shadow-md">
                                                        <Phone className="w-3.5 h-3.5 text-red-400" />
                                                        <span>Need Custom Advice?</span>
                                                    </a>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </nav>

                        {/* RIGHT ACTIONS: APPS HUB, SEARCH, CTA, LOGIN */}
                        <div className="hidden lg:flex items-center flex-shrink-0 gap-3 justify-end">
                            {/* SEARCH BUTTON */}
                            <button
                                onClick={handleSearchClick}
                                className="p-2.5 bg-slate-50 hover:bg-red-50 hover:text-red-600 text-slate-600 border border-slate-200/80 rounded-xl transition-all shadow-2xs"
                                title="Search services"
                            >
                                <Search className="w-4 h-4" />
                            </button>
                            
                            {/* PREMIUM APP STORE & GOOGLE PLAY PRESENTATION */}
                            <div className="relative group/app">
                                <div className="flex items-center gap-2.5 px-3 py-1.5 bg-slate-50 hover:bg-slate-100/90 border border-slate-200/90 rounded-xl transition-all duration-300 shadow-2xs cursor-pointer group-hover/app:border-red-300 group-hover/app:shadow-md">
                                    <div className="flex items-center -space-x-1.5">
                                        <div className="w-6 h-6 rounded-lg bg-black text-white flex items-center justify-center shadow-xs" title="Apple iOS App">
                                            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                                                <path d="M17.05 20.28c-.98 1.56-2.02 3.1-3.72 3.14-1.67.03-2.2-.97-4.1-.97-1.9 0-2.48.94-4.08.99-1.67.06-2.86-1.66-3.85-3.08-2.02-2.9-3.56-8.17-1.48-11.75 1.03-1.78 2.87-2.9 4.88-2.93 1.52-.03 2.96 1.02 3.9 1.02.93 0 2.65-1.23 4.47-1.04.76.03 2.9.3 4.27 2.3-1.11.67-2.61 2.23-2.58 4.8.03 3.08 2.68 4.15 2.71 4.17-.02.08-.43 1.48-1.42 2.92M15 4.3c.77-.94 1.28-2.24 1.14-3.54-1.12.05-2.48.75-3.28 1.69-.7.8-1.32 2.12-1.15 3.4 1.25.1 2.52-.61 3.29-1.55z" />
                                            </svg>
                                        </div>
                                        <div className="w-6 h-6 rounded-lg bg-emerald-600 text-white flex items-center justify-center shadow-xs ring-2 ring-white" title="Google Play Android App">
                                            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                                                <path d="M3.609 1.814L13.782 12l-10.173 10.186c-.328-.31-.523-.746-.523-1.23V3.044c0-.484.195-.92.523-1.23M17.47 8.35L4.85 1.196C5.074 1.071 5.332 1 5.614 1c.54 0 1.037.262 1.344.67l10.513 6.68-1.741 1.741M18.847 12.925l-2.079-1.32-1.722 1.722 1.722 1.722 2.079-1.32c.791-.502.791-1.302 0-1.804M17.07 15.65L6.958 22.09c-.307.408-.804.67-1.344.67-.282 0-.54-.071-.764-.196l12.62-7.155-1.4 1.4" />
                                            </svg>
                                        </div>
                                    </div>
                                    <div className="flex flex-col text-left">
                                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-900 leading-none flex items-center gap-1">
                                            Apps <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                                        </span>
                                        <span className="text-[9px] font-bold text-red-600 leading-tight">iOS & Android</span>
                                    </div>
                                </div>

                                {/* APPS POPOVER CARD */}
                                <div className="absolute top-full right-0 mt-2 w-72 bg-white rounded-2xl p-4 shadow-2xl border border-slate-200/90 opacity-0 translate-y-2 invisible group-hover/app:opacity-100 group-hover/app:translate-y-0 group-hover/app:visible transition-all duration-200 z-50">
                                    <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                                        <div>
                                            <div className="text-xs font-black text-slate-900">VR HERE Mobile Suite</div>
                                            <div className="text-[10px] text-slate-500 font-medium">Live document & filing tracking</div>
                                        </div>
                                        <span className="bg-emerald-50 text-emerald-700 text-[9px] font-black px-2 py-0.5 rounded-full border border-emerald-200">v2.0 Live</span>
                                    </div>

                                    <div className="space-y-2 mt-3">
                                        <a
                                            href="https://apps.apple.com/in/app/vr-here-bms/id6785507672"
                                            target="_blank"
                                            rel="noreferrer"
                                            className="flex items-center gap-3 p-2.5 rounded-xl bg-slate-950 text-white hover:bg-slate-800 transition group/btn"
                                        >
                                            <div className="w-8 h-8 rounded-lg bg-white/10 flex items-center justify-center shrink-0">
                                                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                                                    <path d="M17.05 20.28c-.98 1.56-2.02 3.1-3.72 3.14-1.67.03-2.2-.97-4.1-.97-1.9 0-2.48.94-4.08.99-1.67.06-2.86-1.66-3.85-3.08-2.02-2.9-3.56-8.17-1.48-11.75 1.03-1.78 2.87-2.9 4.88-2.93 1.52-.03 2.96 1.02 3.9 1.02.93 0 2.65-1.23 4.47-1.04.76.03 2.9.3 4.27 2.3-1.11.67-2.61 2.23-2.58 4.8.03 3.08 2.68 4.15 2.71 4.17-.02.08-.43 1.48-1.42 2.92M15 4.3c.77-.94 1.28-2.24 1.14-3.54-1.12.05-2.48.75-3.28 1.69-.7.8-1.32 2.12-1.15 3.4 1.25.1 2.52-.61 3.29-1.55z" />
                                                </svg>
                                            </div>
                                            <div className="flex flex-col text-left flex-1">
                                                <span className="text-[9px] text-slate-400 font-semibold uppercase leading-none">Download on the</span>
                                                <span className="text-xs font-black tracking-tight leading-tight">Apple App Store</span>
                                            </div>
                                            <span className="text-xs text-slate-400 group-hover/btn:text-white">&rarr;</span>
                                        </a>

                                        <a
                                            href="https://play.google.com/store/apps/details?id=com.sbr.vrherebms&hl=en_IN"
                                            target="_blank"
                                            rel="noreferrer"
                                            className="flex items-center gap-3 p-2.5 rounded-xl bg-slate-950 text-white hover:bg-slate-800 transition group/btn"
                                        >
                                            <div className="w-8 h-8 rounded-lg bg-emerald-600/20 text-emerald-400 flex items-center justify-center shrink-0 border border-emerald-500/20">
                                                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                                                    <path d="M3.609 1.814L13.782 12l-10.173 10.186c-.328-.31-.523-.746-.523-1.23V3.044c0-.484.195-.92.523-1.23M17.47 8.35L4.85 1.196C5.074 1.071 5.332 1 5.614 1c.54 0 1.037.262 1.344.67l10.513 6.68-1.741 1.741M18.847 12.925l-2.079-1.32-1.722 1.722 1.722 1.722 2.079-1.32c.791-.502.791-1.302 0-1.804M17.07 15.65L6.958 22.09c-.307.408-.804.67-1.344.67-.282 0-.54-.071-.764-.196l12.62-7.155-1.4 1.4" />
                                                </svg>
                                            </div>
                                            <div className="flex flex-col text-left flex-1">
                                                <span className="text-[9px] text-slate-400 font-semibold uppercase leading-none">Get it on</span>
                                                <span className="text-xs font-black tracking-tight leading-tight">Google Play Store</span>
                                            </div>
                                            <span className="text-xs text-slate-400 group-hover/btn:text-white">&rarr;</span>
                                        </a>
                                    </div>

                                    <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between text-[10px] text-slate-500 font-semibold">
                                        <span className="text-amber-500 font-bold">★ 4.9 Rating</span>
                                        <span>MCA & CA Verified</span>
                                    </div>
                                </div>
                            </div>

                            {/* TALK TO EXPERT CTA BUTTON */}
                            <a
                                href="/contact"
                                className="bg-gradient-to-r from-red-600 via-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 text-white px-4 py-2.5 rounded-xl font-bold text-xs uppercase tracking-wider transition-all shadow-md shadow-red-600/25 flex items-center gap-2 whitespace-nowrap transform hover:-translate-y-0.5 active:scale-95"
                            >
                                <Phone className="w-3.5 h-3.5" />
                                <span>Talk to Expert</span>
                            </a>

                            {/* LOGIN BUTTON */}
                            <a
                                href="/login"
                                className="flex items-center gap-1.5 px-3.5 py-2.5 text-slate-700 hover:text-red-600 font-bold text-xs uppercase tracking-wider border border-slate-200/90 rounded-xl hover:bg-slate-50 hover:border-slate-300 whitespace-nowrap transition-all flex-shrink-0 shadow-2xs"
                            >
                                <LogIn className="w-3.5 h-3.5" />
                                <span>Login</span>
                            </a>
                        </div>

                        {/* MOBILE HAMBURGER TOGGLE */}
                        <div className="flex items-center gap-2 lg:hidden ml-auto">
                            <a href="/login" className="p-2 text-slate-700 hover:text-red-600 transition">
                                <LogIn className="w-5 h-5" />
                            </a>
                            <button className="p-2 text-slate-800 hover:bg-slate-100 rounded-xl transition" onClick={() => setIsMobileMenuOpen(true)}>
                                <Menu className="w-6 h-6" />
                            </button>
                        </div>
                    </div>
                </div>
            </header>
            <div className="h-[76px] lg:h-[120px]"></div>

            {/* MOBILE MENU DRAWER */}
            <div className={`fixed inset-0 bg-white z-[60] transform transition-transform duration-300 lg:hidden overflow-y-auto ${isMobileMenuOpen ? 'translate-x-0' : 'translate-x-full'}`}>
                <div className="p-4 border-b border-slate-100 flex justify-between items-center sticky top-0 bg-white z-10">
                    <div className="flex items-center">
                        <img src="/logo.png" alt="VR HERE" className="h-8 w-auto object-contain mr-2" />
                        <span className="font-bold text-base text-slate-900">Services Menu</span>
                    </div>
                    <button onClick={() => setIsMobileMenuOpen(false)} className="p-2 bg-slate-100 rounded-full hover:bg-red-100 hover:text-red-600 transition">
                        <X className="w-5 h-5" />
                    </button>
                </div>
                <div className="p-4 space-y-3">
                    <div className="border rounded-2xl overflow-hidden border-slate-100">
                        <div className="bg-slate-50 px-4 py-3 font-bold text-sm flex justify-between items-center text-slate-900">
                            <span>Browse Categories</span>
                            <span className="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded-full font-bold">{menuConfig.length} Tabs</span>
                        </div>
                        <div className="divide-y divide-slate-100">
                            {menuConfig.map((service) => (
                                <div key={service.id} className="bg-white">
                                    <button onClick={() => setActiveMobileCategory(activeMobileCategory === service.id ? null : service.id)} className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-slate-50 transition">
                                        <div className="flex items-center space-x-3">
                                            <div className={`p-1.5 rounded-lg ${activeMobileCategory === service.id ? 'bg-red-600 text-white' : 'bg-slate-100 text-slate-600'}`}>
                                                <service.icon className="w-4 h-4" />
                                            </div>
                                            <span className={`text-xs font-bold ${activeMobileCategory === service.id ? 'text-red-600' : 'text-slate-700'}`}>{service.title}</span>
                                        </div>
                                        <ChevronDown className={`w-4 h-4 transition-transform ${activeMobileCategory === service.id ? 'rotate-180 text-red-600' : 'text-slate-400'}`} />
                                    </button>
                                    {activeMobileCategory === service.id && (
                                        <div className="bg-slate-50 px-4 pb-4 pt-2 space-y-2 pl-12 animate-fade-in">
                                            {service.columns.map((column, colIdx) => (
                                                <div key={`${service.id}-mobile-col-${colIdx}`} className="mb-3">
                                                    <div className="text-[11px] font-black uppercase tracking-wider text-slate-800 mb-1">{column.title}</div>
                                                    {(column.items || []).map((item, i) => (
                                                        <a href={getServiceLink(item)} key={`${service.id}-${colIdx}-${i}`} className="block text-xs text-slate-600 border-l-2 border-slate-200 pl-3 py-1 active:text-red-600 hover:text-red-600">
                                                            {item}
                                                        </a>
                                                    ))}
                                                </div>
                                            ))}
                                            <a href={`/all-services?category=${encodeURIComponent(service.id)}`} className="block text-xs font-bold text-red-600 border-l-2 border-red-200 pl-3 py-1 mt-2">
                                                View All Services &rarr;
                                            </a>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Mobile App Download Card */}
                    <div className="p-4 rounded-2xl border border-slate-200 bg-slate-900 text-white shadow-lg">
                        <div className="flex items-center justify-between mb-3">
                            <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Download VR HERE App</span>
                            <span className="bg-emerald-500/20 text-emerald-300 text-[9px] font-black px-2 py-0.5 rounded-full">v2.0 Live</span>
                        </div>
                        <p className="text-xs text-slate-300 mb-3 leading-relaxed">
                            Access CA consultations, status tracking, and certificates directly on your phone.
                        </p>
                        <div className="grid grid-cols-2 gap-2">
                            <a href="https://apps.apple.com/in/app/vr-here-bms/id6785507672" target="_blank" rel="noreferrer" className="flex items-center justify-center gap-2 px-3 py-2.5 bg-white/10 hover:bg-white/20 rounded-xl text-white transition text-xs font-bold">
                                <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M17.05 20.28c-.98 1.56-2.02 3.1-3.72 3.14-1.67.03-2.2-.97-4.1-.97-1.9 0-2.48.94-4.08.99-1.67.06-2.86-1.66-3.85-3.08-2.02-2.9-3.56-8.17-1.48-11.75 1.03-1.78 2.87-2.9 4.88-2.93 1.52-.03 2.96 1.02 3.9 1.02.93 0 2.65-1.23 4.47-1.04.76.03 2.9.3 4.27 2.3-1.11.67-2.61 2.23-2.58 4.8.03 3.08 2.68 4.15 2.71 4.17-.02.08-.43 1.48-1.42 2.92M15 4.3c.77-.94 1.28-2.24 1.14-3.54-1.12.05-2.48.75-3.28 1.69-.7.8-1.32 2.12-1.15 3.4 1.25.1 2.52-.61 3.29-1.55z" />
                                </svg>
                                <span>App Store</span>
                            </a>
                            <a href="https://play.google.com/store/apps/details?id=com.sbr.vrherebms&hl=en_IN" target="_blank" rel="noreferrer" className="flex items-center justify-center gap-2 px-3 py-2.5 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-white transition text-xs font-bold">
                                <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M3.609 1.814L13.782 12l-10.173 10.186c-.328-.31-.523-.746-.523-1.23V3.044c0-.484.195-.92.523-1.23M17.47 8.35L4.85 1.196C5.074 1.071 5.332 1 5.614 1c.54 0 1.037.262 1.344.67l10.513 6.68-1.741 1.741M18.847 12.925l-2.079-1.32-1.722 1.722 1.722 1.722 2.079-1.32c.791-.502.791-1.302 0-1.804M17.07 15.65L6.958 22.09c-.307.408-.804.67-1.344.67-.282 0-.54-.071-.764-.196l12.62-7.155-1.4 1.4" />
                                </svg>
                                <span>Google Play</span>
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
};

export const GlobalFloatingButtons = () => {
    const [isVisible, setIsVisible] = useState(false);
    const [isMenuOpen, setIsMenuOpen] = useState(false);
    const [isHome, setIsHome] = useState(window.location.pathname === '/' || window.location.pathname === '/home');

    useEffect(() => {
        const toggleVisibility = () => setIsVisible(window.scrollY > 300);
        const checkPath = () => setIsHome(window.location.pathname === '/' || window.location.pathname === '/home');
        
        window.addEventListener('scroll', toggleVisibility);
        // Path check on navigation or interval since it's a SPA
        const interval = setInterval(checkPath, 1000);
        
        return () => {
            window.removeEventListener('scroll', toggleVisibility);
            clearInterval(interval);
        };
    }, []);

    const scrollToTop = () => window.scrollTo({ top: 0, behavior: 'smooth' });
    const scrollToSection = (id) => {
        const el = document.getElementById(id);
        if (el) el.scrollIntoView({ behavior: 'smooth' });
        setIsMenuOpen(false);
    };

    return (
        <div className="fixed right-6 bottom-6 z-[100] flex flex-col gap-3">
            {/* Page Jump Navigator (Hidden on Home) */}
            {!isHome && (
                <div className="relative mb-2">
                    {isMenuOpen && (
                        <div className="absolute right-0 bottom-full mb-4 flex flex-col bg-white rounded-xl shadow-2xl border border-slate-100 p-2 min-w-[150px] animate-fade-in text-sm font-bold text-slate-700">
                            <button onClick={() => scrollToSection('hero')} className="hover:bg-slate-50 hover:text-red-600 px-3 py-2 rounded-lg text-left transition-colors whitespace-nowrap border-b border-slate-50">Top Section</button>
                            <button onClick={() => scrollToSection('services')} className="hover:bg-slate-50 hover:text-red-600 px-3 py-2 rounded-lg text-left transition-colors whitespace-nowrap border-b border-slate-50">Information</button>
                            <button onClick={() => scrollToSection('pricing')} className="hover:bg-slate-50 hover:text-red-600 px-3 py-2 rounded-lg text-left transition-colors whitespace-nowrap border-b border-slate-50">Pricing Plan</button>
                            <button onClick={() => scrollToSection('faq')} className="hover:bg-slate-50 hover:text-red-600 px-3 py-2 rounded-lg text-left transition-colors whitespace-nowrap">Questions</button>
                        </div>
                    )}
                    <button
                        onClick={() => setIsMenuOpen(!isMenuOpen)}
                        className="w-12 h-12 bg-slate-900 text-white rounded-full flex items-center justify-center shadow-lg hover:bg-black hover:shadow-xl transition-all duration-300 transform hover:scale-110"
                        title="Jump to Section"
                    >
                        {isMenuOpen ? <X className="w-5 h-5" /> : <List className="w-5 h-5" />}
                    </button>
                </div>
            )}

            {/* Contact WhatsApp */}
            <a href="https://wa.me/918008530606" target="_blank" rel="noreferrer" className="bg-green-500 hover:bg-green-600 text-white w-12 h-12 rounded-full shadow-lg hover:shadow-2xl transition-all duration-300 transform hover:scale-110 flex items-center justify-center group relative" title="WhatsApp Us">
                <MessageSquare className="w-5 h-5" />
                <span className="absolute right-full mr-3 bg-black text-white text-xs font-bold px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">Chat on WhatsApp</span>
            </a>

            {/* Contact Phone */}
            <a href="tel:+918008530606" className="bg-black hover:bg-slate-800 text-white w-12 h-12 rounded-full shadow-lg hover:shadow-2xl transition-all duration-300 transform hover:scale-110 flex items-center justify-center group relative" title="Call Us">
                <Phone className="w-5 h-5" />
                <span className="absolute right-full mr-3 bg-black text-white text-xs font-bold px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">Call Expert</span>
            </a>

            {/* Back to Top (Positioned at bottom per user request) */}
            {isVisible && (
                <button
                    onClick={scrollToTop}
                    className="w-12 h-12 bg-white text-slate-900 rounded-full flex items-center justify-center shadow-lg border border-slate-200 hover:bg-slate-50 hover:text-red-600 transition-all duration-300 transform hover:scale-110 animate-fade-in"
                    title="Back to Top"
                >
                    <ArrowUp className="w-5 h-5" />
                </button>
            )}
        </div>
    );
};

export const SharedFooter = () => (
    <footer className="bg-[#0f172a] text-slate-300 pt-16 pb-8 border-t border-slate-800 font-sans relative">
        <GlobalFloatingButtons />
        <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 mb-16">

                {/* Column 1: Brand & Contact */}
                <div className="lg:col-span-3 space-y-8">
                    <div className="flex items-center space-x-3 group cursor-pointer" onClick={() => window.scrollTo(0, 0)}>
                        <div className="w-10 h-10 bg-white rounded-lg flex items-center justify-center transform group-hover:rotate-12 transition-transform duration-300">
                            <span className="text-black font-black text-xl">VR</span>
                        </div>
                        <div>
                            <h2 className="text-2xl font-extrabold text-white leading-none group-hover:text-red-500 transition-colors">VR Here</h2>
                            <p className="text-[10px] text-red-500 font-bold tracking-widest uppercase mt-1">Business Management Solutions</p>
                        </div>
                    </div>
                    {/* ADDRESS REMOVED */}
                    <p className="text-sm leading-relaxed text-slate-400">
                        India's Leading Digital Business Consultant.<br />
                        Everything from Registration to Industrial Setup.
                    </p>
                    <div className="space-y-2">
                        <a href="tel:+918008530606" className="flex items-center text-slate-400 hover:text-white transition"><Phone className="w-4 h-4 mr-2" /> +91 80085 30606</a>
                        <a href="mailto:vrherebms@gmail.com" className="flex items-center text-slate-400 hover:text-white transition"><Mail className="w-4 h-4 mr-2" /> vrherebms@gmail.com</a>
                    </div>
                    <div className="flex space-x-4">
                        <a href="#" className="p-2 bg-slate-800 rounded-full hover:bg-red-600 hover:text-white transition transform hover:scale-110 hover:-translate-y-1">
                            <UsersIcon className="w-4 h-4" />
                        </a>
                        <a href="#" className="p-2 bg-slate-800 rounded-full hover:bg-red-600 hover:text-white transition transform hover:scale-110 hover:-translate-y-1">
                            <Globe className="w-4 h-4" />
                        </a>
                    </div>
                    <div className="pt-2">
                        <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">Download our App</p>
                        <div className="flex flex-col sm:flex-row lg:flex-col xl:flex-row gap-3 mb-4">
                            <a href="https://apps.apple.com/in/app/vr-here-bms/id6785507672" target="_blank" rel="noreferrer" className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-lg text-white transition hover:bg-slate-800 w-[140px]">
                                <svg className="w-5 h-5 shrink-0" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M17.05 20.28c-.98 1.56-2.02 3.1-3.72 3.14-1.67.03-2.2-.97-4.1-.97-1.9 0-2.48.94-4.08.99-1.67.06-2.86-1.66-3.85-3.08-2.02-2.9-3.56-8.17-1.48-11.75 1.03-1.78 2.87-2.9 4.88-2.93 1.52-.03 2.96 1.02 3.9 1.02.93 0 2.65-1.23 4.47-1.04.76.03 2.9.3 4.27 2.3-1.11.67-2.61 2.23-2.58 4.8.03 3.08 2.68 4.15 2.71 4.17-.02.08-.43 1.48-1.42 2.92M15 4.3c.77-.94 1.28-2.24 1.14-3.54-1.12.05-2.48.75-3.28 1.69-.7.8-1.32 2.12-1.15 3.4 1.25.1 2.52-.61 3.29-1.55z" />
                                </svg>
                                <div className="text-left">
                                    <div className="text-[9px] text-slate-500 leading-none">Download on the</div>
                                    <div className="text-xs font-bold leading-tight">App Store</div>
                                </div>
                            </a>
                            <a href="https://play.google.com/store/apps/details?id=com.sbr.vrherebms&hl=en_IN" target="_blank" rel="noreferrer" className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-lg text-white transition hover:bg-slate-800 w-[140px]">
                                <svg className="w-5 h-5 shrink-0" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M3.609 1.814L13.782 12l-10.173 10.186c-.328-.31-.523-.746-.523-1.23V3.044c0-.484.195-.92.523-1.23M17.47 8.35L4.85 1.196C5.074 1.071 5.332 1 5.614 1c.54 0 1.037.262 1.344.67l10.513 6.68-1.741 1.741M18.847 12.925l-2.079-1.32-1.722 1.722 1.722 1.722 2.079-1.32c.791-.502.791-1.302 0-1.804M17.07 15.65L6.958 22.09c-.307.408-.804.67-1.344.67-.282 0-.54-.071-.764-.196l12.62-7.155-1.4 1.4" />
                                </svg>
                                <div className="text-left">
                                    <div className="text-[9px] text-slate-500 leading-none">GET IT ON</div>
                                    <div className="text-xs font-bold leading-tight">Google Play</div>
                                </div>
                            </a>
                        </div>
                    </div>
                </div>

                {/* Columns 2-4: Links Grid */}
                <div className="lg:col-span-9 grid md:grid-cols-3 gap-8">
                    <div>
                        <h3 className="text-red-500 font-bold text-sm uppercase tracking-wider mb-6">Start a Business</h3>
                        <ul className="space-y-3 text-sm">
                            <li><a href="/pvt-ltd-registration" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Private Limited Company</a></li>
                            <li><a href="/public-limited-company" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Public Limited Company</a></li>
                            <li><a href="/llp-registration" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Limited Liability Partnership (LLP)</a></li>
                            <li><a href="/partnership-firm-registration" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Partnership Firm</a></li>
                            <li><a href="/proprietorship-setup" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Sole Proprietorship</a></li>
                            <li><a href="/section-8-company" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Section 8 Company (NGO)</a></li>
                            <li><a href="/one-person-company" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">One Person Company (OPC)</a></li>
                            <li><a href="/society-trust-registration" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Society & Trust Registration</a></li>
                        </ul>
                    </div>
                    <div>
                        <h3 className="text-red-500 font-bold text-sm uppercase tracking-wider mb-6">Grow & Manage</h3>
                        <ul className="space-y-3 text-sm">
                            <li><a href="/gst-registration" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">GST Registration</a></li>
                            <li><a href="/contact?service=Accounting" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Accounting Services</a></li>
                            <li><a href="/contact?service=MSME" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">MSME Loans</a></li>
                            <li><a href="/contact?service=GeM" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">GeM Registration</a></li>
                            <li><a href="/contact?service=ISO" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">ISO Certification</a></li>
                        </ul>
                    </div>
                    <div>
                        <h3 className="text-red-500 font-bold text-sm uppercase tracking-wider mb-6">Industrial</h3>
                        <ul className="space-y-3 text-sm">
                            {['Machinery Sourcing', 'Factory License', 'Pollution Control NOC', 'Turnkey Setup', 'Import Export Code'].map(item => (
                                <li key={item}><a href={`/contact?service=${encodeURIComponent(item)}`} className="hover:text-white transition-colors block py-1">{item}</a></li>
                            ))}
                        </ul>
                    </div>
                </div>
            </div>
            <div className="pt-8 border-t border-slate-800 flex flex-col md:flex-row justify-between items-center gap-4 text-xs text-slate-500">
                <div className="space-y-1">
                    <p>&copy; {new Date().getFullYear()} VR Here Business Management Solutions. All rights reserved.</p>
                    <p className="text-[11px] text-slate-600">Built with ❤️ by <a href="https://www.rajugariventures.com" target="_blank" rel="noreferrer" className="hover:text-red-500 transition-colors font-medium">Rajugari Ventures</a></p>
                </div>
                <div className="flex gap-4 items-center py-2 md:py-0">
                    <img src="/iso9001.png" alt="ISO 9001:2015" className="h-8 w-auto opacity-70 hover:opacity-100 transition duration-300" />
                    <img src="/iso27001.png" alt="ISO 27001:2022" className="h-8 w-auto opacity-70 hover:opacity-100 transition duration-300" />
                    <img src="/dpdp.png" alt="DPDP Act Compliance" className="h-8 w-auto opacity-70 hover:opacity-100 transition duration-300" />
                </div>
                <div className="flex space-x-6">
                    <a href="/partner/signup" className="hover:text-red-500 transition font-medium">Become a Partner</a>
                    <a href="/privacy-policy" className="hover:text-white transition">Privacy Policy</a>
                    <a href="/terms-and-conditions" className="hover:text-white transition">Terms & Conditions</a>
                </div>
            </div>
        </div>
    </footer>
);
