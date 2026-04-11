// Header Version: 1.5 - Logo + Menu Merge + Dropdown Fix
import React, { useState, useEffect, useRef } from 'react';
import {
    Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
    Phone, Menu, X, ChevronDown, Clock, Award, Search,
    Mail, Users, CheckCircle, LogIn, ArrowUp, List, MessageSquare
} from 'lucide-react';

/* --- MENU DATA WITH LINKS --- */
export const getServiceLink = (serviceName) => {
    const normalized = String(serviceName || '').toLowerCase();
    if (normalized.includes('private limited')) return '/pvt-ltd-registration';
    if (normalized.includes('gst registration') || normalized.includes('gst return')) return '/gst-registration';
    if (normalized.includes('income tax')) return '/income-tax-return';
    if (normalized.includes('compliance scheme 2026') || normalized.includes('ccfs')) return '/compliance-scheme-2026';
    if (normalized.includes('partnership')) return '/partnership-firm';
    return `/contact?service=${encodeURIComponent(serviceName)}`;
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
                    'Private Limited / Public Limited Company',
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
            <div className="bg-slate-900 text-slate-400 text-xs py-2 px-4 hidden lg:block border-b border-slate-800 fixed top-0 left-0 right-0 z-[60]">
                <div className="max-w-[1400px] mx-auto flex justify-between items-center">
                    <div className="flex items-center gap-4 min-w-0 flex-1">
                        {/* ADDRESS REMOVED HERE */}
                        <span className="flex items-center hover:text-white transition cursor-default"><Clock className="w-3 h-3 mr-2 text-red-600" /> Mon - Sat: 10AM - 7PM</span>
                        <span className="flex items-center hover:text-white transition cursor-default"><Award className="w-3 h-3 mr-2 text-red-600" /> ISO 9001:2015 Certified</span>
                        <div className="min-w-0 flex-1 overflow-hidden rounded-full border border-slate-700/80 bg-slate-800/70 h-6">
                            <div className="ticker-track h-full flex items-center gap-10 px-4 text-[11px] font-semibold text-slate-200 whitespace-nowrap">
                                {[...tickerMessages, ...tickerMessages].map((msg, idx) => (
                                    <span key={`ticker-msg-${idx}`} className="inline-flex items-center">
                                        <span className="w-1.5 h-1.5 rounded-full bg-red-500 mr-2"></span>
                                        {msg}
                                    </span>
                                ))}
                            </div>
                        </div>
                    </div>
                    <div className="flex items-center space-x-6">
                        <a href="mailto:vrherebms@gmail.com" className="flex items-center hover:text-red-500 transition"><Mail className="w-3 h-3 mr-2" /> vrherebms@gmail.com</a>
                        <a href="tel:+918008530606" className="flex items-center hover:text-red-500 font-bold transition"><Phone className="w-3 h-3 mr-2" /> +91 80085 30606</a>
                    </div>
                </div>
            </div>

            <header className={`fixed left-0 right-0 top-0 lg:top-8 z-[55] transition-all duration-300 w-full ${isScrolled ? 'bg-white/95 backdrop-blur-md shadow-xl py-2' : 'bg-white border-b border-slate-100 py-4'}`}>
                <div className={`absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-red-400/60 to-transparent transition-opacity ${isScrolled ? 'opacity-100' : 'opacity-0'}`}></div>
                <div className="max-w-[1400px] mx-auto px-4 sm:px-6">
                    <div className="grid grid-cols-[auto_1fr_auto] items-center gap-4 relative">
                        {/* LOGO: Points to / (Home) */}
                        <a href="/" className="flex items-center flex-shrink-0 group cursor-pointer">
                            <img src="/logo.png" alt="VR HERE" className="h-12 w-auto object-contain mr-2 group-hover:scale-105 transition-transform duration-300" />
                            <div className="flex flex-col">
                                <span className="text-2xl font-extrabold text-black leading-none tracking-tight group-hover:text-red-600 transition-colors">VR HERE</span>
                                <span className="text-[10px] font-bold text-red-600 uppercase tracking-widest mt-0.5">Business Solutions</span>
                            </div>
                        </a>

                        <nav className="hidden lg:flex items-center justify-center min-w-0">
                            <div className="relative" onMouseLeave={closeMenuWithDelay}>
                                <div className="max-w-[980px]">
                                    <div className="flex items-stretch gap-1 rounded-2xl border border-slate-200 bg-slate-50/80 p-1">
                                    {menuConfig.map((service) => (
                                        <div
                                            key={service.id}
                                            className="relative"
                                            onMouseEnter={() => openMenu(service.id)}
                                        >
                                            <button className={`h-full flex items-center px-3 py-2 text-[12px] font-bold rounded-xl transition-all duration-300 min-w-[110px] ${activeDesktopServiceId === service.id ? 'bg-gradient-to-r from-red-600 to-orange-500 text-white shadow-lg shadow-red-600/30 -translate-y-0.5' : 'text-slate-700 hover:text-red-600 hover:bg-white'}`}>
                                                <span className="text-left leading-[1.05]">
                                                    {(TAB_LABEL_LINES[service.id] || [service.title]).map((line, idx) => (
                                                        <span key={`${service.id}-line-${idx}`} className="block">{line}</span>
                                                    ))}
                                                </span>
                                                <ChevronDown className={`ml-1 w-3.5 h-3.5 shrink-0 transition-transform duration-300 ${activeDesktopServiceId === service.id ? 'rotate-180' : ''}`} />
                                            </button>
                                        </div>
                                    ))}
                                    </div>
                                </div>

                                <div onMouseEnter={cancelClose} onMouseLeave={closeMenuWithDelay} className={`absolute top-full left-1/2 -translate-x-1/2 w-[92vw] max-w-[1240px] bg-white/95 backdrop-blur-xl rounded-2xl shadow-[0_30px_80px_-25px_rgba(0,0,0,0.4)] border border-slate-200 overflow-hidden transition-all duration-300 origin-top z-50 mt-1 ${activeDesktopService ? 'opacity-100 translate-y-0 visible' : 'opacity-0 translate-y-4 invisible pointer-events-none'}`}>
                                    {activeDesktopService && (
                                        <div className="flex min-h-[360px]">
                                            <div className="flex-1 p-8 bg-gradient-to-br from-white via-white to-slate-50">
                                                <div className={`grid gap-4 ${activeDesktopService.columns.length >= 3 ? 'xl:grid-cols-3' : 'xl:grid-cols-2'} grid-cols-1`}>
                                                    {activeDesktopService.columns.map((column, columnIndex) => (
                                                        <div key={`${activeDesktopService.id}-col-${columnIndex}`} className="rounded-xl border border-slate-200 bg-white p-4 hover:border-red-200 hover:shadow-lg hover:shadow-red-100/40 transition-all">
                                                            <h4 className="text-sm font-extrabold text-slate-800 mb-3">{column.title}</h4>
                                                            <div className="space-y-2">
                                                                {(column.items || []).map((item, i) => (
                                                                    <a
                                                                        href={getServiceLink(item)}
                                                                        key={`${activeDesktopService.id}-${columnIndex}-${i}`}
                                                                        className="block text-sm font-medium text-slate-600 hover:text-red-600 transition-colors"
                                                                    >
                                                                        {item}
                                                                    </a>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                                <div className="mt-4">
                                                    <a href={`/all-services?category=${encodeURIComponent(activeDesktopService.id)}`} className="text-xs font-bold text-red-500 hover:text-red-700 uppercase tracking-wide">View all services &rarr;</a>
                                                </div>
                                            </div>
                                            <div className="w-[320px] bg-slate-50 p-6 border-l border-slate-100">
                                                <div className="flex items-center justify-between mb-3">
                                                    <h4 className="text-sm font-black text-slate-900">Latest Offers</h4>
                                                </div>
                                                <div className="space-y-3">
                                                    {activeDesktopOffers.slice(0, 2).map((offer) => (
                                                        <a key={offer._id || `${offer.title}-${offer.imageUrl}`} href={offer.ctaLink || '/contact'} className="block overflow-hidden rounded-xl border border-slate-200 bg-white hover:shadow-xl hover:-translate-y-0.5 transition-all">
                                                            <img src={offer.imageUrl} alt={offer.title} className="w-full h-28 object-cover" />
                                                            <div className="p-3">
                                                                <div className="text-sm font-bold text-slate-800 line-clamp-2">{offer.title}</div>
                                                                <div className="mt-1 text-xs font-bold text-red-600">Explore Offer</div>
                                                            </div>
                                                        </a>
                                                    ))}
                                                    {activeDesktopOffers.length === 0 && (
                                                        <div className="text-xs text-slate-500 bg-white border border-dashed border-slate-300 rounded-xl px-3 py-4">
                                                            Latest offers will appear here soon.
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </nav>

                        <div className="hidden lg:flex items-center flex-shrink-0 gap-4 justify-end">
                            <button onClick={handleSearchClick} className="p-2 text-slate-600 hover:text-red-600 transition transform hover:scale-110"><Search className="w-5 h-5" /></button>
                            
                            <div className="flex items-center gap-2 flex-shrink-0">
                                <a href="/contact" className="bg-red-600 text-white px-4 py-2.5 rounded-lg font-bold text-sm hover:bg-red-700 transition shadow-lg shadow-red-600/20 flex items-center whitespace-nowrap">
                                    <Phone className="w-4 h-4 mr-2" /> Talk to Expert
                                </a>
                                <a href="/login" className="flex items-center gap-1.5 px-3 py-2.5 text-slate-700 hover:text-red-600 font-bold border border-slate-200 rounded-lg hover:bg-slate-50 whitespace-nowrap transition-all flex-shrink-0">
                                    <LogIn className="w-4 h-4" />
                                    <span>Login</span>
                                </a>
                            </div>
                        </div>
                        <div className="flex items-center gap-1 lg:hidden ml-auto">
                            <a href="/login" className="p-2 text-slate-700 hover:text-red-600 transition">
                                <LogIn className="w-6 h-6" />
                            </a>
                            <button className="p-2 text-slate-800 hover:bg-slate-100 rounded-lg transition" onClick={() => setIsMobileMenuOpen(true)}>
                                <Menu className="w-7 h-7" />
                            </button>
                        </div>
                    </div>
                </div>
            </header>
            <div className="h-[84px] lg:h-[132px]"></div>

            {/* MOBILE MENU */}
            <div className={`fixed inset-0 bg-white z-[60] transform transition-transform duration-300 lg:hidden overflow-y-auto ${isMobileMenuOpen ? 'translate-x-0' : 'translate-x-full'}`}>
                <div className="p-4 border-b border-slate-100 flex justify-between items-center sticky top-0 bg-white z-10">
                    <div className="flex items-center">
                        <img src="/logo.png" alt="VR HERE" className="h-8 w-auto object-contain mr-2" />
                        <span className="font-bold text-lg">Menu</span>
                    </div>
                    <button onClick={() => setIsMobileMenuOpen(false)} className="p-2 bg-slate-100 rounded-full hover:bg-red-100 hover:text-red-600 transition"><X className="w-6 h-6" /></button>
                </div>
                <div className="p-4 space-y-1">
                    <div className="border rounded-xl overflow-hidden border-slate-100 my-2">
                        <div className="bg-slate-50 px-4 py-3 font-bold text-lg flex justify-between items-center text-slate-900">Services <span className="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded-full">{menuConfig.length} Tabs</span></div>
                        <div className="divide-y divide-slate-100">
                            {menuConfig.map((service) => (
                                <div key={service.id} className="bg-white">
                                    <button onClick={() => setActiveMobileCategory(activeMobileCategory === service.id ? null : service.id)} className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-slate-50 transition">
                                        <div className="flex items-center space-x-3">
                                            <div className={`p-1.5 rounded-lg ${activeMobileCategory === service.id ? 'bg-red-600 text-white' : 'bg-slate-100 text-slate-600'}`}>
                                                <service.icon className="w-5 h-5" />
                                            </div>
                                            <span className={`text-sm font-bold ${activeMobileCategory === service.id ? 'text-red-600' : 'text-slate-700'}`}>{service.title}</span>
                                        </div>
                                        <ChevronDown className={`w-4 h-4 transition-transform ${activeMobileCategory === service.id ? 'rotate-180 text-red-600' : 'text-slate-400'}`} />
                                    </button>
                                    {activeMobileCategory === service.id && (
                                        <div className="bg-slate-50 px-4 pb-4 pt-2 space-y-2 pl-14 animate-fade-in">
                                            {service.columns.map((column, colIdx) => (
                                                <div key={`${service.id}-mobile-col-${colIdx}`} className="mb-3">
                                                    <div className="text-xs font-black uppercase tracking-wider text-slate-800 mb-1">{column.title}</div>
                                                    {(column.items || []).map((item, i) => (
                                                        <a href={getServiceLink(item)} key={`${service.id}-${colIdx}-${i}`} className="block text-sm text-slate-600 border-l-2 border-slate-200 pl-3 py-1 active:text-red-600 hover:text-red-600">
                                                            {item}
                                                        </a>
                                                    ))}
                                                </div>
                                            ))}
                                            <a href={`/all-services?category=${encodeURIComponent(service.id)}`} className="block text-sm font-bold text-red-600 border-l-2 border-red-200 pl-3 py-1 mt-2">
                                                View All Services
                                            </a>
                                            {((Array.isArray(service.offers) && service.offers.length > 0 ? service.offers : SAMPLE_OFFERS_BY_CATEGORY[service.id] || [])).slice(0, 1).map((offer) => (
                                                <a key={offer._id || offer.title} href={offer.ctaLink || '/contact'} className="block border rounded-lg border-slate-200 overflow-hidden bg-white mt-3">
                                                    <img src={offer.imageUrl} alt={offer.title} className="w-full h-28 object-cover" />
                                                    <div className="p-2 text-xs font-semibold text-slate-700">{offer.title}</div>
                                                </a>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            ))}
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
                            <h2 className="text-2xl font-extrabold text-white leading-none group-hover:text-red-500 transition-colors">VR HERE</h2>
                            <p className="text-[10px] text-red-500 font-bold tracking-widest uppercase mt-1">Business Solutions</p>
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
                            <Users className="w-4 h-4" />
                        </a>
                        <a href="#" className="p-2 bg-slate-800 rounded-full hover:bg-red-600 hover:text-white transition transform hover:scale-110 hover:-translate-y-1">
                            <Globe className="w-4 h-4" />
                        </a>
                    </div>
                </div>

                {/* Columns 2-4: Links Grid */}
                <div className="lg:col-span-9 grid md:grid-cols-3 gap-8">
                    <div>
                        <h3 className="text-red-500 font-bold text-sm uppercase tracking-wider mb-6">Start a Business</h3>
                        <ul className="space-y-3 text-sm">
                            <li><a href="/pvt-ltd-registration" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Private Limited Company</a></li>
                            <li><a href="/contact?service=LLP" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Limited Liability Partnership</a></li>
                            <li><a href="/contact?service=OPC" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">One Person Company</a></li>
                            <li><a href="/contact?service=Section8" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Section 8 Company</a></li>
                            <li><a href="/partnership-firm" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Partnership Firm</a></li>
                            <li><a href="/contact?service=Proprietorship" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Proprietorship</a></li>
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
                <p>&copy; {new Date().getFullYear()} VR HERE Business Management Solutions. All rights reserved.</p>
                <div className="flex space-x-6">
                    <a href="#" className="hover:text-white transition">Privacy Policy</a>
                    <a href="/terms-and-conditions" className="hover:text-white transition">Terms & Conditions</a>
                </div>
            </div>
        </div>
    </footer>
);
