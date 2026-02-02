import React, { useState, useEffect } from 'react';
import {
    Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
    Phone, Menu, X, ChevronDown, Clock, Award, Search, ArrowRight, CheckCircle2,
    Mail, MapPin, Quote, Star, Users, CheckCircle
} from 'lucide-react';

/* --- MENU DATA WITH LINKS --- */
export const getServiceLink = (serviceName) => {
    const map = {
        'Pvt Ltd / LLP / OPC': '/pvt-ltd-registration',
        'Partnership Firm': '/partnership-firm', // Assumed based on existing files or common naming
        'GST Reg & Returns': '/gst-registration',
    };
    // Partial matches or specific logic
    if (serviceName.includes('Partnership')) return '/partnership-firm';

    return map[serviceName] || `/contact?service=${encodeURIComponent(serviceName)}`;
};

export const MENU_DATA = [
    {
        id: 'machinery',
        title: 'Machinery & Industrial',
        icon: Factory,
        items: ['Machinery Sourcing', 'Vendor Verification', 'Turnkey Factory Setup', 'Technology Upgradation']
    },
    {
        id: 'iso',
        title: 'Certification & ISO',
        icon: Stamp,
        items: ['ISO 9001, 14001, 45001', 'ISO 27001 (Info Sec)', 'CE Marking & FDA', 'GMP / HACCP / Halal']
    },
    {
        id: 'accounting',
        title: 'Accounting & Tax',
        icon: Calculator,
        items: ['Cloud Accounting', 'GST Reg & Returns', 'Income Tax Filing', 'Statutory & Tax Audits']
    },
    {
        id: 'registration',
        title: 'Business Registration',
        icon: Briefcase,
        items: ['Pvt Ltd / LLP / OPC', 'Section 8 (NGO)', 'Start-up India Reg', 'FSSAI & Trade License']
    },
    {
        id: 'govt',
        title: 'Govt. Portals',
        icon: Globe,
        items: ['GeM Seller/OEM Reg', 'GeM Product Listing', 'TReDS', 'RERA Registration']
    },
    {
        id: 'msme',
        title: 'Ind. & MSME Loans',
        icon: IndianRupee,
        items: ['Project Reports (DPR)', 'Term Loans', 'CGTMSE & PMEGP', 'Subsidy Guidance']
    },
    {
        id: 'branding',
        title: 'Branding & Startup',
        icon: Lightbulb,
        items: ['Business Plans', 'Website & Branding', 'Vendor Empanelment', 'HR Policy & SOPs']
    },
    {
        id: 'utility',
        title: 'Utility Services',
        icon: MoreHorizontal,
        items: ['Trademark & IP', 'PAN / TAN Apps', 'Digital Marketing', 'Digital Signatures']
    }
];

export const SharedHeader = ({ isScrolled: externalIsScrolled }) => {
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    const [activeMobileCategory, setActiveMobileCategory] = useState(null);
    const [isServicesHovered, setIsServicesHovered] = useState(false);
    const [localIsScrolled, setLocalIsScrolled] = useState(false);

    // Use external scroll state if provided, otherwise handle internally
    const isScrolled = externalIsScrolled !== undefined ? externalIsScrolled : localIsScrolled;

    useEffect(() => {
        if (externalIsScrolled === undefined) {
            const handleScroll = () => {
                setLocalIsScrolled(window.scrollY > 20);
                if (isServicesHovered) setIsServicesHovered(false);
            };
            window.addEventListener('scroll', handleScroll);
            return () => window.removeEventListener('scroll', handleScroll);
        }
    }, [externalIsScrolled, isServicesHovered]);

    return (
        <>
            <div className="bg-slate-900 text-slate-400 text-xs py-2 px-4 hidden lg:block border-b border-slate-800">
                <div className="max-w-[1400px] mx-auto flex justify-between items-center">
                    <div className="flex space-x-6">
                        {/* ADDRESS REMOVED HERE */}
                        <span className="flex items-center hover:text-white transition cursor-default"><Clock className="w-3 h-3 mr-2 text-red-600" /> Mon - Sat: 10AM - 7PM</span>
                        <span className="flex items-center hover:text-white transition cursor-default"><Award className="w-3 h-3 mr-2 text-red-600" /> ISO 9001:2015 Certified</span>
                        <span className="flex items-center hover:text-white transition cursor-default text-green-500 font-bold"><CheckCircle className="w-3 h-3 mr-2" /> Digital Office Only</span>
                    </div>
                    <div className="flex items-center space-x-6">
                        <a href="mailto:vrherebms@gmail.com" className="flex items-center hover:text-red-500 transition"><Mail className="w-3 h-3 mr-2" /> vrherebms@gmail.com</a>
                        <a href="tel:+918008530606" className="flex items-center hover:text-red-500 font-bold transition"><Phone className="w-3 h-3 mr-2" /> +91 80085 30606</a>
                    </div>
                </div>
            </div>

            <header className={`sticky top-0 z-50 transition-all duration-300 w-full ${isScrolled ? 'bg-white/95 backdrop-blur-md shadow-lg py-2' : 'bg-white border-b border-slate-100 py-4'}`}>
                <div className="max-w-[1400px] mx-auto px-4 sm:px-6">
                    <div className="flex justify-between items-center relative">
                        {/* LOGO: Points to / (Home) */}
                        <a href="/" className="flex items-center flex-shrink-0 group cursor-pointer">
                            <div className="w-10 h-10 bg-black rounded-lg flex items-center justify-center mr-3 shadow-lg group-hover:bg-red-600 transition duration-300 relative overflow-hidden transform group-hover:scale-105">
                                <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition duration-300"></div>
                                <span className="text-white font-black text-xl tracking-tighter">VR</span>
                            </div>
                            <div className="flex flex-col">
                                <span className="text-2xl font-extrabold text-black leading-none tracking-tight group-hover:text-red-600 transition-colors">VR HERE</span>
                                <span className="text-[10px] font-bold text-red-600 uppercase tracking-widest mt-0.5">Business Solutions</span>
                            </div>
                        </a>

                        <nav className="hidden lg:flex items-center space-x-1">
                            <a href="/" className="px-4 py-2 text-sm font-bold text-slate-700 hover:text-red-600 rounded-full hover:bg-red-50 transition-all duration-300 hover:scale-105">Home</a>
                            <div className="relative px-2 py-4" onMouseEnter={() => setIsServicesHovered(true)} onMouseLeave={() => setIsServicesHovered(false)}>
                                <button className={`flex items-center px-4 py-2 text-sm font-bold rounded-full transition-all duration-300 hover:scale-105 group ${isServicesHovered ? 'bg-red-600 text-white shadow-lg shadow-red-600/30' : 'text-slate-700 hover:text-red-600 hover:bg-red-50'}`}>
                                    Services <ChevronDown className={`ml-1 w-4 h-4 transition-transform duration-300 ${isServicesHovered ? 'rotate-180' : ''}`} />
                                </button>
                                <div className={`absolute top-full left-1/2 -translate-x-1/2 w-[90vw] max-w-[1200px] bg-white rounded-2xl shadow-2xl border-t-4 border-red-600 overflow-hidden transition-all duration-300 origin-top z-50 ${isServicesHovered ? 'opacity-100 translate-y-0 visible' : 'opacity-0 translate-y-4 invisible pointer-events-none'}`}>
                                    <div className="flex">
                                        <div className="w-64 bg-slate-50 p-8 flex flex-col justify-between border-r border-slate-100">
                                            <div>
                                                <h3 className="text-xl font-extrabold text-slate-900 mb-2">Our Expertise</h3>
                                                <p className="text-sm text-slate-500 mb-6">From registration to expansion, we handle all your business needs under one roof.</p>
                                                <div className="space-y-3">
                                                    <div className="flex items-center text-xs font-semibold text-slate-600"><CheckCircle2 className="w-4 h-4 text-green-500 mr-2" /> 100% Online Process</div>
                                                    <div className="flex items-center text-xs font-semibold text-slate-600"><CheckCircle2 className="w-4 h-4 text-green-500 mr-2" /> Expert CA/CS Team</div>
                                                </div>
                                            </div>
                                            <a href="/contact" className="block w-full py-3 bg-black text-white text-center text-sm font-bold rounded-lg hover:bg-slate-800 transition transform hover:-translate-y-1 shadow-lg">Get Custom Quote</a>
                                        </div>
                                        <div className="flex-1 p-8 bg-white">
                                            <div className="grid grid-cols-4 gap-6">
                                                {MENU_DATA.map((service) => (
                                                    <div key={service.id} className="group/item hover:bg-slate-50 p-3 rounded-lg transition-colors">
                                                        <div className="flex items-center space-x-3 mb-2">
                                                            <div className="p-2 bg-red-50 text-red-600 rounded-lg group-hover/item:bg-red-600 group-hover/item:text-white transition-colors duration-300 shadow-sm">
                                                                <service.icon className="w-6 h-6" />
                                                            </div>
                                                            <h4 className="font-bold text-slate-900 text-sm leading-tight group-hover/item:text-red-600 transition-colors">{service.title}</h4>
                                                        </div>
                                                        <ul className="space-y-1 ml-11 border-l-2 border-slate-100 pl-3 group-hover/item:border-red-200 transition-colors">
                                                            {service.items.slice(0, 3).map((item, i) => (
                                                                <li key={i}>
                                                                    <a href={getServiceLink(item)} className="block text-xs font-medium text-slate-500 hover:text-red-600 transition-colors truncate">
                                                                        {item}
                                                                    </a>
                                                                </li>
                                                            ))}
                                                        </ul>
                                                        <div className="mt-2 ml-11 pl-3">
                                                            <a href={`/contact?service=${encodeURIComponent(service.title)}`} className="text-[10px] font-bold text-red-500 hover:text-red-700 uppercase tracking-wide">View All &rarr;</a>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <button className="px-4 py-2 text-sm font-bold text-slate-700 hover:text-red-600 rounded-full hover:bg-red-50 transition-all duration-300 hover:scale-105">Pricing</button>
                        </nav>

                        <div className="hidden lg:flex items-center space-x-4">
                            <button className="p-2 text-slate-600 hover:text-red-600 transition transform hover:scale-110"><Search className="w-5 h-5" /></button>
                            <a href="/contact" className="bg-red-600 text-white px-6 py-2.5 rounded-lg font-bold text-sm hover:bg-red-700 transition shadow-lg shadow-red-600/20 flex items-center transform hover:-translate-y-1 active:scale-95 group">
                                <Phone className="w-4 h-4 mr-2 group-hover:rotate-12 transition-transform" /> Talk to Expert
                            </a>
                        </div>
                        <button className="lg:hidden p-2 text-slate-800 hover:bg-slate-100 rounded-lg transition" onClick={() => setIsMobileMenuOpen(true)}>
                            <Menu className="w-7 h-7" />
                        </button>
                    </div>
                </div>
            </header>

            {/* MOBILE MENU */}
            <div className={`fixed inset-0 bg-white z-[60] transform transition-transform duration-300 lg:hidden overflow-y-auto ${isMobileMenuOpen ? 'translate-x-0' : 'translate-x-full'}`}>
                <div className="p-4 border-b border-slate-100 flex justify-between items-center sticky top-0 bg-white z-10">
                    <div className="flex items-center">
                        <div className="w-8 h-8 bg-black rounded flex items-center justify-center mr-2"><span className="text-white font-bold">VR</span></div>
                        <span className="font-bold text-lg">Menu</span>
                    </div>
                    <button onClick={() => setIsMobileMenuOpen(false)} className="p-2 bg-slate-100 rounded-full hover:bg-red-100 hover:text-red-600 transition"><X className="w-6 h-6" /></button>
                </div>
                <div className="p-4 space-y-1">
                    <a href="/" className="block w-full text-left px-4 py-3 text-lg font-bold text-slate-800 hover:bg-slate-50 rounded-xl">Home</a>
                    <div className="border rounded-xl overflow-hidden border-slate-100 my-2">
                        <div className="bg-slate-50 px-4 py-3 font-bold text-lg flex justify-between items-center text-slate-900">Services <span className="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded-full">8 Cats</span></div>
                        <div className="divide-y divide-slate-100">
                            {MENU_DATA.map((service) => (
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
                                            {service.items.map((item, i) => (
                                                <a href={getServiceLink(item)} key={i} className="block text-sm text-slate-600 border-l-2 border-slate-200 pl-3 py-1 active:text-red-600 hover:text-red-600">
                                                    {item}
                                                </a>
                                            ))}
                                            <a href={`/contact?service=${encodeURIComponent(service.title)}`} className="block text-sm font-bold text-red-600 border-l-2 border-red-200 pl-3 py-1 mt-2">
                                                View All Services
                                            </a>
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

export const SharedFooter = () => (
    <footer className="bg-[#0f172a] text-slate-300 pt-16 pb-8 border-t border-slate-800 font-sans">
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
                    <a href="#" className="hover:text-white transition">Terms & Conditions</a>
                </div>
            </div>
        </div>
    </footer>
);
