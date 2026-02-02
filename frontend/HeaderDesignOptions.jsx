import React, { useState } from 'react';
import {
    Phone, Search, ChevronDown, User, LogIn, Menu, X,
    MapPin, Mail, ArrowRight, ShieldCheck, Gem,
    Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal
} from 'lucide-react';
import { MENU_DATA, getServiceLink } from './components/SharedComponents';

// --- SHARED COMPONENTS ---

const Logo = ({ theme = 'dark' }) => (
    <div className="flex items-center gap-3 cursor-pointer select-none">
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center font-black text-xl shadow-lg ${theme === 'dark' ? 'bg-black text-white' : 'bg-red-600 text-white'}`}>
            VR
        </div>
        <div className="flex flex-col">
            <span className={`text-2xl font-black leading-none tracking-tight ${theme === 'dark' ? 'text-slate-900' : 'text-white'}`}>VR HERE</span>
            <span className={`text-[10px] font-bold tracking-widest uppercase ${theme === 'dark' ? 'text-red-600' : 'text-slate-200'}`}>Business Solutions</span>
        </div>
    </div>
);

const MegaMenu = ({ isOpen }) => {
    if (!isOpen) return null;
    return (
        <div className="absolute top-full left-1/2 -translate-x-1/2 mt-4 w-[90vw] max-w-[1000px] bg-white rounded-2xl shadow-2xl border-t-4 border-red-600 overflow-hidden animate-fade-in z-[100] text-left">
            <div className="flex">
                <div className="w-64 bg-slate-50 p-6 flex flex-col justify-between border-r border-slate-100 hidden md:flex">
                    <div>
                        <h3 className="text-lg font-black text-slate-900 mb-2">Our Expertise</h3>
                        <p className="text-xs text-slate-500 mb-6 leading-relaxed">Everything from company registration to industrial setup under one roof.</p>
                        <div className="space-y-3">
                            <div className="flex items-center text-[10px] font-bold uppercase tracking-wider text-slate-600"><span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span> 100% Online</div>
                            <div className="flex items-center text-[10px] font-bold uppercase tracking-wider text-slate-600"><span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span> Expert Team</div>
                        </div>
                    </div>
                </div>
                <div className="flex-1 p-6 grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-6 max-h-[60vh] overflow-y-auto">
                    {MENU_DATA.map((service) => (
                        <div key={service.id} className="group/item">
                            <div className="flex items-center space-x-2 mb-2">
                                <service.icon className="w-4 h-4 text-red-600" />
                                <h4 className="font-bold text-slate-900 text-xs uppercase tracking-wide group-hover/item:text-red-600 transition-colors">{service.title}</h4>
                            </div>
                            <ul className="space-y-1.5 border-l border-slate-100 pl-3">
                                {service.items.map((item, i) => (
                                    <li key={i}>
                                        <a href={getServiceLink(item)} className="block text-xs text-slate-500 hover:text-red-600 hover:font-bold transition-all truncate">
                                            {item}
                                        </a>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

// --- DUMMY CONTENT SCROLLER ---
const PageContent = () => (
    <div className="max-w-4xl mx-auto py-20 px-4 space-y-12 opacity-30 pointer-events-none select-none grayscale">
        <div className="h-64 bg-slate-200 rounded-3xl w-full"></div>
        <div className="grid grid-cols-3 gap-8">
            <div className="h-40 bg-slate-200 rounded-2xl"></div>
            <div className="h-40 bg-slate-200 rounded-2xl"></div>
            <div className="h-40 bg-slate-200 rounded-2xl"></div>
        </div>
        <div className="h-96 bg-slate-200 rounded-3xl w-full"></div>
    </div>
);


// --- OPTION 1: "MODERN SAAS" (Clean, No Top Bar, Floating) ---
const HeaderOption1 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-slate-50 relative h-[800px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide">
            <div className="sticky top-0 z-10 p-6 pointer-events-none">
                <span className="absolute top-0 left-0 bg-slate-800 text-white px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20 pointer-events-auto">Option 1: Modern SaaS (Floating)</span>

                <header className="bg-white/90 backdrop-blur-md rounded-2xl shadow-xl border border-white/50 px-6 py-3 max-w-[1400px] mx-auto flex items-center justify-between pointer-events-auto transition-all">
                    <Logo theme="dark" />

                    <div className="flex-1 max-w-2xl mx-8 flex items-center gap-6">
                        <div className="relative flex-1 group hidden md:block">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                            <input type="text" placeholder="Search services..." className="w-full bg-slate-100 border-transparent hover:bg-white hover:border-slate-200 focus:bg-white border focus:border-red-500 rounded-full py-2.5 pl-10 pr-4 text-xs font-medium focus:outline-none transition-all" />
                        </div>

                        <div className="relative" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                            <button className={`flex items-center text-sm font-bold transition-colors py-4 ${isHovered ? 'text-red-600' : 'text-slate-700'}`}>
                                Our Services <ChevronDown className={`ml-1 w-4 h-4 transition-transform ${isHovered ? 'rotate-180' : ''}`} />
                            </button>
                            <MegaMenu isOpen={isHovered} />
                        </div>
                    </div>

                    <div className="flex items-center gap-4">
                        <button className="flex items-center gap-2 text-slate-600 hover:text-red-600 font-bold text-xs px-3 py-2 rounded-lg hover:bg-red-50 transition-colors">
                            <LogIn className="w-4 h-4" /> <span>Login</span>
                        </button>
                        <button className="bg-black text-white px-5 py-2.5 rounded-xl font-bold text-xs hover:bg-slate-800 transition shadow-lg shadow-slate-200 flex items-center gap-2 transform hover:-translate-y-0.5">
                            <Phone className="w-3.5 h-3.5" /> <span>Talk to Expert</span>
                        </button>
                    </div>
                </header>
            </div>
            <PageContent />
        </div>
    );
};

// --- OPTION 2: "CORPORATE TRUST" (Structured, Dark Top, Professional) ---
const HeaderOption2 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-slate-100 relative h-[800px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide">
            <span className="absolute top-0 left-0 bg-slate-800 text-white px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20">Option 2: Corporate Trust (Sticky)</span>

            {/* HEADER CONTAINER */}
            <div className="bg-white shadow-sm sticky top-0 z-50">
                {/* TOP BAR */}
                <div className="bg-[#0f172a] text-slate-400 text-[10px] font-bold uppercase tracking-wider py-2 px-8 flex justify-between items-center">
                    <div className="flex gap-6">
                        <span className="flex items-center"><ShieldCheck className="w-3 h-3 mr-2 text-green-500" /> 100% Digital Process</span>
                        <span className="flex items-center"><Gem className="w-3 h-3 mr-2 text-blue-500" /> ISO 9001 Certified</span>
                    </div>
                    <div className="flex gap-6">
                        <a href="#" className="hover:text-white transition">Support</a>
                        <a href="#" className="hover:text-white transition">Partner with us</a>
                    </div>
                </div>

                {/* MAIN BAR */}
                <div className="px-8 py-3 flex items-center justify-between max-w-[1400px] mx-auto relative">
                    <div className="flex items-center gap-12">
                        <Logo theme="dark" />

                        <nav className="hidden lg:flex items-center gap-1 h-full" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                            <button className={`px-4 py-4 text-sm font-bold flex items-center gap-1 transition-colors ${isHovered ? 'text-red-600 bg-red-50 rounded-t-lg' : 'text-slate-700'}`}>
                                Explore Services <ChevronDown className={`w-4 h-4 transition-transform ${isHovered ? 'rotate-180' : ''}`} />
                            </button>
                            <MegaMenu isOpen={isHovered} />
                        </nav>
                    </div>

                    <div className="flex items-center gap-6">
                        <button className="p-2 text-slate-400 hover:text-red-600 transition"><Search className="w-5 h-5" /></button>

                        <div className="h-8 w-px bg-slate-100"></div>

                        {/* LOGIN WITH AVATAR FEEL */}
                        <button className="flex items-center gap-3 group">
                            <div className="w-9 h-9 bg-slate-100 rounded-full flex items-center justify-center text-slate-600 group-hover:bg-red-100 group-hover:text-red-600 transition-colors">
                                <User className="w-5 h-5" />
                            </div>
                            <div className="text-left hidden xl:block">
                                <p className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Client Portal</p>
                                <p className="text-xs font-bold text-slate-800 group-hover:text-red-600 transition-colors">Login / Sign Up</p>
                            </div>
                        </button>

                        <button className="bg-red-600 text-white px-6 py-2.5 rounded-lg font-bold text-xs hover:bg-red-700 transition shadow-lg shadow-red-600/20 uppercase tracking-wide">
                            Book Consultant
                        </button>
                    </div>
                </div>
            </div>
            <PageContent />
        </div>
    );
};

// --- OPTION 3: "HYBRID SPLIT" (Logo Center, Actions Sides, High Contrast) ---
const HeaderOption3 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-white relative h-[800px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide">
            <span className="absolute top-0 left-0 bg-slate-800 text-white px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20">Option 3: Hybrid Split (Floating)</span>

            <div className="sticky top-0 z-50 p-4">
                <header className="bg-[#1e293b] text-white py-3 px-8 rounded-t-2xl max-w-[1400px] mx-auto relative shadow-2xl">
                    <div className="flex justify-between items-center relative z-10">
                        {/* LEFT: NAV */}
                        <div className="flex items-center gap-6">
                            <div className="bg-white/10 p-2 rounded-lg cursor-pointer hover:bg-white/20 transition">
                                <Menu className="w-5 h-5 text-white" />
                            </div>

                            <div className="relative" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                                <button className={`flex items-center gap-2 text-sm font-bold transition py-2 ${isHovered ? 'text-white' : 'text-slate-300 hover:text-white'}`}>
                                    All Services <ChevronDown className="w-4 h-4 opacity-50" />
                                </button>
                                <MegaMenu isOpen={isHovered} />
                            </div>

                            <div className="relative hidden lg:block ml-4">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
                                <input type="text" placeholder="Find service..." className="bg-slate-800 border-none rounded-full py-1.5 pl-9 pr-4 text-xs focus:ring-1 focus:ring-red-500 text-slate-200 w-48 transition-all focus:w-64" />
                            </div>
                        </div>

                        {/* CENTER: LOGO */}
                        <div className="absolute left-1/2 top-1/2 -translate-x-1/2">
                            <div className="flex items-center gap-2">
                                <div className="w-8 h-8 bg-red-600 rounded-lg flex items-center justify-center font-black text-white text-lg shadow-lg shadow-red-900/50">VR</div>
                                <span className="text-xl font-bold tracking-tight">VR HERE</span>
                            </div>
                        </div>

                        {/* RIGHT: LOGIN & CTA */}
                        <div className="flex items-center gap-5">
                            <button className="flex items-center gap-2 text-slate-300 hover:text-white font-medium text-xs transition">
                                <LogIn className="w-4 h-4" /> <span className="hidden sm:inline">Login</span>
                            </button>
                            <button className="bg-white text-slate-900 px-5 py-2 rounded-lg font-bold text-xs hover:bg-slate-100 transition flex items-center gap-2">
                                <span>Get Started</span> <ArrowRight className="w-3.5 h-3.5" />
                            </button>
                        </div>
                    </div>
                </header>
                <div className="bg-slate-100 py-2.5 px-8 rounded-b-2xl border-x border-b border-slate-200 max-w-[1400px] mx-auto flex gap-6 overflow-x-auto text-[10px] font-bold uppercase tracking-wide text-slate-500 shadow-lg">
                    <span className="hover:text-red-600 cursor-pointer whitespace-nowrap">Startup Registration</span>
                    <span className="hover:text-red-600 cursor-pointer whitespace-nowrap">GST & Tax</span>
                    <span className="hover:text-red-600 cursor-pointer whitespace-nowrap">Industrial Setup</span>
                    <span className="hover:text-red-600 cursor-pointer whitespace-nowrap">Licenses</span>
                    <span className="text-red-600 cursor-pointer whitespace-nowrap flex-1 text-right flex items-center justify-end gap-1">View Full Catalog <ArrowRight className="w-3 h-3" /></span>
                </div>
            </div>
            <PageContent />
        </div>
    );
};

const HeaderDesignOptions = () => {
    return (
        <div className="min-h-screen bg-slate-900 space-y-12 pb-20 font-sans text-slate-800">
            <div className="bg-black text-white py-12 px-6 text-center border-b border-slate-800">
                <h1 className="text-4xl font-black mb-4">Header Design Concepts</h1>
                <p className="text-slate-400 max-w-xl mx-auto">
                    Design exploration based on requirements:
                    <br />
                    <span className="text-red-400">• No "Home" / "Pricing" Links</span> &nbsp;|&nbsp;
                    <span className="text-green-400">• Added Login Icon</span> &nbsp;|&nbsp;
                    <span className="text-blue-400">• Full Mega Menu Enabled</span>
                </p>
            </div>

            <div className="max-w-[1600px] mx-auto px-4 grid grid-cols-1 gap-16">
                <HeaderOption1 />
                <HeaderOption2 />
                <HeaderOption3 />
            </div>
        </div>
    );
};

export default HeaderDesignOptions;
