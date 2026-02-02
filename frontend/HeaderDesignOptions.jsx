import React, { useState } from 'react';
import {
    Phone, Search, ChevronDown, User, LogIn, Menu, X,
    MapPin, Mail, ArrowRight, ShieldCheck, Gem
} from 'lucide-react';
import { MENU_DATA, getServiceLink } from './components/SharedComponents';

// --- MOCK LOGO COMPONENT ---
const Logo = ({ theme = 'dark' }) => (
    <div className="flex items-center gap-3 cursor-pointer">
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center font-black text-xl shadow-lg ${theme === 'dark' ? 'bg-black text-white' : 'bg-red-600 text-white'}`}>
            VR
        </div>
        <div className="flex flex-col">
            <span className={`text-2xl font-black leading-none tracking-tight ${theme === 'dark' ? 'text-slate-900' : 'text-white'}`}>VR HERE</span>
            <span className={`text-[10px] font-bold tracking-widest uppercase ${theme === 'dark' ? 'text-red-600' : 'text-slate-200'}`}>Business Solutions</span>
        </div>
    </div>
);

// --- OPTION 1: "MODERN SAAS" (Clean, No Top Bar, Floating) ---
const HeaderOption1 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-slate-50 p-8 border-b-4 border-slate-200 relative">
            <span className="absolute top-0 left-0 bg-slate-200 text-slate-600 px-3 py-1 text-xs font-bold uppercase">Option 1: Modern SaaS</span>

            <header className="bg-white rounded-2xl shadow-xl border border-slate-100 px-6 py-4 max-w-[1400px] mx-auto flex items-center justify-between relative mt-6">
                <Logo theme="dark" />

                {/* CENTER: SEARCH & NAV */}
                <div className="flex-1 max-w-2xl mx-8 flex items-center gap-6">
                    <div className="relative flex-1 group">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                        <input type="text" placeholder="Search services..." className="w-full bg-slate-50 border border-slate-200 rounded-full py-2.5 pl-10 pr-4 text-sm focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 transition-all" />
                    </div>

                    {/* SIMPLE DROPDOWN TRIGGER */}
                    <div className="relative" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                        <button className={`flex items-center text-sm font-bold transition-colors ${isHovered ? 'text-red-600' : 'text-slate-700'}`}>
                            Our Services <ChevronDown className={`ml-1 w-4 h-4 transition-transform ${isHovered ? 'rotate-180' : ''}`} />
                        </button>
                        {/* Placeholder for Dropdown Content */}
                        {isHovered && (
                            <div className="absolute top-full left-1/2 -translate-x-1/2 mt-4 w-64 bg-white rounded-xl shadow-2xl border border-slate-100 p-4 text-center text-xs text-slate-400 z-50">
                                (Full Mega Menu Content would go here)
                            </div>
                        )}
                    </div>
                </div>

                {/* RIGHT: ACTIONS */}
                <div className="flex items-center gap-4">
                    <button className="flex items-center gap-2 text-slate-600 hover:text-red-600 font-bold text-sm px-3 py-2 rounded-lg hover:bg-red-50 transition-colors">
                        <LogIn className="w-4 h-4" /> <span>Login</span>
                    </button>
                    <button className="bg-black text-white px-6 py-2.5 rounded-xl font-bold text-sm hover:bg-slate-800 transition shadow-lg shadow-slate-200 flex items-center gap-2">
                        <Phone className="w-4 h-4" /> <span>Talk to Expert</span>
                    </button>
                </div>
            </header>
        </div>
    );
};

// --- OPTION 2: "CORPORATE TRUST" (Structured, Dark Top, Professional) ---
const HeaderOption2 = () => {
    return (
        <div className="bg-slate-100 p-8 border-b-4 border-slate-200 relative">
            <span className="absolute top-0 left-0 bg-slate-200 text-slate-600 px-3 py-1 text-xs font-bold uppercase">Option 2: Corporate Trust</span>

            {/* HEADER CONTAINER */}
            <div className="bg-white shadow-sm mt-6">
                {/* TOP BAR */}
                <div className="bg-[#0f172a] text-slate-400 text-[11px] font-medium py-2 px-8 flex justify-between items-center">
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
                <div className="px-8 py-4 flex items-center justify-between max-w-[1400px] mx-auto">
                    <div className="flex items-center gap-12">
                        <Logo theme="dark" />

                        {/* LEFT ALIGNED NAV */}
                        <nav className="hidden lg:flex items-center gap-1">
                            <button className="px-4 py-2 text-sm font-bold text-slate-700 hover:text-red-600 flex items-center gap-1">
                                Explore Services <ChevronDown className="w-4 h-4 text-slate-400" />
                            </button>
                        </nav>
                    </div>

                    <div className="flex items-center gap-6">
                        {/* SEARCH ICON ONLY */}
                        <button className="p-2 text-slate-400 hover:text-red-600 transition"><Search className="w-5 h-5" /></button>

                        <div className="h-6 w-px bg-slate-200"></div>

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

                        <button className="bg-red-600 text-white px-6 py-2.5 rounded-lg font-bold text-sm hover:bg-red-700 transition shadow-lg shadow-red-600/20">
                            Book Consultant
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

// --- OPTION 3: "HYBRID SPLIT" (Logo Center, Actions Sides, High Contrast) ---
const HeaderOption3 = () => {
    return (
        <div className="bg-white p-8 relative">
            <span className="absolute top-0 left-0 bg-slate-200 text-slate-600 px-3 py-1 text-xs font-bold uppercase">Option 3: Hybrid Split</span>

            <header className="mt-6 bg-[#1e293b] text-white py-4 px-8 rounded-t-2xl max-w-[1400px] mx-auto relative overflow-hidden">
                {/* DECORATION */}
                <div className="absolute top-0 right-0 w-64 h-64 bg-red-600 rounded-full blur-[80px] opacity-20 -mr-16 -mt-16 pointer-events-none"></div>

                <div className="flex justify-between items-center relative z-10">
                    {/* LEFT: NAV */}
                    <div className="flex items-center gap-6">
                        <div className="bg-white/10 p-2 rounded-lg cursor-pointer hover:bg-white/20 transition">
                            <Menu className="w-6 h-6 text-white" />
                        </div>
                        <button className="flex items-center gap-2 text-sm font-bold text-slate-200 hover:text-white transition">
                            All Services <ChevronDown className="w-4 h-4 opacity-50" />
                        </button>
                        <div className="relative hidden md:block">
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
                        <button className="flex items-center gap-2 text-slate-300 hover:text-white font-medium text-sm transition">
                            <LogIn className="w-4 h-4" /> <span className="hidden sm:inline">Login</span>
                        </button>
                        <button className="bg-white text-slate-900 px-5 py-2 rounded-lg font-bold text-sm hover:bg-slate-100 transition flex items-center gap-2">
                            <span>Get Started</span> <ArrowRight className="w-4 h-4" />
                        </button>
                    </div>
                </div>
            </header>
            <div className="bg-slate-100 py-2 px-8 rounded-b-2xl border-x border-b border-slate-200 max-w-[1400px] mx-auto flex gap-6 overflow-x-auto text-[11px] font-bold uppercase tracking-wide text-slate-500">
                <span className="hover:text-red-600 cursor-pointer whitespace-nowrap">Startup Registration</span>
                <span className="hover:text-red-600 cursor-pointer whitespace-nowrap">GST & Tax</span>
                <span className="hover:text-red-600 cursor-pointer whitespace-nowrap">Industrial Setup</span>
                <span className="hover:text-red-600 cursor-pointer whitespace-nowrap">Licenses</span>
                <span className="text-red-600 cursor-pointer whitespace-nowrap flex-1 text-right flex items-center justify-end gap-1">View Full Catalog <ArrowRight className="w-3 h-3" /></span>
            </div>
        </div>
    );
};

const HeaderDesignOptions = () => {
    return (
        <div className="min-h-screen bg-slate-50 space-y-12 pb-20 font-sans text-slate-800">
            <div className="bg-black text-white py-12 px-6 text-center">
                <h1 className="text-4xl font-black mb-4">Header Design Concepts</h1>
                <p className="text-slate-400 max-w-xl mx-auto">
                    Design exploration based on requirements:
                    <br />
                    <span className="text-red-400">• No "Home" / "Pricing" Links</span> &nbsp;|&nbsp;
                    <span className="text-green-400">• Added Login Icon</span> &nbsp;|&nbsp;
                    <span className="text-blue-400">• Updated Aesthetics</span>
                </p>
            </div>

            <div className="max-w-[1600px] mx-auto px-4 space-y-20">
                <HeaderOption1 />
                <HeaderOption2 />
                <HeaderOption3 />
            </div>
        </div>
    );
};

export default HeaderDesignOptions;
