import React, { useState, useEffect, useRef } from 'react';
import {
    Phone, Search, ChevronDown, User, LogIn, Menu, X,
    MapPin, Mail, ArrowRight, ShieldCheck, Gem,
    Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
    CreditCard, FileText, CheckCircle
} from 'lucide-react';
import { MENU_DATA, getServiceLink } from './components/SharedComponents';

// --- UTILS: FLATTEN MENU DATA FOR SEARCH ---
const getAllServices = () => {
    let services = [];
    MENU_DATA.forEach(cat => {
        cat.items.forEach(item => {
            services.push({ name: item, category: cat.title, link: getServiceLink(item) });
        });
    });
    // Add some common keywords manually for better UX
    services.push({ name: 'Private Limited Registration', category: 'Business Registration', link: '/pvt-ltd-registration' });
    services.push({ name: 'GST Registration', category: 'Accounting', link: '/gst-registration' });
    services.push({ name: 'Trademark', category: 'Utility', link: '/contact?service=Trademark' });
    return services;
};

const ALL_SERVICES = getAllServices();

// --- SHARED COMPONENTS ---

const Logo = ({ theme = 'dark', size = 'normal' }) => (
    <div className="flex items-center gap-3 cursor-pointer select-none">
        <div className={`rounded-xl flex items-center justify-center font-black shadow-lg ${theme === 'dark' ? 'bg-black text-white' : 'bg-red-600 text-white'} ${size === 'large' ? 'w-12 h-12 text-2xl' : 'w-10 h-10 text-xl'}`}>
            VR
        </div>
        <div className="flex flex-col justify-center">
            <span className={`font-black leading-none tracking-tight ${theme === 'dark' ? 'text-slate-900' : 'text-white'} ${size === 'large' ? 'text-3xl' : 'text-2xl'}`}>VR HERE</span>
            <span className={`font-bold tracking-widest uppercase ${theme === 'dark' ? 'text-red-600' : 'text-slate-200'} ${size === 'large' ? 'text-xs' : 'text-[10px]'}`}>Business Solutions</span>
        </div>
    </div>
);

const FunctionalSearch = ({ variant = 'default' }) => {
    const [query, setQuery] = useState('');
    const [suggestions, setSuggestions] = useState([]);
    const [isOpen, setIsOpen] = useState(false);
    const wrapperRef = useRef(null);

    useEffect(() => {
        const handleClickOutside = (event) => {
            if (wrapperRef.current && !wrapperRef.current.contains(event.target)) {
                setIsOpen(false);
            }
        };
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, [wrapperRef]);

    const handleSearch = (e) => {
        const val = e.target.value;
        setQuery(val);
        if (val.length > 1) {
            const filtered = ALL_SERVICES.filter(s =>
                s.name.toLowerCase().includes(val.toLowerCase()) ||
                s.category.toLowerCase().includes(val.toLowerCase())
            ).slice(0, 6); // Limit to top 6
            setSuggestions(filtered);
            setIsOpen(true);
        } else {
            setSuggestions([]);
            setIsOpen(false);
        }
    };

    // STYLES BASED ON VARIANT
    const containerClasses = variant === 'dark'
        ? "bg-slate-800 border-slate-700 text-white"
        : "bg-slate-100 border-slate-200 text-slate-900 focus-within:bg-white focus-within:ring-2 focus-within:ring-red-100 focus-within:border-red-500";

    const inputClasses = variant === 'dark'
        ? "text-white placeholder:text-slate-400"
        : "text-slate-900 placeholder:text-slate-500";

    return (
        <div className="relative w-full max-w-lg z-[60]" ref={wrapperRef}>
            <div className={`flex items-center px-4 py-2.5 rounded-full border transition-all duration-300 ${containerClasses}`}>
                <Search className={`w-4 h-4 mr-3 ${variant === 'dark' ? 'text-slate-400' : 'text-slate-500'}`} />
                <input
                    type="text"
                    placeholder="Search for 'GST', 'Company', 'Loans'..."
                    className={`bg-transparent border-none outline-none w-full text-sm font-medium ${inputClasses}`}
                    value={query}
                    onChange={handleSearch}
                    onFocus={() => query.length > 1 && setIsOpen(true)}
                />
                {query && <X className="w-4 h-4 text-slate-400 cursor-pointer hover:text-red-500" onClick={() => { setQuery(''); setIsOpen(false); }} />}
            </div>

            {/* SUGGESTIONS DROPDOWN */}
            {isOpen && suggestions.length > 0 && (
                <div className="absolute top-full left-0 right-0 mt-2 bg-white rounded-xl shadow-2xl border border-slate-100 overflow-hidden animate-fade-in">
                    <div className="py-2">
                        {suggestions.map((s, i) => (
                            <a href={s.link} key={i} className="flex items-center justify-between px-4 py-3 hover:bg-slate-50 transition-colors group">
                                <div className="flex items-center">
                                    <div className="p-1.5 bg-slate-100 rounded text-slate-500 mr-3 group-hover:bg-red-50 group-hover:text-red-600 transition">
                                        <Search className="w-3.5 h-3.5" />
                                    </div>
                                    <div>
                                        <div className="text-sm font-bold text-slate-800 group-hover:text-red-700">{s.name}</div>
                                        <div className="text-[10px] text-slate-400 font-medium uppercase tracking-wider">{s.category}</div>
                                    </div>
                                </div>
                                <ArrowRight className="w-4 h-4 text-slate-300 group-hover:text-red-500 -translate-x-2 group-hover:translate-x-0 transition-all opacity-0 group-hover:opacity-100" />
                            </a>
                        ))}
                    </div>
                    <div className="bg-slate-50 px-4 py-2 border-t border-slate-100 text-[10px] font-bold text-slate-400 text-center uppercase tracking-wider">
                        Press Enter to see all results
                    </div>
                </div>
            )}
        </div>
    );
};

const MegaMenu = ({ isOpen }) => {
    if (!isOpen) return null;
    return (
        <div className="absolute top-full left-0 w-full pt-4 animate-fade-in z-[50]">
            <div className="bg-white rounded-b-3xl shadow-2xl border-t border-slate-100 overflow-hidden">
                <div className="max-w-[1400px] mx-auto flex">
                    {/* SIDEBAR */}
                    <div className="w-72 bg-slate-50 p-8 flex flex-col justify-between border-r border-slate-100">
                        <div>
                            <h3 className="text-2xl font-black text-slate-900 mb-2">Our Expertise</h3>
                            <p className="text-sm text-slate-500 mb-8 leading-relaxed">End-to-end business solutions from registration to industrial expansion.</p>
                            <div className="space-y-4">
                                <div className="flex items-center text-xs font-bold uppercase tracking-wider text-slate-700 bg-white p-3 rounded-lg border border-slate-200 shadow-sm"><CheckCircle className="w-4 h-4 text-green-500 mr-3" /> 100% Online Process</div>
                                <div className="flex items-center text-xs font-bold uppercase tracking-wider text-slate-700 bg-white p-3 rounded-lg border border-slate-200 shadow-sm"><CheckCircle className="w-4 h-4 text-green-500 mr-3" /> Expert CA/CS Team</div>
                            </div>
                        </div>
                        <button className="w-full py-3 bg-black text-white text-sm font-bold rounded-lg hover:bg-slate-800 transition shadow-lg mt-8">View All Services</button>
                    </div>
                    {/* GRID */}
                    <div className="flex-1 p-8 grid grid-cols-4 gap-8">
                        {MENU_DATA.map((service) => (
                            <div key={service.id} className="group/item">
                                <a href={`/contact?service=${encodeURIComponent(service.title)}`} className="flex items-center space-x-2 mb-3 group-hover/item:translate-x-1 transition-transform cursor-pointer">
                                    <div className="p-1.5 bg-red-50 text-red-600 rounded-md group-hover/item:bg-red-600 group-hover/item:text-white transition-colors">
                                        <service.icon className="w-4 h-4" />
                                    </div>
                                    <h4 className="font-bold text-slate-900 text-sm group-hover/item:text-red-700 transition-colors">{service.title}</h4>
                                </a>
                                <ul className="space-y-2 border-l-2 border-slate-100 pl-4 group-hover/item:border-red-100 transition-colors">
                                    {service.items.map((item, i) => (
                                        <li key={i}>
                                            <a href={getServiceLink(item)} className="block text-xs font-medium text-slate-500 hover:text-red-600 hover:translate-x-1 transition-all">
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
        </div>
    );
};

const PageContent = () => (
    <div className="max-w-7xl mx-auto py-20 px-4 space-y-12 opacity-20 pointer-events-none select-none grayscale origin-top">
        <div className="h-96 bg-slate-300 rounded-3xl w-full flex items-center justify-center text-6xl font-black text-slate-400">HERO BANNER</div>
        <div className="grid grid-cols-3 gap-8">
            <div className="h-64 bg-slate-300 rounded-2xl"></div>
            <div className="h-64 bg-slate-300 rounded-2xl"></div>
            <div className="h-64 bg-slate-300 rounded-2xl"></div>
        </div>
    </div>
);


// --- OPTION 4: "MINIMALIST WIDE" (Very Clean, White, Simple) ---
const HeaderOption4 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-slate-50 relative h-[800px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide">
            <span className="absolute top-0 left-0 bg-slate-800 text-white px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20">Option 4: Minimalist Wide with Mega Menu</span>

            <header className="bg-white sticky top-0 z-50 border-b border-slate-100 shadow-sm transition-all hover:shadow-lg">
                <div className="max-w-[1600px] mx-auto px-6 h-20 flex items-center justify-between gap-8">
                    <Logo theme="dark" />

                    {/* Search is center stage here */}
                    <div className="flex-1 max-w-xl mx-auto hidden md:block">
                        <FunctionalSearch />
                    </div>

                    <div className="flex items-center gap-2 lg:gap-6">
                        <div className="" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                            <button className={`h-20 px-4 flex items-center text-sm font-bold border-b-2 transition-all ${isHovered ? 'border-red-600 text-red-600 bg-red-50/50' : 'border-transparent text-slate-700 hover:text-slate-900'}`}>
                                Services <ChevronDown className={`ml-1 w-4 h-4 transition-transform ${isHovered ? 'rotate-180' : ''}`} />
                            </button>
                            <MegaMenu isOpen={isHovered} />
                        </div>

                        <div className="h-8 w-px bg-slate-100 hidden lg:block"></div>

                        <button className="flex items-center gap-2 text-slate-700 hover:text-red-700 font-bold text-sm px-4 py-2 rounded-full hover:bg-slate-50 transition">
                            <LogIn className="w-5 h-5" /> <span>Login</span>
                        </button>

                        <button className="bg-black text-white px-6 py-2.5 rounded-full font-bold text-sm hover:bg-slate-800 transition shadow-lg shadow-black/20 transform hover:-translate-y-0.5">
                            Get Started
                        </button>
                    </div>
                </div>
            </header>
            <PageContent />
        </div>
    );
};

// --- OPTION 5: "DARK PREMIUM" (High Contrast, Gold/White Accents) ---
const HeaderOption5 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-slate-100 relative h-[800px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide">
            <span className="absolute top-0 left-0 bg-slate-800 text-white px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20">Option 5: Dark Premium (High Contrast)</span>

            <header className="bg-[#0B1120] text-white sticky top-0 z-50 shadow-2xl">
                <div className="max-w-[1400px] mx-auto px-6 h-24 flex items-center justify-between">
                    <div className="flex items-center gap-12">
                        <Logo theme="light" size="large" />
                        <div className="hidden lg:block w-px h-10 bg-white/10"></div>
                        <div className="hidden lg:block w-96">
                            <FunctionalSearch variant="dark" />
                        </div>
                    </div>

                    <div className="flex items-center gap-8">
                        <nav className="h-24 flex items-center" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                            <button className={`flex items-center gap-2 text-base font-bold transition-all px-4 py-2 rounded-lg ${isHovered ? 'bg-white/10 text-white' : 'text-slate-300 hover:text-white'}`}>
                                Explore Services <ChevronDown className="w-4 h-4" />
                            </button>
                            <div className="tracking-in-expand">
                                <MegaMenu isOpen={isHovered} />
                            </div>
                        </nav>

                        <div className="flex items-center gap-6">
                            <a href="#" className="text-sm font-bold text-slate-300 hover:text-white flex items-center gap-2 transition">
                                <LogIn className="w-5 h-5 text-red-500" /> Login
                            </a>
                            <button className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-white px-8 py-3 rounded-xl font-bold text-sm shadow-lg shadow-red-900/50 transition-all transform hover:scale-105">
                                Book Expert
                            </button>
                        </div>
                    </div>
                </div>
            </header>
            <div className="bg-white py-4 shadow-sm border-b border-slate-100">
                <div className="max-w-[1400px] mx-auto px-6 flex gap-8 overflow-x-auto text-xs font-bold uppercase tracking-widest text-slate-500">
                    <span className="text-red-600 border-b-2 border-red-600 pb-1 cursor-pointer">Start Business</span>
                    <span className="hover:text-slate-900 cursor-pointer transition">Registration</span>
                    <span className="hover:text-slate-900 cursor-pointer transition">Accounting</span>
                    <span className="hover:text-slate-900 cursor-pointer transition">Licenses</span>
                    <span className="hover:text-slate-900 cursor-pointer transition">Loans</span>
                </div>
            </div>
            <PageContent />
        </div>
    );
};

// --- OPTION 6: "CENTERED STACK" (Classic E-Commerce, Logo Top, Nav Bottom) ---
const HeaderOption6 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-white relative h-[800px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide">
            <span className="absolute top-0 left-0 bg-slate-800 text-white px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20">Option 6: Centered Stack (Classic)</span>

            {/* TOP BAR */}
            <div className="bg-slate-50 border-b border-slate-100 py-2">
                <div className="max-w-[1400px] mx-auto px-6 flex justify-between items-center text-[11px] font-bold uppercase tracking-wider text-slate-500">
                    <div className="flex gap-4">
                        <span><Phone className="w-3 h-3 inline mr-1" /> +91 80085 30606</span>
                        <span><Mail className="w-3 h-3 inline mr-1" /> support@vrhere.in</span>
                    </div>
                    <div className="flex gap-4">
                        <span className="cursor-pointer hover:text-red-600 flex items-center"><LogIn className="w-3 h-3 mr-1" /> Client Login</span>
                    </div>
                </div>
            </div>

            {/* MAIN HEADER */}
            <header className="bg-white pt-6 pb-0 sticky top-0 z-50 shadow-sm">
                <div className="max-w-[1400px] mx-auto px-6 pb-6 flex items-center justify-between gap-12">
                    <Logo theme="dark" size="large" />

                    <div className="flex-1 max-w-2xl">
                        <FunctionalSearch />
                    </div>

                    <div className="flex items-center gap-4">
                        <button className="flex flex-col items-center text-slate-600 hover:text-red-600 transition group">
                            <span className="bg-slate-100 p-2 rounded-full mb-1 group-hover:bg-red-50 transition"><Phone className="w-5 h-5" /></span>
                            <span className="text-[10px] font-bold uppercase">Call Us</span>
                        </button>
                        <button className="flex flex-col items-center text-slate-600 hover:text-red-600 transition group">
                            <span className="bg-slate-100 p-2 rounded-full mb-1 group-hover:bg-red-50 transition"><User className="w-5 h-5" /></span>
                            <span className="text-[10px] font-bold uppercase">Account</span>
                        </button>
                    </div>
                </div>

                {/* NAV BAR */}
                <div className="border-t border-slate-100 bg-white">
                    <div className="max-w-[1400px] mx-auto px-6 flex items-center">
                        <div className="relative group" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                            <button className="bg-red-600 text-white px-8 py-4 font-bold text-sm flex items-center gap-2 hover:bg-black transition-colors">
                                <Menu className="w-5 h-5" /> ALL SERVICES
                            </button>
                            <MegaMenu isOpen={isHovered} />
                        </div>

                        <nav className="flex-1 flex gap-8 px-8 overflow-x-auto">
                            {['Start Business', 'GST & Tax', 'Licenses', 'Loans', 'Legal'].map((item, i) => (
                                <a key={i} href="#" className="text-sm font-bold text-slate-700 hover:text-red-600 py-4 border-b-2 border-transparent hover:border-red-600 transition-all whitespace-nowrap">
                                    {item}
                                </a>
                            ))}
                        </nav>
                    </div>
                </div>
            </header>
            <PageContent />
        </div>
    );
};


const HeaderDesignOptions = () => {
    return (
        <div className="min-h-screen bg-slate-200 space-y-12 pb-20 font-sans text-slate-800">
            <div className="bg-black text-white py-16 px-6 text-center border-b border-slate-800">
                <h1 className="text-5xl font-black mb-6">Header Re-Design (Round 2)</h1>
                <p className="text-slate-400 max-w-2xl mx-auto text-lg">
                    New layouts focusing on functionality and distinct styles.
                    <br />
                    <span className="text-white font-bold inline-block mt-4 bg-red-600 px-4 py-1 rounded-full text-sm">TRY THE SEARCH BAR 🔍</span>
                </p>
                <div className="flex justify-center gap-8 mt-8 text-xs font-bold uppercase tracking-widest text-slate-500">
                    <div className="flex items-center"><CheckCircle className="w-4 h-4 mr-2 text-green-500" /> Functional Search</div>
                    <div className="flex items-center"><CheckCircle className="w-4 h-4 mr-2 text-green-500" /> Mega Menu</div>
                    <div className="flex items-center"><CheckCircle className="w-4 h-4 mr-2 text-green-500" /> Login Component</div>
                </div>
            </div>

            <div className="max-w-[1600px] mx-auto px-4 grid grid-cols-1 gap-24 mb-32">
                <HeaderOption4 />
                <HeaderOption5 />
                <HeaderOption6 />
            </div>
        </div>
    );
};

export default HeaderDesignOptions;
