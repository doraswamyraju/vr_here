import React, { useState, useEffect, useRef } from 'react';
import {
    Phone, Search, ChevronDown, User, LogIn, Menu, X,
    MapPin, Mail, ArrowRight, ShieldCheck, Gem,
    Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
    CheckCircle, Sparkles, MessageCircle, HelpCircle, ArrowUpRight
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
    // Add keywords
    services.push({ name: 'Private Limited Registration', category: 'Business Registration', link: '/pvt-ltd-registration' });
    services.push({ name: 'GST Registration', category: 'Accounting', link: '/gst-registration' });
    services.push({ name: 'Trademark', category: 'Utility', link: '/contact?service=Trademark' });
    return services;
};

const ALL_SERVICES = getAllServices();

// --- COMPONENTS ---

const Logo = ({ theme = 'dark', size = 'normal' }) => (
    <div className="flex items-center gap-3 cursor-pointer select-none group">
        <div className={`rounded-xl flex items-center justify-center font-black shadow-lg transition-transform group-hover:scale-110 duration-300 ${theme === 'dark' ? 'bg-black text-white' : 'bg-red-600 text-white'} ${size === 'large' ? 'w-12 h-12 text-2xl' : 'w-10 h-10 text-xl'}`}>
            VR
        </div>
        <div className="flex flex-col justify-center">
            <span className={`font-black leading-none tracking-tight ${theme === 'dark' ? 'text-slate-900' : 'text-white'} ${size === 'large' ? 'text-3xl' : 'text-2xl'}`}>VR HERE</span>
            <span className={`font-bold tracking-widest uppercase ${theme === 'dark' ? 'text-red-600' : 'text-slate-200'} ${size === 'large' ? 'text-xs' : 'text-[10px]'}`}>Business Solutions</span>
        </div>
    </div>
);

const MegaMenu = ({ isOpen }) => {
    if (!isOpen) return null;
    return (
        <div className="absolute top-full left-0 w-full pt-2 animate-fade-in z-[100]">
            <div className="bg-white rounded-b-3xl shadow-2xl border-t border-slate-100 overflow-hidden ring-1 ring-black/5">
                <div className="max-w-[1400px] mx-auto flex">
                    {/* SIDEBAR */}
                    <div className="w-72 bg-slate-50 p-8 flex flex-col justify-between border-r border-slate-100 relative overflow-hidden">
                        {/* Decorator */}
                        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-red-500 to-orange-500"></div>

                        <div>
                            <h3 className="text-2xl font-black text-slate-900 mb-2">Our Expertise</h3>
                            <p className="text-sm text-slate-500 mb-8 leading-relaxed">End-to-end business solutions from registration to industrial expansion.</p>
                            <div className="space-y-4">
                                <div className="flex items-center text-xs font-bold uppercase tracking-wider text-slate-700 bg-white p-3 rounded-lg border border-slate-200 shadow-sm"><CheckCircle className="w-4 h-4 text-green-500 mr-3" /> 100% Online Process</div>
                                <div className="flex items-center text-xs font-bold uppercase tracking-wider text-slate-700 bg-white p-3 rounded-lg border border-slate-200 shadow-sm"><CheckCircle className="w-4 h-4 text-green-500 mr-3" /> Expert CA/CS Team</div>
                            </div>
                        </div>
                        <button className="w-full py-3 bg-black text-white text-sm font-bold rounded-lg hover:bg-slate-800 transition shadow-lg mt-8 flex items-center justify-center gap-2 group">
                            View All Services <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                        </button>
                    </div>
                    {/* GRID */}
                    <div className="flex-1 p-8 grid grid-cols-4 gap-x-6 gap-y-10 bg-white">
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
            ).slice(0, 5);
            setSuggestions(filtered);
            setIsOpen(true);
        } else {
            setSuggestions([]);
            setIsOpen(false);
        }
    };

    // STYLES
    const containerClasses = variant === 'dark'
        ? "bg-slate-800/50 border-slate-700 text-white focus-within:bg-slate-800 focus-within:ring-2 focus-within:ring-red-500/50"
        : variant === 'glass'
            ? "bg-white/10 backdrop-blur-md border border-white/20 text-white placeholder:text-white/70 focus-within:bg-white/20 hover:bg-white/20"
            : "bg-slate-100 border-slate-200 text-slate-900 focus-within:bg-white focus-within:ring-2 focus-within:ring-red-100 focus-within:border-red-500 shadow-inner";

    const inputClasses = (variant === 'dark' || variant === 'glass')
        ? "text-white placeholder:text-white/50"
        : "text-slate-900 placeholder:text-slate-500";

    const iconClass = (variant === 'dark' || variant === 'glass') ? "text-white/60" : "text-slate-500";

    return (
        <div className="relative w-full z-[60]" ref={wrapperRef}>
            <div className={`flex items-center px-4 py-3 rounded-full border transition-all duration-300 ${containerClasses}`}>
                <Search className={`w-4 h-4 mr-3 ${iconClass}`} />
                <input
                    type="text"
                    placeholder="Search for services..."
                    className={`bg-transparent border-none outline-none w-full text-sm font-medium ${inputClasses}`}
                    value={query}
                    onChange={handleSearch}
                    onFocus={() => query.length > 1 && setIsOpen(true)}
                />
                {query && <X className={`w-4 h-4 cursor-pointer hover:text-red-500 ${iconClass}`} onClick={() => { setQuery(''); setIsOpen(false); }} />}
            </div>

            {/* REDESIGNED DROPDOWN */}
            {isOpen && (
                <div className="absolute top-full left-0 right-0 mt-3 bg-white rounded-2xl shadow-xl border border-slate-100 overflow-hidden animate-fade-in origin-top transform transition-all ring-1 ring-black/5">
                    {suggestions.length > 0 ? (
                        <>
                            <div className="bg-slate-50/50 px-4 py-2 border-b border-slate-100 text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                                Best Matches
                            </div>
                            <div className="py-2">
                                {suggestions.map((s, i) => (
                                    <a href={s.link} key={i} className="flex items-center justify-between px-4 py-3 hover:bg-slate-50 transition-colors group border-b border-slate-50 last:border-0 cursor-pointer">
                                        <div className="flex items-center">
                                            <div className="w-8 h-8 rounded-full bg-red-50 text-red-600 flex items-center justify-center mr-3 group-hover:scale-110 transition-transform">
                                                <ArrowUpRight className="w-4 h-4" />
                                            </div>
                                            <div>
                                                <div className="text-sm font-bold text-slate-800 group-hover:text-red-700 leading-tight">{s.name}</div>
                                                <div className="text-[10px] text-slate-400 font-medium uppercase tracking-wider mt-0.5">{s.category}</div>
                                            </div>
                                        </div>
                                    </a>
                                ))}
                            </div>
                        </>
                    ) : (
                        /* REDESIGNED "NOT FOUND" */
                        <div className="p-1">
                            <div className="bg-gradient-to-br from-slate-900 to-slate-800 rounded-xl p-6 text-center text-white relative overflow-hidden">
                                {/* Decor */}
                                <div className="absolute top-0 right-0 w-32 h-32 bg-red-600/20 rounded-full blur-3xl -mr-10 -mt-10"></div>
                                <div className="absolute bottom-0 left-0 w-24 h-24 bg-blue-600/20 rounded-full blur-2xl -ml-6 -mb-6"></div>

                                <div className="relative z-10">
                                    <div className="w-12 h-12 bg-white/10 backdrop-blur-md rounded-full flex items-center justify-center mx-auto mb-3 border border-white/10 shadow-lg">
                                        <HelpCircle className="w-6 h-6 text-red-400" />
                                    </div>
                                    <h4 className="text-lg font-bold mb-1">Couldn't find "{query}"</h4>
                                    <p className="text-xs text-slate-300 mb-5 max-w-[200px] mx-auto">Don't worry, we offer custom solutions for almost everything.</p>

                                    <a href={`/contact?service=${encodeURIComponent(query)}`} className="inline-flex items-center justify-center w-full px-4 py-3 bg-red-600 hover:bg-red-500 text-white text-sm font-bold rounded-lg transition shadow-lg shadow-red-900/20 group">
                                        <MessageCircle className="w-4 h-4 mr-2" />
                                        Request Callback for "{query}"
                                    </a>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

// --- DUMMY CONTENT SCROLLER (To show stickiness) ---
const PageContent = ({ label }) => (
    <div className="max-w-7xl mx-auto py-24 px-4 space-y-16 opacity-30 select-none grayscale origin-top">
        <div className="h-64 bg-slate-300 rounded-3xl w-full flex items-center justify-center text-5xl font-black text-slate-400 uppercase tracking-widest border-4 border-dashed border-slate-400">
            {label} SCROLL CONTENT
        </div>
        <div className="grid grid-cols-2 gap-8">
            <div className="space-y-4">
                <div className="h-8 bg-slate-300 rounded w-3/4"></div>
                <div className="h-4 bg-slate-300 rounded w-full"></div>
                <div className="h-4 bg-slate-300 rounded w-5/6"></div>
            </div>
            <div className="h-40 bg-slate-300 rounded-xl"></div>
        </div>
        <div className="h-96 bg-slate-300 rounded-3xl w-full"></div>
    </div>
);


const HeaderDesignOptions = () => {
    const [hoveredState, setHoveredState] = useState([false, false, false, false, false, false, false]); // For 7 headers

    // Helper to toggle hover
    const setHover = (index, val) => {
        const newState = [...hoveredState];
        newState[index] = val;
        setHoveredState(newState);
    }

    return (
        <div className="bg-slate-950 font-sans text-slate-800">

            {/* --- HEADER 3: HYBRID SPLIT --- */}
            <div className="relative h-[600px] overflow-y-auto overflow-x-hidden bg-white border-b-8 border-slate-900 group/container">
                <span className="fixed top-4 left-4 bg-black text-white px-3 py-1 text-[10px] font-bold uppercase rounded z-[200] opacity-50 group-hover/container:opacity-100 transition-opacity">Option 3: Hybrid Split</span>

                <header className="bg-[#1e293b] text-white py-3 px-8 sticky top-0 z-50 shadow-2xl transition-all duration-300">
                    <div className="max-w-[1400px] mx-auto flex justify-between items-center relative z-10">
                        <div className="flex items-center gap-6">
                            <div className="bg-white/10 p-2 rounded-lg cursor-pointer hover:bg-white/20 transition"><Menu className="w-5 h-5 text-white" /></div>
                            <div className="relative h-12 flex items-center" onMouseEnter={() => setHover(0, true)} onMouseLeave={() => setHover(0, false)}>
                                <button className={`flex items-center gap-2 text-sm font-bold transition ${hoveredState[0] ? 'text-white' : 'text-slate-300'}`}>All Services <ChevronDown className="w-4 h-4 opacity-50" /></button>
                                <MegaMenu isOpen={hoveredState[0]} />
                            </div>
                        </div>
                        <div className="absolute left-1/2 top-1/2 -translate-x-1/2"><Logo theme="dark" /></div>
                        <div className="flex items-center gap-5">
                            <button className="bg-white text-slate-900 px-5 py-2 rounded-lg font-bold text-xs hover:bg-slate-100 transition flex items-center gap-2"><span>Get Started</span> <ArrowRight className="w-3.5 h-3.5" /></button>
                        </div>
                    </div>
                </header>
                <div className="bg-slate-100 py-2.5 px-8 max-w-[1400px] mx-auto flex gap-6 text-[10px] font-bold uppercase tracking-wide text-slate-500 shadow-lg sticky top-[70px] z-40">
                    <span className="hover:text-red-600 cursor-pointer">Startup Registration</span>
                    <span className="hover:text-red-600 cursor-pointer">GST & Tax</span>
                    <span className="hover:text-red-600 cursor-pointer">Industrial Setup</span>
                </div>
                <PageContent label="Hybrid Split" />
            </div>

            {/* --- HEADER 4: MINIMALIST WIDE --- */}
            <div className="relative h-[600px] overflow-y-auto overflow-x-hidden bg-slate-50 border-b-8 border-slate-900 group/container">
                <span className="fixed top-4 left-4 bg-black text-white px-3 py-1 text-[10px] font-bold uppercase rounded z-[200] opacity-50 group-hover/container:opacity-100 transition-opacity">Option 4: Minimalist Wide</span>

                <header className="bg-white sticky top-0 z-50 border-b border-slate-100 shadow-sm transition-all hover:shadow-lg">
                    <div className="max-w-[1600px] mx-auto px-6 h-20 flex items-center justify-between gap-8">
                        <Logo theme="dark" />
                        <div className="flex-1 max-w-xl mx-auto hidden md:block"><FunctionalSearch /></div>
                        <div className="flex items-center gap-4">
                            <div className="h-20 flex items-center relative" onMouseEnter={() => setHover(1, true)} onMouseLeave={() => setHover(1, false)}>
                                <button className={`px-4 py-2 flex items-center text-sm font-bold rounded-md transition-all ${hoveredState[1] ? 'bg-red-50 text-red-600' : 'text-slate-700 hover:text-slate-900'}`}>Services <ChevronDown className="ml-1 w-4 h-4" /></button>
                                <MegaMenu isOpen={hoveredState[1]} />
                            </div>
                            <div className="h-8 w-px bg-slate-100"></div>
                            <button className="bg-black text-white px-6 py-2.5 rounded-full font-bold text-sm hover:bg-slate-800 transition shadow-lg shadow-black/20">Get Started</button>
                        </div>
                    </div>
                </header>
                <PageContent label="Minimalist" />
            </div>

            {/* --- HEADER 5: DARK PREMIUM --- */}
            <div className="relative h-[600px] overflow-y-auto overflow-x-hidden bg-slate-300 border-b-8 border-slate-900 group/container">
                <span className="fixed top-4 left-4 bg-black text-white px-3 py-1 text-[10px] font-bold uppercase rounded z-[200] opacity-50 group-hover/container:opacity-100 transition-opacity">Option 5: Dark Premium</span>

                <header className="bg-[#0f172a] text-white sticky top-0 z-50 shadow-2xl">
                    <div className="max-w-[1400px] mx-auto px-6 h-24 flex items-center justify-between">
                        <div className="flex items-center gap-12">
                            <Logo theme="light" size="large" />
                            <div className="hidden lg:block w-96"><FunctionalSearch variant="dark" /></div>
                        </div>
                        <div className="flex items-center gap-8">
                            <nav className="h-24 flex items-center relative" onMouseEnter={() => setHover(2, true)} onMouseLeave={() => setHover(2, false)}>
                                <button className={`flex items-center gap-2 text-base font-bold transition-all px-4 py-2 rounded-lg ${hoveredState[2] ? 'bg-white/10 text-white' : 'text-slate-300 hover:text-white'}`}>Explore Services <ChevronDown className="w-4 h-4" /></button>
                                <MegaMenu isOpen={hoveredState[2]} />
                            </nav>
                            <button className="bg-red-600 text-white px-8 py-3 rounded-xl font-bold text-sm shadow-lg shadow-red-900/50 hover:bg-red-500 transition-all">Book Expert</button>
                        </div>
                    </div>
                </header>
                <PageContent label="Dark Premium" />
            </div>

            {/* --- HEADER 6: CENTERED STACK --- */}
            <div className="relative h-[600px] overflow-y-auto overflow-x-hidden bg-white border-b-8 border-slate-900 group/container">
                <span className="fixed top-4 left-4 bg-black text-white px-3 py-1 text-[10px] font-bold uppercase rounded z-[200] opacity-50 group-hover/container:opacity-100 transition-opacity">Option 6: Centered Stack</span>

                <header className="bg-white pt-6 pb-0 sticky top-0 z-50 shadow-md">
                    <div className="max-w-[1400px] mx-auto px-6 pb-6 flex items-center justify-between gap-12">
                        <Logo theme="dark" size="large" />
                        <div className="flex-1 max-w-2xl"><FunctionalSearch /></div>
                        <div className="flex items-center gap-4">
                            <button className="bg-slate-100 p-3 rounded-full hover:bg-red-50 text-slate-600 hover:text-red-600 transition"><User className="w-5 h-5" /></button>
                        </div>
                    </div>
                    <div className="border-t border-slate-100 bg-white">
                        <div className="max-w-[1400px] mx-auto px-6 flex items-center justify-center">
                            <div className="relative group p-2" onMouseEnter={() => setHover(3, true)} onMouseLeave={() => setHover(3, false)}>
                                <button className="bg-red-600 text-white px-8 py-3 font-bold text-sm flex items-center gap-2 hover:bg-black transition-colors rounded-t-lg"><Menu className="w-5 h-5" /> ALL SERVICES </button>
                                <MegaMenu isOpen={hoveredState[3]} />
                            </div>
                        </div>
                    </div>
                </header>
                <PageContent label="Centered Stack" />
            </div>

            {/* --- HEADER 7: DYNAMIC ISLAND --- */}
            <div className="relative h-[600px] overflow-y-auto overflow-x-hidden bg-slate-200 border-b-8 border-slate-900 group/container">
                <span className="fixed top-4 left-4 bg-black text-white px-3 py-1 text-[10px] font-bold uppercase rounded z-[200] opacity-50 group-hover/container:opacity-100 transition-opacity">Option 7: Dynamic Island</span>

                <div className="sticky top-6 z-50 px-4">
                    <header className="bg-white/90 backdrop-blur-xl max-w-[1200px] mx-auto rounded-full shadow-2xl border border-white/50 p-2 pl-6 flex items-center justify-between transition-all hover:scale-[1.002]">
                        <div className="flex items-center gap-8">
                            <Logo theme="dark" size="normal" />
                            <div className="hidden md:flex items-center bg-slate-100/50 rounded-full px-1 border border-slate-200/50">
                                <div className="relative py-2 px-4" onMouseEnter={() => setHover(4, true)} onMouseLeave={() => setHover(4, false)}>
                                    <div className="cursor-pointer text-sm font-bold text-red-600 flex items-center gap-1">Services <ChevronDown className="w-3 h-3" /></div>
                                    <MegaMenu isOpen={hoveredState[4]} />
                                </div>
                            </div>
                        </div>
                        <div className="w-96 mx-4"><FunctionalSearch /></div>
                        <div className="flex items-center pr-2">
                            <button className="w-10 h-10 bg-black text-white rounded-full flex items-center justify-center hover:bg-red-600 transition shadow-lg"><LogIn className="w-4 h-4" /></button>
                        </div>
                    </header>
                </div>
                <div className="pt-24">
                    <PageContent label="Dynamic Island" />
                </div>
            </div>

            {/* --- HEADER 8: GLASSMORPHISM --- */}
            <div className="relative h-[600px] overflow-y-auto overflow-x-hidden bg-slate-900 border-b-8 border-slate-900 group/container">
                <span className="fixed top-4 left-4 bg-white text-black px-3 py-1 text-[10px] font-bold uppercase rounded z-[200] opacity-50 group-hover/container:opacity-100 transition-opacity">Option 8: Glassmorphism</span>

                <div className="absolute top-0 left-0 w-full h-[500px] bg-gradient-to-br from-indigo-900 via-slate-900 to-red-900 z-0"></div>

                <header className="sticky top-0 z-50 bg-white/5 backdrop-blur-xl border-b border-white/10 text-white shadow-2xl">
                    <div className="max-w-[1400px] mx-auto px-6 h-24 flex items-center justify-between">
                        <Logo theme="light" />
                        <div className="flex-1 max-w-xl mx-12"><FunctionalSearch variant="glass" /></div>
                        <div className="flex items-center gap-8">
                            <div className="relative h-24 flex items-center" onMouseEnter={() => setHover(5, true)} onMouseLeave={() => setHover(5, false)}>
                                <button className="flex items-center gap-2 text-sm font-bold tracking-wider hover:text-red-400 transition">EXPLORE <Sparkles className="w-3 h-3 text-yellow-400" /></button>
                                <MegaMenu isOpen={hoveredState[5]} />
                            </div>
                            <button className="w-10 h-10 rounded-xl bg-white/10 border border-white/20 flex items-center justify-center hover:bg-red-600 transition-all"><User className="w-5 h-5" /></button>
                        </div>
                    </div>
                </header>
                <PageContent label="Glassmorphism" />
            </div>

            {/* --- HEADER 9: POWER SEARCH --- */}
            <div className="relative h-[600px] overflow-y-auto overflow-x-hidden bg-white border-b-8 border-slate-900 group/container">
                <span className="fixed top-4 left-4 bg-black text-white px-3 py-1 text-[10px] font-bold uppercase rounded z-[200] opacity-50 group-hover/container:opacity-100 transition-opacity">Option 9: Power Search</span>

                <header className="sticky top-0 z-50 bg-white border-b-4 border-black shadow-lg">
                    <div className="flex flex-col md:flex-row">
                        <div className="bg-black text-white p-6 md:w-64 flex-shrink-0 flex items-center justify-center"><Logo theme="light" /></div>
                        <div className="flex-1 flex flex-col">
                            <div className="flex items-center justify-between p-4 border-b border-slate-100 bg-slate-50">
                                <div className="flex-1 max-w-2xl"><FunctionalSearch /></div>
                                <div className="flex items-center gap-6 px-6">
                                    <button className="bg-red-600 text-white px-6 py-2 rounded-lg font-black text-xs uppercase tracking-wider hover:bg-black transition shadow-lg">Login</button>
                                </div>
                            </div>
                            <div className="bg-white px-6 py-2 flex gap-8 relative">
                                <div className="relative group py-2" onMouseEnter={() => setHover(6, true)} onMouseLeave={() => setHover(6, false)}>
                                    <button className="font-black text-sm uppercase tracking-widest hover:text-red-600 border-b-4 border-transparent hover:border-red-600 transition-all">All Services</button>
                                    <MegaMenu isOpen={hoveredState[6]} />
                                </div>
                            </div>
                        </div>
                    </div>
                </header>
                <PageContent label="Power Search" />
            </div>

        </div>
    );
};

export default HeaderDesignOptions;
