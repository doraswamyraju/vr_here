import React, { useState, useEffect, useRef } from 'react';
import {
    Phone, Search, ChevronDown, User, LogIn, Menu, X,
    MapPin, Mail, ArrowRight, ShieldCheck, Gem,
    Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
    CreditCard, FileText, CheckCircle, Sparkles, MessageCircle, Send
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
            ).slice(0, 5); // Limit to top 5
            setSuggestions(filtered);
            setIsOpen(true);
        } else {
            setSuggestions([]);
            setIsOpen(false);
        }
    };

    // STYLES BASED ON VARIANT
    const containerClasses = variant === 'dark'
        ? "bg-slate-800 border-slate-700 text-white focus-within:bg-slate-700 focus-within:ring-2 focus-within:ring-red-500/50"
        : variant === 'glass'
            ? "bg-white/20 backdrop-blur-md border border-white/30 text-white placeholder:text-white/70 focus-within:bg-white/30"
            : "bg-slate-100 border-slate-200 text-slate-900 focus-within:bg-white focus-within:ring-2 focus-within:ring-red-100 focus-within:border-red-500 shadow-sm";

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
                    placeholder="Search services (e.g., GST, Loan)..."
                    className={`bg-transparent border-none outline-none w-full text-sm font-medium ${inputClasses}`}
                    value={query}
                    onChange={handleSearch}
                    onFocus={() => query.length > 1 && setIsOpen(true)}
                />
                {query && <X className={`w-4 h-4 cursor-pointer hover:text-red-500 ${iconClass}`} onClick={() => { setQuery(''); setIsOpen(false); }} />}
            </div>

            {/* SUGGESTIONS DROPDOWN */}
            {isOpen && (
                <div className="absolute top-full left-0 right-0 mt-2 bg-white rounded-xl shadow-2xl border border-slate-100 overflow-hidden animate-fade-in origin-top transform transition-all">
                    {suggestions.length > 0 ? (
                        <>
                            <div className="py-2">
                                {suggestions.map((s, i) => (
                                    <a href={s.link} key={i} className="flex items-center justify-between px-4 py-3 hover:bg-slate-50 transition-colors group border-b border-slate-50 last:border-0">
                                        <div className="flex items-center">
                                            <div className="p-2 bg-slate-100 rounded-lg text-slate-500 mr-3 group-hover:bg-red-50 group-hover:text-red-600 transition">
                                                <Search className="w-3.5 h-3.5" />
                                            </div>
                                            <div>
                                                <div className="text-sm font-bold text-slate-800 group-hover:text-red-700 leading-tight">{s.name}</div>
                                                <div className="text-[10px] text-slate-400 font-medium uppercase tracking-wider mt-0.5">{s.category}</div>
                                            </div>
                                        </div>
                                        <ArrowRight className="w-4 h-4 text-slate-300 group-hover:text-red-500 -translate-x-2 group-hover:translate-x-0 transition-all opacity-0 group-hover:opacity-100" />
                                    </a>
                                ))}
                            </div>
                            {/* FALLBACK IF NOT FOUND IN LIST BUT HAS SUGGESTIONS (Should rarely happen due to logic, but good for UI consistency) */}
                        </>
                    ) : (
                        /* NO RESULTS STATE - CREATIVE FALLBACK */
                        <div className="p-6 text-center">
                            <div className="w-12 h-12 bg-red-50 rounded-full flex items-center justify-center mx-auto mb-3 text-red-500">
                                <Search className="w-6 h-6 opacity-50" />
                            </div>
                            <h4 className="text-slate-900 font-bold mb-1">Service not listed?</h4>
                            <p className="text-xs text-slate-500 mb-4">We likely still offer it! Connect with our team.</p>
                            <a href={`/contact?service=${encodeURIComponent(query)}`} className="inline-flex items-center justify-center w-full px-4 py-3 bg-black text-white text-sm font-bold rounded-lg hover:bg-slate-800 transition transform hover:-translate-y-1 shadow-lg">
                                <MessageCircle className="w-4 h-4 mr-2" /> Request "{query}"
                            </a>
                        </div>
                    )}
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

// --- DUMMY CONTENT SCROLLER ---
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


// --- PREVIOUS OPTIONS (4, 5, 6) ---
// ... (Keeping the logic simple, I will re-implement them concisely here to maintain the file integrity)

const HeaderOption4 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-slate-50 relative h-[600px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide">
            <span className="absolute top-0 left-0 bg-slate-800 text-white px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20">Option 4: Minimalist Wide</span>
            <header className="bg-white sticky top-0 z-50 border-b border-slate-100 shadow-sm transition-all hover:shadow-lg">
                <div className="max-w-[1600px] mx-auto px-6 h-20 flex items-center justify-between gap-8">
                    <Logo theme="dark" />
                    <div className="flex-1 max-w-xl mx-auto hidden md:block"><FunctionalSearch /></div>
                    <div className="flex items-center gap-6">
                        <div onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                            <button className={`h-20 px-4 flex items-center text-sm font-bold border-b-2 transition-all ${isHovered ? 'border-red-600 text-red-600 bg-red-50/50' : 'border-transparent text-slate-700 hover:text-slate-900'}`}>Services <ChevronDown className="ml-1 w-4 h-4" /></button>
                            <MegaMenu isOpen={isHovered} />
                        </div>
                        <button className="flex items-center gap-2 text-slate-700 font-bold text-sm px-4 py-2 rounded-full hover:bg-slate-50 transition"><LogIn className="w-5 h-5" /> <span>Login</span></button>
                    </div>
                </div>
            </header>
            <PageContent />
        </div>
    );
};

const HeaderOption5 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-slate-100 relative h-[600px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide">
            <span className="absolute top-0 left-0 bg-slate-800 text-white px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20">Option 5: Dark Premium</span>
            <header className="bg-[#0B1120] text-white sticky top-0 z-50 shadow-2xl">
                <div className="max-w-[1400px] mx-auto px-6 h-24 flex items-center justify-between">
                    <div className="flex items-center gap-12">
                        <Logo theme="light" size="large" />
                        <div className="hidden lg:block w-96"><FunctionalSearch variant="dark" /></div>
                    </div>
                    <div className="flex items-center gap-8">
                        <nav className="h-24 flex items-center" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                            <button className={`flex items-center gap-2 text-base font-bold transition-all px-4 py-2 rounded-lg ${isHovered ? 'bg-white/10 text-white' : 'text-slate-300 hover:text-white'}`}>Explore Services <ChevronDown className="w-4 h-4" /></button>
                            <MegaMenu isOpen={isHovered} />
                        </nav>
                        <div className="flex items-center gap-6">
                            <a href="#" className="text-sm font-bold text-slate-300 hover:text-white flex items-center gap-2 transition"><LogIn className="w-5 h-5 text-red-500" /> Login</a>
                        </div>
                    </div>
                </div>
            </header>
            <PageContent />
        </div>
    );
};

const HeaderOption6 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-white relative h-[600px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide">
            <span className="absolute top-0 left-0 bg-slate-800 text-white px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20">Option 6: Centered Stack</span>
            <header className="bg-white pt-6 pb-0 sticky top-0 z-50 shadow-sm">
                <div className="max-w-[1400px] mx-auto px-6 pb-6 flex items-center justify-between gap-12">
                    <Logo theme="dark" size="large" />
                    <div className="flex-1 max-w-2xl"><FunctionalSearch /></div>
                    <div className="flex items-center gap-4">
                        <button className="flex flex-col items-center text-slate-600 hover:text-red-600 transition group">
                            <span className="bg-slate-100 p-2 rounded-full mb-1 group-hover:bg-red-50 transition"><User className="w-5 h-5" /></span>
                            <span className="text-[10px] font-bold uppercase">Account</span>
                        </button>
                    </div>
                </div>
                <div className="border-t border-slate-100 bg-white">
                    <div className="max-w-[1400px] mx-auto px-6 flex items-center justify-center">
                        <div className="relative group" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                            <button className="bg-red-600 text-white px-8 py-4 font-bold text-sm flex items-center gap-2 hover:bg-black transition-colors"><Menu className="w-5 h-5" /> ALL SERVICES </button>
                            <MegaMenu isOpen={isHovered} />
                        </div>
                    </div>
                </div>
            </header>
            <PageContent />
        </div>
    );
};

// --- NEW CREATIVE OPTIONS (7, 8, 9) ---

// OPTION 7: "NEUMORPHIC FLOATING" - Soft shadows, rounded, floating island
const HeaderOption7 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-slate-200 relative h-[600px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide">
            <span className="absolute top-0 left-0 bg-slate-800 text-white px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20">Option 7: The "Dynamic Island"</span>

            <div className="sticky top-6 z-50 px-4">
                <header className="bg-white/80 backdrop-blur-xl max-w-[1200px] mx-auto rounded-full shadow-[0_8px_30px_rgb(0,0,0,0.04)] border border-white/50 p-2 pl-6 flex items-center justify-between transition-all hover:scale-[1.002]">
                    <div className="flex items-center gap-8">
                        <Logo theme="dark" size="normal" />

                        <div className="hidden md:flex items-center bg-slate-100/50 rounded-full px-1 border border-slate-200/50">
                            <div className="px-4 py-2 cursor-pointer text-sm font-bold text-slate-600 hover:text-black transition">About</div>
                            <div className="h-4 w-px bg-slate-300"></div>
                            <div className="relative" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                                <div className="px-4 py-2 cursor-pointer text-sm font-bold text-red-600 flex items-center gap-1">Services <ChevronDown className="w-3 h-3" /></div>
                                <MegaMenu isOpen={isHovered} />
                            </div>
                        </div>
                    </div>

                    <div className="w-96 mx-4">
                        <FunctionalSearch />
                    </div>

                    <div className="flex items-center pr-2">
                        <button className="w-10 h-10 bg-black text-white rounded-full flex items-center justify-center hover:bg-red-600 transition shadow-lg hover:shadow-red-600/30 transform hover:rotate-12">
                            <LogIn className="w-4 h-4" />
                        </button>
                    </div>
                </header>
            </div>
            <div className="pt-12">
                <PageContent />
            </div>
        </div>
    );
};

// OPTION 8: "GLASSMORPHISM" - Heavy Blur, Background Image, Very Trendy
const HeaderOption8 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="relative h-[600px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide bg-slate-900">
            <span className="absolute top-0 left-0 bg-white text-black px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20">Option 8: Glassmorphism</span>

            {/* Colorful Background Blob */}
            <div className="absolute top-0 left-0 w-full h-[500px] bg-gradient-to-br from-purple-900 via-slate-900 to-red-900 z-0"></div>
            <div className="absolute top-[-100px] right-[-100px] w-[500px] h-[500px] bg-red-600 rounded-full blur-[150px] opacity-40 animate-pulse"></div>

            <header className="sticky top-0 z-50 bg-white/5 backdrop-blur-xl border-b border-white/10 text-white shadow-2xl">
                <div className="max-w-[1400px] mx-auto px-6 h-24 flex items-center justify-between">
                    <Logo theme="light" />

                    <div className="flex-1 max-w-xl mx-12">
                        <FunctionalSearch variant="glass" />
                    </div>

                    <div className="flex items-center gap-8">
                        <div className="relative h-24 flex items-center" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                            <button className="flex items-center gap-2 text-sm font-bold tracking-wider hover:text-red-400 transition">
                                EXPLORE <Sparkles className="w-3 h-3 text-yellow-400" />
                            </button>
                            <MegaMenu isOpen={isHovered} />
                        </div>

                        <div className="w-px h-8 bg-white/20"></div>

                        <button className="flex items-center gap-3 group">
                            <div className="text-right">
                                <div className="text-[10px] font-bold text-white/60">CLIENT ACCESS</div>
                                <div className="text-sm font-bold group-hover:text-red-400 transition">Login</div>
                            </div>
                            <div className="w-10 h-10 rounded-xl bg-white/10 border border-white/20 flex items-center justify-center group-hover:bg-red-600 group-hover:border-red-600 transition-all">
                                <User className="w-5 h-5" />
                            </div>
                        </button>
                    </div>
                </div>
            </header>
            <PageContent />
        </div>
    );
};

// OPTION 9: "ASYMMETRIC SPLIT" - Logo Left, Massive Search Right, Menu Bottom
const HeaderOption9 = () => {
    const [isHovered, setIsHovered] = useState(false);
    return (
        <div className="bg-white relative h-[600px] overflow-y-auto border border-slate-300 rounded-xl shadow-inner scrollbar-hide">
            <span className="absolute top-0 left-0 bg-slate-800 text-white px-3 py-1 text-xs font-bold uppercase rounded-br-lg z-20">Option 9: The "Power Search"</span>

            <header className="sticky top-0 z-50 bg-white border-b-4 border-black">
                <div className="flex flex-col md:flex-row">
                    {/* LEFT BLOCK */}
                    <div className="bg-black text-white p-6 md:w-64 flex-shrink-0 flex items-center justify-center">
                        <Logo theme="light" />
                    </div>

                    {/* RIGHT BLOCK */}
                    <div className="flex-1 flex flex-col">
                        {/* TOP ROw */}
                        <div className="flex items-center justify-between p-4 border-b border-slate-100 bg-slate-50">
                            <div className="flex-1 max-w-2xl">
                                <FunctionalSearch />
                            </div>
                            <div className="flex items-center gap-6 px-6">
                                <button className="flex items-center gap-2 font-bold text-sm text-slate-600 hover:text-black hover:underline"><Phone className="w-4 h-4" /> Support</button>
                                <button className="bg-red-600 text-white px-6 py-2 rounded-lg font-black text-xs uppercase tracking-wider hover:bg-black transition transform hover:-translate-y-1 shadow-lg">Login</button>
                            </div>
                        </div>
                        {/* BOTTOM ROW */}
                        <div className="bg-white px-6 py-2 flex gap-8">
                            <div className="relative group" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
                                <button className="font-black text-sm uppercase tracking-widest hover:text-red-600 py-2 border-b-4 border-transparent hover:border-red-600 transition-all">All Services</button>
                                <MegaMenu isOpen={isHovered} />
                            </div>
                            <button className="font-bold text-sm text-slate-500 hover:text-black py-2">Consultation</button>
                            <button className="font-bold text-sm text-slate-500 hover:text-black py-2">Partner with Us</button>
                        </div>
                    </div>
                </div>
            </header>
            <PageContent />
        </div>
    );
};


const HeaderDesignOptions = () => {
    return (
        <div className="min-h-screen bg-slate-50 space-y-12 pb-20 font-sans text-slate-800">
            <div className="bg-slate-900 text-white py-16 px-6 text-center border-b-8 border-red-600">
                <div className="inline-block bg-red-600 text-white text-[10px] font-black uppercase tracking-widest px-3 py-1 rounded mb-4">Round 3</div>
                <h1 className="text-5xl font-black mb-6">Header Design Collection</h1>
                <p className="text-slate-400 max-w-2xl mx-auto text-lg mb-8">
                    Choose from 6 unique styles.
                    <br />
                    <span className="text-white font-bold">Search Feature Updated:</span> Try searching for "Gym" or "Food" to see the "Not Found" fallback.
                </p>
                <a href="#new" className="bg-white text-black px-6 py-3 rounded-full font-bold text-sm hover:bg-slate-200 transition">Jump to New Creative Options 👇</a>
            </div>

            <div className="max-w-[1600px] mx-auto px-4 grid grid-cols-1 gap-24 mb-32">

                {/* PREVIOUS ROUND 2 */}
                <div className="opacity-50 hover:opacity-100 transition-opacity duration-500">
                    <h2 className="text-2xl font-black text-slate-400 mb-8 uppercase tracking-widest pl-4 border-l-4 border-slate-300">Round 2 Candidates</h2>
                    <div className="space-y-16">
                        <HeaderOption4 />
                        <HeaderOption5 />
                        <HeaderOption6 />
                    </div>
                </div>

                {/* NEW ROUND 3 */}
                <div id="new" className="pt-12">
                    <h2 className="text-4xl font-black text-red-600 mb-12 uppercase tracking-tight pl-4 border-l-8 border-red-600">Round 3: Creative Series</h2>
                    <div className="space-y-24">
                        <HeaderOption7 />
                        <HeaderOption8 />
                        <HeaderOption9 />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default HeaderDesignOptions;
