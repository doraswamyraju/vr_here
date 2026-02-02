import React, { useState, useEffect, useRef } from 'react';
import {
    Phone, Search, ChevronDown, User, LogIn, Menu, X,
    MapPin, Mail, ArrowRight, ShieldCheck, Gem,
    Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
    CheckCircle, Sparkles, MessageCircle, HelpCircle, ArrowUpRight, Grid, Layout
} from 'lucide-react';
import { MENU_DATA, getServiceLink } from './components/SharedComponents';

// --- UTILS ---
const getAllServices = () => {
    let services = [];
    MENU_DATA.forEach(cat => {
        cat.items.forEach(item => {
            services.push({ name: item, category: cat.title, link: getServiceLink(item) });
        });
    });
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
            <div className="bg-white rounded-b-3xl shadow-[0_30px_60px_-15px_rgba(0,0,0,0.3)] border-t border-slate-100 overflow-hidden ring-1 ring-black/5 mx-6 md:mx-0">
                <div className="max-w-[1400px] mx-auto flex flex-col md:flex-row min-h-[400px]">
                    <div className="w-full md:w-72 bg-slate-50 p-8 flex flex-col justify-between border-b md:border-b-0 md:border-r border-slate-100 relative overflow-hidden shrink-0">
                        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-red-500 to-orange-500"></div>
                        <div>
                            <h3 className="text-2xl font-black text-slate-900 mb-2">Our Expertise</h3>
                            <p className="text-sm text-slate-500 mb-8 leading-relaxed">End-to-end business solutions.</p>
                            <div className="space-y-4">
                                <div className="flex items-center text-xs font-bold uppercase tracking-wider text-slate-700 bg-white p-3 rounded-lg border border-slate-200 shadow-sm"><CheckCircle className="w-4 h-4 text-green-500 mr-3" /> 100% Online Process</div>
                                <div className="flex items-center text-xs font-bold uppercase tracking-wider text-slate-700 bg-white p-3 rounded-lg border border-slate-200 shadow-sm"><CheckCircle className="w-4 h-4 text-green-500 mr-3" /> Expert CA/CS Team</div>
                            </div>
                        </div>
                        <button className="w-full py-3 bg-black text-white text-sm font-bold rounded-lg hover:bg-slate-800 transition shadow-lg mt-8 flex items-center justify-center gap-2 group">
                            View All Services <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                        </button>
                    </div>
                    <div className="flex-1 p-8 grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-8 bg-white overflow-y-auto">
                        {MENU_DATA.map((service) => (
                            <div key={service.id} className="group/item">
                                <a href={`/contact?service=${encodeURIComponent(service.title)}`} className="flex items-center space-x-2 mb-3 cursor-pointer">
                                    <div className="p-1.5 bg-red-50 text-red-600 rounded-md group-hover/item:bg-red-600 group-hover/item:text-white transition-colors">
                                        <service.icon className="w-4 h-4" />
                                    </div>
                                    <h4 className="font-bold text-slate-900 text-sm group-hover/item:text-red-700 transition-colors">{service.title}</h4>
                                </a>
                                <ul className="space-y-2 border-l-2 border-slate-100 pl-4 group-hover/item:border-red-100 transition-colors">
                                    {service.items.map((item, i) => (
                                        <li key={i}>
                                            <a href={getServiceLink(item)} className="block text-xs font-medium text-slate-500 hover:text-red-600 hover:translate-x-1 transition-all truncate">
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

// --- HELPER WRAPPER ---
function MegaphoneIconWrapper(props) { return <Sparkles {...props} /> }

// --- CANVA MENU DATA (Enhanced with Icons & Colors) ---
const CANVA_MENU_DATA = [
    { title: "Industrial & Manufacturing", icon: Factory, color: "text-orange-600", bg: "bg-orange-50", items: ["Machinery sourcing", "Turnkey setup", "Tech upgradation", "Feasibility", "Consulting"] },
    { title: "Certifications", icon: Stamp, color: "text-green-600", bg: "bg-green-50", items: ["ISO 9001, 14001", "GMP / HACCP", "CE, BIS, ISI", "FDA, BRCGS", "Halal & Kosher"] },
    { title: "Business Setup", icon: Briefcase, color: "text-blue-600", bg: "bg-blue-50", items: ["Company / LLP", "Licenses", "ROC Compliances", "Labour & Pollution", "DSC & Filings"] },
    { title: "Accounting", icon: Calculator, color: "text-indigo-600", bg: "bg-indigo-50", items: ["Outsourcing", "GST & Tax", "Statutory Audits", "MIS & Compliance"] },
    { title: "Finance & MSME", icon: IndianRupee, color: "text-emerald-600", bg: "bg-emerald-50", items: ["DPR & CMA Reports", "Bank Loans", "CGTMSE / PMEGP", "Subsidies", "NSIC & PMFME"] },
    { title: "Govt Portals", icon: Globe, color: "text-cyan-600", bg: "bg-cyan-50", items: ["GeM Registration", "OEM Approvals", "TReDS, RERA", "NPCI Reg", "Single Window"] },
    { title: "Branding & Digital", icon: MegaphoneIconWrapper, color: "text-pink-600", bg: "bg-pink-50", items: ["Identity Consulting", "Digital Marketing", "Website Design", "Landing Pages", "Startup Branding"] },
    { title: "Software & Tech", icon: Layout, color: "text-violet-600", bg: "bg-violet-50", items: ["Custom Software", "Web Apps", "Automation Tools", "ERP / CRM", "Cloud Systems"] },
    { title: "AI Products", icon: Sparkles, color: "text-purple-600", bg: "bg-purple-50", items: ["AI Development", "Chatbots", "Automation", "Analytics Tools", "Custom AI"] },
    { title: "IP & Support", icon: ShieldCheck, color: "text-red-600", bg: "bg-red-50", items: ["Trademark & IP", "Business Docs", "HR Policies", "Loan Docs", "Insurance"] }
];

// --- CANVA MEGA MENU (Enhanced) ---
const CanvaMegaMenu = ({ isOpen }) => {
    if (!isOpen) return null;
    return (
        <div className="absolute top-full left-0 w-full pt-2 animate-fade-in z-[100]">
            <div className="bg-white rounded-xl shadow-2xl border border-slate-100 mx-4 mt-2 p-8 relative">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-x-8 gap-y-10">
                    {CANVA_MENU_DATA.map((cat, i) => (
                        <div key={i} className="group/cat">
                            <div className="flex items-center gap-3 mb-4">
                                <div className={`w-8 h-8 rounded-lg ${cat.bg} ${cat.color} flex items-center justify-center shrink-0`}>
                                    <cat.icon className="w-5 h-5" />
                                </div>
                                <h4 className="font-bold text-slate-900 text-sm">{cat.title}</h4>
                            </div>
                            <ul className="space-y-2 pl-11">
                                {cat.items.map((item, j) => (
                                    <li key={j}>
                                        <a href="#" className="text-xs font-medium text-slate-500 hover:text-purple-600 hover:bg-purple-50 px-2 py-1 -ml-2 rounded block transition-colors">
                                            {item}
                                        </a>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ))}
                </div>
                {/* Featured AI Section */}
                <div className="mt-10 pt-6 border-t border-slate-100 flex items-center justify-between bg-gradient-to-r from-purple-50 via-white to-white -mx-8 -mb-8 p-8 rounded-b-xl">
                    <div className="flex items-center gap-5">
                        <div className="bg-purple-600 text-white p-4 rounded-xl shadow-lg shadow-purple-200"><Sparkles className="w-6 h-6" /></div>
                        <div>
                            <div className="font-black text-slate-900 text-lg">Future-Ready AI Solutions</div>
                            <div className="text-sm text-slate-500">Upgrade your business with intelligent automation and analytics.</div>
                        </div>
                    </div>
                    <button className="bg-slate-900 text-white px-6 py-3 rounded-xl text-sm font-bold hover:bg-purple-600 transition-colors shadow-lg">Explore AI Products</button>
                </div>
            </div>
        </div>
    )
}

// --- VISME MENU DATA ---
const VISME_PRODUCTS = [
    { name: "Presentations", icon: Layout, desc: "Keep your audience engaged", color: "bg-blue-500" },
    { name: "Documents", icon: Briefcase, desc: "Visual docs that inform", color: "bg-green-500" },
    { name: "Charts & Graphs", icon: Calculator, desc: "Bring your data to life", color: "bg-orange-500" },
    { name: "Infographics", icon: Grid, desc: "Share information visually", color: "bg-pink-500" },
    { name: "Forms & Surveys", icon: CheckCircle, desc: "Visual forms that convert", color: "bg-indigo-500" },
];

const VISME_COLS = {
    tools: { title: "Design Tools", items: ["Video Maker", "Timeline Maker", "eBook Creator", "GIF Maker", "Flowchart Maker", "Report Maker"] },
    ai: { title: "VR AI >", items: ["AI Designer", "AI Presentation Maker", "AI Document Generator", "AI Brand Design Tools", "AI Image Generator"] },
    graphics: { title: "Graphics & Assets", items: ["Data Visualization", "Photos", "Mockups", "Icons", "Animated Characters"] }
};

// --- VISME MEGA MENU ---
const VismeMegaMenu = ({ isOpen }) => {
    if (!isOpen) return null;
    return (
        <div className="absolute top-full left-0 w-full pt-1 animate-fade-in z-[100]">
            <div className="bg-white shadow-[0_20px_60px_rgba(0,0,0,0.08)] border-t border-slate-200 min-h-[500px]">
                <div className="max-w-[1400px] mx-auto flex">

                    {/* LEFT SIDEBAR - PRODUCTS */}
                    <div className="w-72 bg-slate-50 p-8 border-r border-slate-100">
                        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-6">Products</h4>
                        <div className="space-y-4">
                            {VISME_PRODUCTS.map((prod, i) => (
                                <a href="#" key={i} className="flex items-start gap-4 group p-2 rounded-xl hover:bg-white hover:shadow-md transition-all">
                                    <div className={`w-10 h-10 rounded-lg ${prod.color} text-white flex items-center justify-center shrink-0 shadow-sm shadow-${prod.color.replace('bg-', '')}/30`}>
                                        <prod.icon className="w-5 h-5" />
                                    </div>
                                    <div>
                                        <div className="font-bold text-slate-800 text-sm group-hover:text-blue-600 transition-colors">{prod.name}</div>
                                        <div className="text-[10px] text-slate-500 font-medium leading-tight mt-0.5">{prod.desc}</div>
                                    </div>
                                </a>
                            ))}
                        </div>
                    </div>

                    {/* CENTER COLS */}
                    <div className="flex-1 p-10 grid grid-cols-3 gap-12">
                        <div>
                            <h4 className="font-bold text-slate-900 mb-6">{VISME_COLS.tools.title}</h4>
                            <ul className="space-y-3">
                                {VISME_COLS.tools.items.map((item, i) => (
                                    <li key={i}><a href="#" className="text-sm text-slate-600 hover:text-blue-600 font-medium transition-colors block">{item}</a></li>
                                ))}
                            </ul>
                        </div>
                        <div>
                            <h4 className="font-bold text-blue-600 mb-6 flex items-center gap-1 cursor-pointer hover:underline">{VISME_COLS.ai.title}</h4>
                            <ul className="space-y-3">
                                {VISME_COLS.ai.items.map((item, i) => (
                                    <li key={i}><a href="#" className="text-sm text-slate-600 hover:text-blue-600 font-medium transition-colors flex items-center gap-2"><Sparkles className="w-3 h-3 text-purple-500" /> {item}</a></li>
                                ))}
                            </ul>
                        </div>
                        <div>
                            <h4 className="font-bold text-slate-900 mb-6">{VISME_COLS.graphics.title}</h4>
                            <ul className="space-y-3">
                                {VISME_COLS.graphics.items.map((item, i) => (
                                    <li key={i}><a href="#" className="text-sm text-slate-600 hover:text-blue-600 font-medium transition-colors block">{item}</a></li>
                                ))}
                            </ul>
                        </div>
                    </div>

                    {/* RIGHT SIDEBAR - PROMO */}
                    <div className="w-72 p-8 border-l border-slate-100 flex flex-col justify-between">
                        <div>
                            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-6">What's New</h4>
                            <div className="bg-slate-900 rounded-2xl p-6 text-white relative overflow-hidden group cursor-pointer hover:shadow-xl transition-shadow aspect-square flex flex-col justify-end">
                                <div className="absolute top-0 right-0 w-32 h-32 bg-blue-500/30 rounded-full blur-3xl -mr-10 -mt-10"></div>
                                <div className="absolute bottom-0 left-0 w-24 h-24 bg-purple-500/30 rounded-full blur-2xl -ml-6 -mb-6"></div>
                                <div className="relative z-10">
                                    <div className="bg-white/20 backdrop-blur-md w-fit px-3 py-1 rounded-full text-[10px] font-bold mb-4 border border-white/20">NEW REPORT</div>
                                    <h3 className="text-xl font-bold mb-2">2026 Strategy</h3>
                                    <p className="text-xs text-slate-300 mb-6 line-clamp-3">Future of business compliance.</p>
                                    <div className="text-xs font-bold text-blue-300 group-hover:text-white transition-colors flex items-center gap-2">Read Report <ArrowRight className="w-3 h-3" /></div>
                                </div>
                            </div>
                        </div>
                        <div className="text-[10px] text-slate-400 text-center">
                            &copy; 2026 VR HERE. All rights reserved.
                        </div>
                    </div>

                </div>
            </div>
        </div>
    )
}

// --- SERVICES TO TYPE ---
const TYPING_WORDS = [
    "Private Ltd Registration",
    "GST Filing",
    "Trademark",
    "ISO Certification",
    "Startup India",
    "Accounting"
];

// --- TYPEWRITER HOOK ---
const useTypewriter = (words = TYPING_WORDS, speed = 100, pause = 1500) => {
    const [index, setIndex] = useState(0);
    const [subIndex, setSubIndex] = useState(0);
    const [reverse, setReverse] = useState(false);
    const [blink, setBlink] = useState(true);

    useEffect(() => {
        const timeout2 = setInterval(() => setBlink((prev) => !prev), 500);
        return () => clearInterval(timeout2);
    }, []);

    useEffect(() => {
        if (subIndex === words[index].length + 1 && !reverse) {
            setTimeout(() => setReverse(true), pause);
            return;
        }
        if (subIndex === 0 && reverse) {
            setReverse(false);
            setIndex((prev) => (prev + 1) % words.length);
            return;
        }
        const timeout = setTimeout(() => {
            setSubIndex((prev) => prev + (reverse ? -1 : 1));
        }, Math.max(reverse ? 50 : subIndex === words[index].length ? 1000 : speed, parseInt(Math.random() * 50)));

        return () => clearTimeout(timeout);
    }, [subIndex, index, reverse, words, speed, pause]);

    return `${words[index].substring(0, subIndex)}${blink ? "|" : ""}`;
};


const FunctionalSearch = ({ variant = 'default' }) => {
    const [query, setQuery] = useState('');
    const [suggestions, setSuggestions] = useState([]);
    const [isOpen, setIsOpen] = useState(false);
    const [isExpanded, setIsExpanded] = useState(false);
    const wrapperRef = useRef(null);
    const inputRef = useRef(null);
    const typewriterText = useTypewriter();

    useEffect(() => {
        const handleClickOutside = (event) => {
            if (wrapperRef.current && !wrapperRef.current.contains(event.target)) {
                setIsOpen(false);
                setIsExpanded(false);
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

    const toggleExpand = () => {
        setIsExpanded(true);
        setTimeout(() => inputRef.current?.focus(), 100);
    };

    // --- STYLES ---
    let containerClasses = "";
    let inputClasses = "";
    let iconClass = "";
    let placeholderText = `Search for ${typewriterText.replace('|', '')}`;

    if (variant === 'dark') {
        containerClasses = "bg-slate-800/50 border-slate-700 text-white focus-within:bg-slate-800 focus-within:ring-2 focus-within:ring-red-500/50";
        inputClasses = "text-white placeholder:text-slate-400";
        iconClass = "text-white/60";
    } else if (variant === 'glass') {
        containerClasses = "bg-white/10 backdrop-blur-md border border-white/20 text-white placeholder:text-white/70 focus-within:bg-white/20 hover:bg-white/20";
        inputClasses = "text-white placeholder:text-slate-300";
        iconClass = "text-white/60";
    } else if (variant === 'expanding') {
        containerClasses = `bg-slate-100 border-slate-200 text-slate-900 transition-all duration-500 ease-out ${isExpanded ? 'w-[400px] border-red-500 ring-4 ring-red-50 shadow-lg bg-white' : 'w-10 h-10 rounded-full bg-slate-100 hover:bg-slate-200 border-transparent cursor-pointer justify-center px-0'}`;
        inputClasses = `text-slate-900 placeholder:text-slate-400 transition-all ${isExpanded ? 'w-full opacity-100 ml-2' : 'w-0 opacity-0'}`;
        iconClass = "text-slate-500 shrink-0 auto";
        placeholderText = isExpanded ? `Search for ${typewriterText.replace('|', '')}` : "";
    } else if (variant === 'canva') {
        containerClasses = "bg-slate-100 hover:bg-white border-transparent text-slate-900 focus-within:bg-white focus-within:shadow-md transition-all";
        inputClasses = "text-slate-900 placeholder:text-slate-500";
        iconClass = "text-slate-500";
    } else {
        containerClasses = "bg-slate-100 border-slate-200 text-slate-900 focus-within:bg-white focus-within:ring-2 focus-within:ring-red-100 focus-within:border-red-500 shadow-inner";
        inputClasses = "text-slate-900 placeholder:text-slate-500";
        iconClass = "text-slate-500";
    }

    return (
        <div className={`relative z-[60] ${variant === 'expanding' ? 'flex justify-end' : 'w-full'}`} ref={wrapperRef}>
            <div
                className={`flex items-center rounded-full border ${variant !== 'expanding' && 'px-4 py-3'} ${variant === 'expanding' && isExpanded ? 'px-4 py-2.5' : ''} ${variant === 'expanding' && !isExpanded ? 'active:scale-95' : ''} ${containerClasses}`}
                onClick={variant === 'expanding' ? toggleExpand : undefined}
            >
                <Search className={`w-4 h-4 ${iconClass}`} />
                <input
                    ref={inputRef}
                    type="text"
                    placeholder={placeholderText}
                    className={`bg-transparent border-none outline-none text-sm font-medium ${inputClasses}`}
                    value={query}
                    onChange={handleSearch}
                    onFocus={() => { if (query.length > 1) setIsOpen(true); }}
                />
                {query && isExpanded && <X className={`w-4 h-4 cursor-pointer hover:text-red-500 ${iconClass} ml-2`} onClick={(e) => { e.stopPropagation(); setQuery(''); setIsOpen(false); inputRef.current.focus(); }} />}
            </div>

            {isOpen && (
                <div className={`absolute top-full mt-3 bg-white rounded-2xl shadow-xl border border-slate-100 overflow-hidden animate-fade-in origin-top transform transition-all ring-1 ring-black/5 ${variant === 'expanding' ? 'right-0 w-[400px]' : 'left-0 right-0'}`}>
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
                        <div className="p-1">
                            <div className="bg-gradient-to-br from-slate-900 to-slate-800 rounded-xl p-6 text-center text-white relative overflow-hidden">
                                <div className="absolute top-0 right-0 w-32 h-32 bg-red-600/20 rounded-full blur-3xl -mr-10 -mt-10"></div>
                                <div className="absolute bottom-0 left-0 w-24 h-24 bg-blue-600/20 rounded-full blur-2xl -ml-6 -mb-6"></div>
                                <div className="relative z-10">
                                    <div className="w-12 h-12 bg-white/10 backdrop-blur-md rounded-full flex items-center justify-center mx-auto mb-3 border border-white/10 shadow-lg">
                                        <HelpCircle className="w-6 h-6 text-red-400" />
                                    </div>
                                    <h4 className="text-lg font-bold mb-1">Couldn't find "{query}"</h4>
                                    <p className="text-xs text-slate-300 mb-5 max-w-[200px] mx-auto">Don't worry, we offer custom solutions for almost everything.</p>
                                    <a href={`/contact?service=${encodeURIComponent(query)}`} className="inline-flex items-center justify-center w-full px-4 py-3 bg-red-600 hover:bg-red-500 text-white text-sm font-bold rounded-lg transition shadow-lg shadow-red-900/20 group">
                                        <MessageCircle className="w-4 h-4 mr-2" /> Request Callback
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

// PREVIEW WRAPPER: Added min-h-[500px] to ensure dropdowns don't feel cramped/cutoff
const HeaderPreview = ({ title, children, color = "bg-white" }) => (
    <div className={`w-full ${color} py-12 border-b border-slate-200 relative group min-h-[500px]`}>
        <div className="absolute top-4 left-4 z-20 bg-black text-white px-3 py-1 text-[10px] font-bold uppercase rounded shadow-lg opacity-30 group-hover:opacity-100 transition-opacity">
            {title}
        </div>
        {children}
    </div>
);

// MAIN COMPONENT
const HeaderDesignOptions = () => {
    const [hoveredState, setHoveredState] = useState([false, false, false, false, false, false, false, false, false, false, false, false]);

    const setHover = (index, val) => {
        const newState = [...hoveredState];
        newState[index] = val;
        setHoveredState(newState);
    }

    return (
        <div className="bg-slate-100 font-sans text-slate-800 min-h-screen">

            {/* --- NEW OPTION 11: VISME STYLE --- */}
            <HeaderPreview title="Option 11: Visme Style (Structured)" color="bg-white">
                <div className="relative isolate max-w-full mx-auto bg-white shadow-sm" onMouseLeave={() => setHover(10, false)}>
                    <header className="bg-white px-8 h-20 flex items-center justify-between z-[60] relative border-b border-transparent hover:border-slate-100 transition-colors">
                        <div className="flex items-center gap-10">
                            <div className="flex items-center gap-2 cursor-pointer">
                                {/* Visme Logo Style */}
                                <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white font-black text-xs shadow-md">V</div>
                                <div className="font-bold text-xl tracking-tight text-slate-900">visme</div>
                            </div>

                            <nav className="hidden xl:flex items-center gap-6 font-medium text-sm text-slate-600">
                                <div className="relative h-20 flex items-center" onMouseEnter={() => setHover(10, true)}>
                                    <button className={`flex items-center gap-1 transition-colors ${hoveredState[10] ? 'text-blue-600' : 'hover:text-blue-600'}`}>
                                        Create <ChevronDown className={`w-3 h-3 transition-transform ${hoveredState[10] ? 'rotate-180' : ''}`} />
                                    </button>
                                </div>
                                <a href="#" className="hover:text-blue-600 transition-colors flex items-center gap-1">Solutions <ChevronDown className="w-3 h-3" /></a>
                                <a href="#" className="hover:text-blue-600 transition-colors flex items-center gap-1">Templates <ChevronDown className="w-3 h-3" /></a>
                                <a href="#" className="hover:text-blue-600 transition-colors">Pricing</a>
                            </nav>
                        </div>

                        <div className="flex items-center gap-6">
                            <button className="text-slate-500 hover:text-slate-900 font-bold text-sm">Log in</button>
                            <button className="bg-blue-600 text-white px-5 py-2.5 rounded-lg font-bold text-sm hover:bg-blue-700 transition-colors shadow-lg shadow-blue-200">Sign Up Free</button>
                        </div>
                    </header>
                    <div className="absolute left-0 w-full z-[80]"><VismeMegaMenu isOpen={hoveredState[10]} /></div>
                </div>
            </HeaderPreview>

            {/* --- NEW OPTION 10: CANVA STYLE (UPDATED) --- */}
            <HeaderPreview title="Option 10: Canva Style (Enhanced)" color="bg-slate-50">
                <div className="relative isolate max-w-full mx-auto bg-white shadow-sm" onMouseLeave={() => setHover(9, false)}>
                    <header className="bg-white px-6 h-20 flex items-center justify-between z-[60] relative">
                        <div className="flex items-center gap-8">
                            <div className="flex items-center gap-2 cursor-pointer">
                                {/* Canva ish Logo */}
                                <div className="w-10 h-10 bg-gradient-to-br from-[#7D2AE8] to-[#00C4CC] rounded-lg flex items-center justify-center text-white font-black text-xl shadow-md">VR</div>
                                <div className="font-bold text-lg tracking-tight text-slate-900">VR HERE</div>
                            </div>

                            <nav className="hidden xl:flex items-center gap-1 font-medium text-sm text-slate-600">
                                <a href="#" className="px-3 py-2 hover:bg-slate-100 rounded-md transition-colors">Design Spotlight</a>
                                <a href="#" className="px-3 py-2 hover:bg-slate-100 rounded-md transition-colors">Business</a>
                                <a href="#" className="px-3 py-2 hover:bg-slate-100 rounded-md transition-colors">Education</a>

                                <div className="relative h-20 flex items-center" onMouseEnter={() => setHover(9, true)}>
                                    <button className={`px-3 py-2 flex items-center gap-1 rounded-md transition-colors ${hoveredState[9] ? 'text-purple-600 bg-purple-50' : 'hover:bg-slate-100'}`}>
                                        Services <ChevronDown className="w-3 h-3 transition-transform group-hover:rotate-180" />
                                    </button>
                                </div>

                                <a href="#" className="px-3 py-2 hover:bg-slate-100 rounded-md transition-colors">Plans & Pricing</a>
                                <a href="#" className="px-3 py-2 hover:bg-slate-100 rounded-md transition-colors">Learn</a>
                            </nav>
                        </div>

                        <div className="flex items-center gap-4">
                            <div className="w-64"><FunctionalSearch variant="canva" /></div>
                            <button className="bg-[#7D2AE8] text-white px-5 py-2.5 rounded-lg font-bold text-sm shadow-md shadow-purple-200 hover:bg-purple-700 transition-colors">Get Started</button>
                        </div>
                    </header>
                    <div className="absolute left-0 w-full z-[80]"><CanvaMegaMenu isOpen={hoveredState[9]} /></div>
                </div>
            </HeaderPreview>

            <HeaderPreview title="Option 3: Hybrid Split (Fixed)" color="bg-slate-50">
                <div className="relative isolate max-w-[1400px] mx-auto shadow-xl rounded-2xl overflow-visible bg-[#1e293b]" onMouseLeave={() => setHover(0, false)}>
                    <header className="bg-[#1e293b] text-white py-3 px-8 rounded-t-2xl z-[60] relative">
                        <div className="grid grid-cols-3 items-center">
                            <div className="flex items-center gap-6 justify-self-start">
                                <div className="bg-white/10 p-2 rounded-lg cursor-pointer hover:bg-white/20 transition"><Menu className="w-5 h-5 text-white" /></div>
                                <div className="relative h-12 flex items-center" onMouseEnter={() => setHover(0, true)}>
                                    <button className={`flex items-center gap-2 text-sm font-bold transition ${hoveredState[0] ? 'text-white' : 'text-slate-300'}`}>All Services <ChevronDown className="w-4 h-4 opacity-50" /></button>
                                </div>
                            </div>
                            <div className="justify-self-center"><Logo theme="light" /></div>
                            <div className="justify-self-end flex items-center gap-5">
                                <button className="bg-white text-slate-900 px-5 py-2 rounded-lg font-bold text-xs hover:bg-slate-100 transition flex items-center gap-2"><span>Get Started</span> <ArrowRight className="w-3.5 h-3.5" /></button>
                            </div>
                        </div>
                    </header>
                    <div className="absolute left-0 w-full z-[80]"><MegaMenu isOpen={hoveredState[0]} /></div>

                    <div className="bg-white py-3 px-8 flex justify-center border-t border-slate-100 rounded-b-2xl">
                        <div className="w-full flex justify-center gap-8 text-[10px] font-bold uppercase tracking-wide text-slate-500">
                            <span className="hover:text-red-600 cursor-pointer">Startup Registration</span>
                            <span className="hover:text-red-600 cursor-pointer">GST & Tax</span>
                            <span className="hover:text-red-600 cursor-pointer">Industrial Setup</span>
                        </div>
                    </div>
                </div>
            </HeaderPreview>

            <HeaderPreview title="Option 4: Minimalist + Expanding Search">
                <div className="relative isolate max-w-[1600px] mx-auto shadow-xl bg-white rounded-2xl" onMouseLeave={() => setHover(1, false)}>
                    <header className="bg-white border-b border-slate-100 z-[60] relative rounded-t-2xl">
                        <div className="px-6 h-20 flex items-center justify-between gap-8">
                            <Logo theme="dark" />
                            <div className="flex-1 flex justify-center"><FunctionalSearch variant="expanding" /></div>
                            <div className="flex items-center gap-6">
                                <div className="h-20 flex items-center relative" onMouseEnter={() => setHover(1, true)}>
                                    <button className={`px-4 py-2 flex items-center text-sm font-bold rounded-md transition-all ${hoveredState[1] ? 'bg-red-50 text-red-600' : 'text-slate-700 hover:text-slate-900'}`}>Services <ChevronDown className="ml-1 w-4 h-4" /></button>
                                </div>
                                <div className="h-8 w-px bg-slate-100"></div>
                                <button className="bg-black text-white px-6 py-2.5 rounded-full font-bold text-sm hover:bg-slate-800 transition shadow-lg shadow-black/20">Get Started</button>
                            </div>
                        </div>
                    </header>
                    <div className="absolute left-0 w-full z-[80]"><MegaMenu isOpen={hoveredState[1]} /></div>
                    <div className="h-8 bg-white rounded-b-2xl"></div>
                </div>
            </HeaderPreview>

            <HeaderPreview title="Option 5: Dark Premium" color="bg-slate-900">
                <div className="relative isolate max-w-[1400px] mx-auto shadow-2xl bg-[#0f172a] rounded-xl overflow-visible" onMouseLeave={() => setHover(2, false)}>
                    <header className="text-white z-[60] relative rounded-xl">
                        <div className="px-6 h-24 flex items-center justify-between">
                            <div className="flex items-center gap-12">
                                <Logo theme="light" size="large" />
                                <div className="hidden lg:block w-96"><FunctionalSearch variant="dark" /></div>
                            </div>
                            <div className="flex items-center gap-8">
                                <nav className="h-24 flex items-center relative" onMouseEnter={() => setHover(2, true)}>
                                    <button className={`flex items-center gap-2 text-base font-bold transition-all px-4 py-2 rounded-lg ${hoveredState[2] ? 'bg-white/10 text-white' : 'text-slate-300 hover:text-white'}`}>Explore Services <ChevronDown className="w-4 h-4" /></button>
                                </nav>
                                <button className="bg-red-600 text-white px-8 py-3 rounded-xl font-bold text-sm shadow-lg shadow-red-900/50 hover:bg-red-500 transition-all">Book Expert</button>
                            </div>
                        </div>
                    </header>
                    <div className="absolute left-0 w-full z-[80]"><MegaMenu isOpen={hoveredState[2]} /></div>
                </div>
            </HeaderPreview>

            <HeaderPreview title="Option 6: Centered Stack">
                <div className="relative isolate max-w-[1400px] mx-auto shadow-xl bg-white rounded-xl overflow-visible" onMouseLeave={() => setHover(3, false)}>
                    <header className="bg-white pt-6 pb-0 z-[60] relative rounded-t-xl">
                        <div className="px-6 pb-6 flex items-center justify-between gap-12">
                            <Logo theme="dark" size="large" />
                            <div className="flex-1 max-w-2xl"><FunctionalSearch /></div>
                            <div className="flex items-center gap-4">
                                <button className="bg-slate-100 p-3 rounded-full hover:bg-red-50 text-slate-600 hover:text-red-600 transition"><User className="w-5 h-5" /></button>
                            </div>
                        </div>
                        <div className="border-t border-slate-100 bg-white">
                            <div className="px-6 flex items-center justify-center">
                                <div className="relative group p-2" onMouseEnter={() => setHover(3, true)}>
                                    <button className="bg-red-600 text-white px-8 py-3 font-bold text-sm flex items-center gap-2 hover:bg-black transition-colors rounded-t-lg"><Menu className="w-5 h-5" /> ALL SERVICES </button>
                                </div>
                            </div>
                        </div>
                    </header>
                    <div className="absolute left-0 w-full z-[80]"><MegaMenu isOpen={hoveredState[3]} /></div>

                    {/* Filler for stack look */}
                    <div className="h-12 bg-white rounded-b-xl"></div>
                </div>
            </HeaderPreview>

            <HeaderPreview title="Option 7: Dynamic Island" color="bg-slate-200">
                <div className="relative isolate flex items-start justify-center pt-8" onMouseLeave={() => setHover(4, false)}>
                    <div className="z-[60] px-4 w-full">
                        <header className="bg-white/90 backdrop-blur-xl max-w-[1200px] mx-auto rounded-full shadow-2xl border border-white/50 p-2 pl-6 flex items-center justify-between transition-all">
                            <div className="flex items-center gap-8">
                                <Logo theme="dark" size="normal" />
                                <div className="hidden md:flex items-center bg-slate-100/50 rounded-full px-1 border border-slate-200/50">
                                    <div className="relative py-2 px-4" onMouseEnter={() => setHover(4, true)}>
                                        <div className="cursor-pointer text-sm font-bold text-red-600 flex items-center gap-1">Services <ChevronDown className="w-3 h-3" /></div>
                                    </div>
                                </div>
                            </div>
                            <div className="w-96 mx-4"><FunctionalSearch /></div>
                            <div className="flex items-center pr-2">
                                <button className="w-10 h-10 bg-black text-white rounded-full flex items-center justify-center hover:bg-red-600 transition shadow-lg"><LogIn className="w-4 h-4" /></button>
                            </div>
                        </header>
                        <div className="absolute top-24 left-0 w-full z-[80] flex justify-center">
                            <div className="max-w-[1200px] w-full"><MegaMenu isOpen={hoveredState[4]} /></div>
                        </div>
                    </div>
                </div>
            </HeaderPreview>

            <HeaderPreview title="Option 8: Glassmorphism" color="bg-slate-900">
                {/* Background Gradeint */}
                <div className="absolute inset-0 bg-gradient-to-br from-indigo-900 via-slate-900 to-red-900 opacity-50"></div>

                <div className="relative isolate max-w-[1400px] mx-auto pt-8" onMouseLeave={() => setHover(5, false)}>
                    <header className="bg-white/5 backdrop-blur-xl border border-white/10 text-white shadow-2xl rounded-xl z-[60] relative">
                        <div className="px-6 h-24 flex items-center justify-between">
                            <Logo theme="light" />
                            <div className="flex-1 max-w-xl mx-12"><FunctionalSearch variant="glass" /></div>
                            <div className="flex items-center gap-8">
                                <div className="relative h-24 flex items-center" onMouseEnter={() => setHover(5, true)}>
                                    <button className="flex items-center gap-2 text-sm font-bold tracking-wider hover:text-red-400 transition">EXPLORE <Sparkles className="w-3 h-3 text-yellow-400" /></button>
                                </div>
                                <button className="w-10 h-10 rounded-xl bg-white/10 border border-white/20 flex items-center justify-center hover:bg-red-600 transition-all"><User className="w-5 h-5" /></button>
                            </div>
                        </div>
                    </header>
                    <div className="absolute left-0 w-full z-[80]"><MegaMenu isOpen={hoveredState[5]} /></div>
                </div>
            </HeaderPreview>

            <HeaderPreview title="Option 9: Power Search">
                <div className="relative isolate max-w-[1400px] mx-auto shadow-2xl bg-white rounded-xl" onMouseLeave={() => setHover(6, false)}>
                    <header className="bg-white border-b-4 border-black z-[60] relative rounded-t-xl">
                        <div className="flex flex-col md:flex-row">
                            <div className="bg-black text-white p-6 md:w-64 flex-shrink-0 flex items-center justify-center rounded-tl-xl"><Logo theme="light" /></div>
                            <div className="flex-1 flex flex-col">
                                <div className="flex items-center justify-between p-4 border-b border-slate-100 bg-slate-50 text-slate-800 rounded-tr-xl">
                                    <div className="flex-1 max-w-2xl"><FunctionalSearch /></div>
                                    <div className="flex items-center gap-6 px-6">
                                        <button className="bg-red-600 text-white px-6 py-2 rounded-lg font-black text-xs uppercase tracking-wider hover:bg-black transition shadow-lg">Login</button>
                                    </div>
                                </div>
                                <div className="bg-white px-6 py-2 flex gap-8 relative">
                                    <div className="relative group py-2" onMouseEnter={() => setHover(6, true)}>
                                        <button className="font-black text-sm uppercase tracking-widest hover:text-red-600 border-b-4 border-transparent hover:border-red-600 transition-all">All Services</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </header>
                    <div className="absolute left-0 w-full z-[80]"><MegaMenu isOpen={hoveredState[6]} /></div>
                    <div className="h-12 bg-white rounded-b-xl border-t border-slate-100"></div>
                </div>
            </HeaderPreview>

        </div>
    );
};

export default HeaderDesignOptions;
