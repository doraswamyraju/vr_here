import React, { useState } from 'react';
import {
    Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
    ArrowRight, CheckCircle2, Star, Sparkles, MoveUpRight, Box, Hexagon, Layers,
    ChevronDown, ChevronUp, Search, HelpCircle, MessageSquarePlus
} from 'lucide-react';
import { MENU_DATA } from './components/SharedComponents';

const ServicePreviewSection = ({ title, children, className = "bg-white" }) => (
    <div className={`py-16 px-4 border-b border-slate-200 relative group ${className}`}>
        <div className="absolute top-4 left-4 z-20 bg-black text-white px-3 py-1 text-[10px] font-bold uppercase rounded shadow-lg opacity-30 group-hover:opacity-100 transition-opacity">
            {title}
        </div>
        <div className="max-w-7xl mx-auto">
            {children}
        </div>
    </div>
);

const ServiceCardDesignOptions = () => {

    // --- OPTION 1: MINIMALIST CLEAN ---
    const MinimalistCard = ({ item, isNotFound = false }) => {
        const [showAll, setShowAll] = useState(false);

        if (isNotFound) {
            return (
                <div className="group bg-slate-50 p-6 rounded-2xl border-2 border-dashed border-slate-300 hover:border-red-400 hover:bg-red-50 transition-all duration-300 flex flex-col items-center justify-center text-center cursor-pointer h-full min-h-[300px]">
                    <div className="w-16 h-16 bg-white rounded-full flex items-center justify-center text-slate-400 shadow-sm mb-4 group-hover:text-red-600 group-hover:scale-110 transition-all">
                        <Search className="w-8 h-8" />
                    </div>
                    <h3 className="text-lg font-bold text-slate-900 mb-2">Service Not Found?</h3>
                    <p className="text-sm text-slate-500 mb-6 max-w-[200px]">Don't see what you need? We provide custom solutions.</p>
                    <button className="px-6 py-2 bg-slate-900 text-white text-xs font-bold rounded-lg group-hover:bg-red-600 transition-colors">
                        Request Custom Service
                    </button>
                </div>
            )
        }

        return (
            <div className="group bg-white p-6 rounded-2xl border border-slate-100 hover:border-red-100 hover:shadow-xl hover:shadow-red-900/5 transition-all duration-300 flex flex-col h-full">
                <div className="w-12 h-12 bg-slate-50 rounded-xl flex items-center justify-center text-slate-700 mb-6 group-hover:bg-red-600 group-hover:text-white transition-colors shrink-0">
                    <item.icon className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-slate-900 mb-3">{item.title}</h3>
                <ul className="space-y-2 mb-6 flex-1">
                    {(showAll ? item.items : item.items.slice(0, 3)).map((sub, i) => (
                        <li key={i} className="text-xs font-medium text-slate-500 flex items-center gap-2 animate-fade-in">
                            <span className="w-1 h-1 bg-slate-300 rounded-full group-hover:bg-red-400 transition-colors shrink-0"></span>
                            {sub}
                        </li>
                    ))}
                </ul>
                <div className="flex items-center justify-between border-t border-slate-50 pt-4 mt-auto">
                    <button onClick={() => setShowAll(!showAll)} className="text-[10px] font-bold uppercase tracking-wider text-slate-400 hover:text-slate-700 flex items-center gap-1">
                        {showAll ? 'Show Less' : 'View All'} <ChevronDown className={`w-3 h-3 transition-transform ${showAll ? 'rotate-180' : ''}`} />
                    </button>
                    <button className="text-xs font-bold text-slate-400 flex items-center gap-1 group-hover:text-red-600 transition-colors">
                        Explore <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-1" />
                    </button>
                </div>
            </div>
        );
    };

    // --- OPTION 2: GLASSMORPHISM GRADIENT ---
    const GlassCard = ({ item, isNotFound = false }) => {
        if (isNotFound) {
            return (
                <div className="group relative overflow-hidden rounded-3xl p-1 h-full min-h-[300px] cursor-pointer">
                    <div className="absolute inset-0 bg-white/5 backdrop-blur-sm border-2 border-dashed border-white/20 rounded-3xl z-10 hover:bg-white/10 hover:border-white/40 transition-all"></div>
                    <div className="relative z-20 p-6 flex flex-col items-center justify-center h-full text-white text-center">
                        <div className="w-14 h-14 rounded-full bg-white/10 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                            <HelpCircle className="w-8 h-8 text-white/80" />
                        </div>
                        <h3 className="text-xl font-bold mb-2">Can't Find It?</h3>
                        <p className="text-xs text-indigo-100 mb-6 opacity-70">Tell us what you need. We'll make it happen.</p>
                        <button className="px-6 py-2 rounded-full bg-white text-indigo-900 font-bold text-xs hover:bg-indigo-50 transition-colors">Contact Us</button>
                    </div>
                </div>
            )
        }

        return (
            <div className="group relative overflow-hidden rounded-3xl p-1 h-full">
                <div className="absolute inset-0 bg-white/10 backdrop-blur-lg border border-white/20 rounded-3xl z-10 hover:bg-white/20 transition-all"></div>
                <div className="relative z-20 p-6 flex flex-col h-full text-white">
                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center mb-4 shadow-lg group-hover:scale-110 transition-transform shrink-0">
                        <item.icon className="w-5 h-5 text-white" />
                    </div>
                    <h3 className="text-xl font-bold mb-2">{item.title}</h3>

                    <div className="flex-1 overflow-hidden relative group/list">
                        <div className="space-y-1 mb-4 max-h-[100px] overflow-y-auto pr-2 scrollbar-thin scrollbar-white">
                            {item.items.map((sub, i) => (
                                <div key={i} className="text-xs text-indigo-100/70 py-1 border-b border-indigo-200/10 last:border-0 hover:text-white transition-colors">{sub}</div>
                            ))}
                        </div>
                    </div>

                    <div className="mt-auto pt-4 border-t border-white/10 flex justify-between items-center">
                        <span className="text-[10px] font-bold uppercase tracking-wider opacity-60">
                            {item.items.length} Services
                        </span>
                        <div className="w-8 h-8 rounded-full bg-white/10 flex items-center justify-center group-hover:bg-white group-hover:text-indigo-600 transition-all cursor-pointer">
                            <MoveUpRight className="w-4 h-4" />
                        </div>
                    </div>
                </div>
            </div>
        );
    };

    // --- OPTION 3: BENTO GRID HOVER ---
    const BentoCard = ({ item, index, isNotFound = false }) => {
        const isWide = !isNotFound && (index === 0 || index === 3 || index === 6);

        if (isNotFound) {
            return (
                <div className={`group bg-slate-900 rounded-3xl p-8 hover:bg-black transition-all duration-500 relative overflow-hidden flex flex-col items-center justify-center text-center`}>
                    <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-10"></div>
                    <MessageSquarePlus className="w-16 h-16 text-slate-700 group-hover:text-white transition-colors mb-4" />
                    <h3 className="text-2xl font-black text-white mb-2">Custom Service</h3>
                    <p className="text-slate-400 text-sm mb-6">Need something specific? Let's talk.</p>
                    <button className="bg-white text-black px-6 py-2 rounded-full font-bold hover:scale-105 transition-transform">Get in Touch</button>
                </div>
            )
        }

        return (
            <div className={`group bg-slate-50 rounded-3xl p-8 hover:bg-white hover:shadow-2xl transition-all duration-500 relative overflow-hidden ${isWide ? 'md:col-span-2' : ''}`}>
                <div className="absolute top-0 right-0 p-8 opacity-10 group-hover:opacity-100 group-hover:scale-125 transition-all duration-500">
                    <item.icon className="w-32 h-32 text-slate-900" />
                </div>

                <div className="relative z-10 h-full flex flex-col justify-between">
                    <div>
                        <div className="mb-4 inline-flex p-3 bg-white rounded-2xl shadow-sm text-slate-900 group-hover:bg-black group-hover:text-white transition-colors">
                            <item.icon className="w-6 h-6" />
                        </div>
                        <h3 className="text-2xl font-black text-slate-900 mb-1 leading-tight">{item.title}</h3>
                        <div className="w-12 h-1 bg-red-500 rounded my-4 w-0 group-hover:w-12 transition-all duration-500"></div>
                    </div>

                    <div className="translate-y-4 opacity-0 group-hover:translate-y-0 group-hover:opacity-100 transition-all duration-300 delay-75">
                        <div className="flex flex-wrap gap-2 mb-4">
                            {item.items.slice(0, isWide ? 6 : 3).map((sub, i) => (
                                <span key={i} className="text-[10px] font-bold uppercase bg-slate-100 px-2 py-1 rounded text-slate-600 border border-slate-200">{sub}</span>
                            ))}
                            {item.items.length > (isWide ? 6 : 3) && (
                                <span className="text-[10px] font-bold uppercase bg-slate-200 px-2 py-1 rounded text-slate-800 border border-slate-300">+{item.items.length - (isWide ? 6 : 3)} More</span>
                            )}
                        </div>
                        <button className="text-xs font-bold underline decoration-slate-300 hover:decoration-red-600 underline-offset-4">View All Services</button>
                    </div>
                </div>
            </div>
        );
    };

    // --- OPTION 4: NEO-BRUTALISM ---
    const BrutalCard = ({ item, isNotFound = false }) => {
        const [showAll, setShowAll] = useState(false);

        if (isNotFound) {
            return (
                <div className="bg-slate-200 border-2 border-black border-dashed p-6 flex flex-col justify-center items-center text-center hover:bg-red-50 transition-colors h-full min-h-[350px]">
                    <h3 className="text-xl font-black text-black mb-2 uppercase">Not Found?</h3>
                    <p className="text-xs font-bold mb-4 font-mono">ERROR 404: SERVICE NOT LISTED</p>
                    <button className="px-4 py-2 bg-red-600 text-white font-black border-2 border-black hover:translate-x-[2px] hover:translate-y-[2px] shadow-[4px_4px_0px_0px_rgba(0,0,0,1)] hover:shadow-none transition-all">
                        REQUEST CUSTOM
                    </button>
                </div>
            )
        }

        return (
            <div className={`bg-white border-2 border-black p-6 shadow-[6px_6px_0px_0px_rgba(0,0,0,1)] hover:shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] hover:translate-x-[2px] hover:translate-y-[2px] transition-all cursor-pointer flex flex-col h-full ${showAll ? 'row-span-2' : ''}`}>
                <div className="flex justify-between items-start mb-6 shrink-0">
                    <div className="bg-yellow-400 p-2 border-2 border-black">
                        <item.icon className="w-6 h-6 text-black" />
                    </div>
                    <div className="text-xs font-black bg-black text-white px-2 py-1">#{item.id}</div>
                </div>
                <h3 className="text-xl font-black text-black mb-4 uppercase leading-none shrink-0">{item.title}</h3>

                <div className="space-y-2 mb-6 flex-1 overflow-visible">
                    {(showAll ? item.items : item.items.slice(0, 3)).map((sub, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs font-bold text-slate-700">
                            <div className="w-1.5 h-1.5 bg-black"></div> {sub}
                        </div>
                    ))}
                </div>

                <div className="mt-auto pt-4 border-t-2 border-black border-dashed flex gap-2">
                    <button onClick={() => setShowAll(!showAll)} className="flex-1 py-2 bg-white text-black font-bold border-2 border-black hover:bg-slate-100 text-[10px] uppercase">
                        {showAll ? 'Less' : 'View All'}
                    </button>
                    <button className="flex-1 py-2 bg-black text-white font-bold border-2 border-black hover:bg-red-600 transition-colors text-[10px] uppercase">
                        Details
                    </button>
                </div>
            </div>
        );
    };

    // --- OPTION 5: INTERACTIVE 3D ---
    const InteractiveCard = ({ item, isNotFound = false }) => {
        if (isNotFound) {
            return (
                <div className="group h-full bg-white rounded-2xl p-1 shadow-sm hover:shadow-xl transition-all duration-300 min-h-[300px]">
                    <div className="bg-slate-100 h-full rounded-xl p-6 border-2 border-dashed border-slate-300 flex flex-col items-center justify-center text-center group-hover:border-red-400 transition-colors">
                        <div className="w-12 h-12 bg-white rounded-full shadow-sm flex items-center justify-center mb-4">
                            <Search className="w-6 h-6 text-slate-400" />
                        </div>
                        <h3 className="font-bold text-slate-700 mb-1">Looking for something else?</h3>
                        <button className="mt-4 px-4 py-2 bg-white text-red-600 font-bold text-xs rounded-lg shadow-sm hover:shadow-md transition-all">Submit Request</button>
                    </div>
                </div>
            )
        }

        return (
            <div className="group h-full bg-white rounded-2xl p-1 shadow-sm hover:shadow-xl transition-all duration-300">
                <div className="bg-slate-50 h-full rounded-xl p-6 group-hover:bg-slate-900 transition-colors duration-500 group-hover:text-white relative overflow-hidden flex flex-col">
                    <div className="absolute -top-10 -right-10 w-40 h-40 bg-slate-200 rounded-full group-hover:bg-slate-800 transition-colors duration-500"></div>

                    <div className="relative z-10 flex-1 flex flex-col">
                        <item.icon className="w-8 h-8 text-red-600 mb-6" />
                        <h3 className="text-lg font-bold text-slate-900 group-hover:text-white mb-2">{item.title}</h3>

                        <div className="space-y-1 mb-6 flex-1">
                            {item.items.map((sub, i) => (
                                <div key={i} className="text-xs text-slate-500 group-hover:text-slate-400 hidden group-hover:block animate-fade-in">{sub}</div>
                            ))}
                            <p className="text-xs text-slate-500 group-hover:hidden whitespace-pre-line">
                                Comprehensive solutions for <br /> {item.title} needs.
                            </p>
                        </div>

                        <div className="flex items-center justify-between mt-auto">
                            <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">View All</span>
                            <div className="flex items-center gap-2 text-xs font-bold text-slate-900 group-hover:text-red-400 uppercase tracking-wider">
                                Explore <ArrowRight className="w-3 h-3" />
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        );
    };

    // --- OPTION 6: CORPORATE LIST ---
    const CorporateCard = ({ item, isNotFound = false }) => {
        const [showAll, setShowAll] = useState(false);

        if (isNotFound) {
            return (
                <div className="bg-slate-50 border-l-4 border-slate-300 p-6 flex items-center justify-between h-full hover:bg-red-50 hover:border-red-600 transition-colors cursor-pointer group">
                    <div className="flex items-center gap-4">
                        <HelpCircle className="w-10 h-10 text-slate-300 group-hover:text-red-600 transition-colors" />
                        <div>
                            <h3 className="text-lg font-bold text-slate-700 group-hover:text-red-700">Service Not Found?</h3>
                            <p className="text-xs text-slate-500">Contact our experts for help.</p>
                        </div>
                    </div>
                </div>
            )
        }

        return (
            <div className={`bg-white border-l-4 border-red-600 p-6 shadow-sm hover:shadow-lg transition-shadow relative overflow-hidden`}>
                <div className="flex items-start gap-4">
                    <div className="shrink-0">
                        <item.icon className="w-10 h-10 text-slate-300" />
                    </div>
                    <div className="flex-1 z-10">
                        <div className="flex items-center justify-between mb-3">
                            <h3 className="text-lg font-bold text-slate-900">{item.title}</h3>
                            <button onClick={() => setShowAll(!showAll)} className="text-[10px] bg-slate-100 px-2 py-1 rounded hover:bg-slate-200 text-slate-600 font-bold transition-colors">
                                {showAll ? 'Collpase' : 'View full list'}
                            </button>
                        </div>
                        <div className={`grid grid-cols-2 gap-2 transition-all ${showAll ? 'max-h-[500px]' : 'max-h-[60px] overflow-hidden'}`}>
                            {item.items.map((sub, i) => (
                                <a key={i} href="#" className="text-xs text-slate-500 hover:text-red-600 hover:underline decoration-red-600 underline-offset-2 transition-colors flex items-center gap-1">
                                    <span className="w-1 h-1 bg-red-600 rounded-full"></span> {sub}
                                </a>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        );
    };

    return (
        <div className="bg-slate-50 min-h-screen font-sans">

            {/* OPTION 1 */}
            <ServicePreviewSection title="Option 1: Modern Minimalist" className="bg-slate-50">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    {MENU_DATA.map(item => <MinimalistCard key={item.id} item={item} />)}
                    <MinimalistCard isNotFound={true} />
                </div>
            </ServicePreviewSection>

            {/* OPTION 2 */}
            <ServicePreviewSection title="Option 2: Dark Glassmorphism" className="bg-[#0f172a]">
                <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none">
                    <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/20 rounded-full blur-[100px]"></div>
                    <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-red-500/10 rounded-full blur-[100px]"></div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 relative z-10">
                    {MENU_DATA.map(item => <GlassCard key={item.id} item={item} />)}
                    <GlassCard isNotFound={true} />
                </div>
            </ServicePreviewSection>

            {/* OPTION 3 */}
            <ServicePreviewSection title="Option 3: Bento Grid Layout" className="bg-white">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                    {MENU_DATA.slice(0, 6).map((item, index) => <BentoCard key={item.id} item={item} index={index} />)}
                    <BentoCard isNotFound={true} index={99} />
                </div>
            </ServicePreviewSection>

            {/* OPTION 4 */}
            <ServicePreviewSection title="Option 4: Neo-Brutalism" className="bg-yellow-50">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                    {MENU_DATA.map(item => <BrutalCard key={item.id} item={item} />)}
                    <BrutalCard isNotFound={true} />
                </div>
            </ServicePreviewSection>

            {/* OPTION 5 */}
            <ServicePreviewSection title="Option 5: High-Contrast Interactives" className="bg-slate-100">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    {MENU_DATA.map(item => <InteractiveCard key={item.id} item={item} />)}
                    <InteractiveCard isNotFound={true} />
                </div>
            </ServicePreviewSection>

            {/* OPTION 6 */}
            <ServicePreviewSection title="Option 6: Corporate List" className="bg-white">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-6">
                    {MENU_DATA.map(item => <CorporateCard key={item.id} item={item} />)}
                    <CorporateCard isNotFound={true} />
                </div>
            </ServicePreviewSection>

        </div>
    );
};

export default ServiceCardDesignOptions;
