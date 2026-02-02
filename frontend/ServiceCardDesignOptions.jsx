import React, { useState } from 'react';
import {
    Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
    ArrowRight, CheckCircle2, Star, Sparkles, MoveUpRight, Box, Hexagon, Layers, ChevronDown
} from 'lucide-react';
import { MENU_DATA } from './components/SharedComponents';

// --- UTILS ---
// Only using first 6 for symmetry if needed, or all 8. 
// User asked for "6 creative our services options", likely meaning *Layout Styles*, not just 6 items.
// I will show ALL 8 items in 6 different STYLES.

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
    const MinimalistCard = ({ item }) => (
        <div className="group bg-white p-6 rounded-2xl border border-slate-100 hover:border-red-100 hover:shadow-xl hover:shadow-red-900/5 transition-all duration-300">
            <div className="w-12 h-12 bg-slate-50 rounded-xl flex items-center justify-center text-slate-700 mb-6 group-hover:bg-red-600 group-hover:text-white transition-colors">
                <item.icon className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-slate-900 mb-3">{item.title}</h3>
            <ul className="space-y-2 mb-6">
                {item.items.slice(0, 3).map((sub, i) => (
                    <li key={i} className="text-xs font-medium text-slate-500 flex items-center gap-2">
                        <span className="w-1 h-1 bg-slate-300 rounded-full group-hover:bg-red-400 transition-colors"></span>
                        {sub}
                    </li>
                ))}
            </ul>
            <button className="text-xs font-bold text-slate-400 flex items-center gap-1 group-hover:text-red-600 transition-colors">
                Explore <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-1" />
            </button>
        </div>
    );

    // --- OPTION 2: GLASSMORPHISM GRADIENT ---
    const GlassCard = ({ item }) => (
        <div className="group relative overflow-hidden rounded-3xl p-1">
            <div className="absolute inset-0 bg-white/10 backdrop-blur-lg border border-white/20 rounded-3xl z-10 hover:bg-white/20 transition-all"></div>
            {/* Content */}
            <div className="relative z-20 p-6 flex flex-col h-full text-white">
                <div className="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center mb-4 shadow-lg group-hover:scale-110 transition-transform">
                    <item.icon className="w-5 h-5 text-white" />
                </div>
                <h3 className="text-xl font-bold mb-2">{item.title}</h3>
                <p className="text-xs text-indigo-100 mb-4 opacity-70 leading-relaxed">
                    Comprehensive solutions including {item.items[0]} and {item.items[1]}.
                </p>
                <div className="mt-auto pt-4 border-t border-white/10 flex justify-between items-center">
                    <span className="text-[10px] font-bold uppercase tracking-wider opacity-60">Services</span>
                    <div className="w-8 h-8 rounded-full bg-white/10 flex items-center justify-center group-hover:bg-white group-hover:text-indigo-600 transition-all">
                        <MoveUpRight className="w-4 h-4" />
                    </div>
                </div>
            </div>
        </div>
    );

    // --- OPTION 3: BENTO GRID HOVER ---
    const BentoCard = ({ item, index }) => {
        // Mocking varied sizing based on index for "Bento" feel
        const isWide = index === 0 || index === 3 || index === 6;
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
                        <div className="flex flex-wrap gap-2">
                            {item.items.slice(0, 3).map((sub, i) => (
                                <span key={i} className="text-[10px] font-bold uppercase bg-slate-100 px-2 py-1 rounded text-slate-600 border border-slate-200">{sub}</span>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        );
    };

    // --- OPTION 4: NEO-BRUTALISM ---
    const BrutalCard = ({ item }) => (
        <div className="bg-white border-2 border-black p-6 shadow-[6px_6px_0px_0px_rgba(0,0,0,1)] hover:shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] hover:translate-x-[2px] hover:translate-y-[2px] transition-all cursor-pointer">
            <div className="flex justify-between items-start mb-6">
                <div className="bg-yellow-400 p-2 border-2 border-black">
                    <item.icon className="w-6 h-6 text-black" />
                </div>
                <div className="text-xs font-black bg-black text-white px-2 py-1">#{item.id}</div>
            </div>
            <h3 className="text-xl font-black text-black mb-4 uppercase leading-none">{item.title}</h3>
            <div className="space-y-2 mb-6">
                {item.items.map((sub, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs font-bold text-slate-700">
                        <div className="w-1.5 h-1.5 bg-black"></div> {sub}
                    </div>
                ))}
            </div>
            <button className="w-full py-2 bg-red-600 text-white font-bold border-2 border-black hover:bg-white hover:text-black transition-colors uppercase text-sm">
                View Details
            </button>
        </div>
    );

    // --- OPTION 5: INTERACTIVE 3D (Subtle Pivot) ---
    // CSS-only hover effect simulated with tailwind
    const InteractiveCard = ({ item }) => (
        <div className="group h-full bg-white rounded-2xl p-1 shadow-sm hover:shadow-xl transition-all duration-300">
            <div className="bg-slate-50 h-full rounded-xl p-6 group-hover:bg-slate-900 transition-colors duration-500 group-hover:text-white relative overflow-hidden">
                {/* Circle Background */}
                <div className="absolute -top-10 -right-10 w-40 h-40 bg-slate-200 rounded-full group-hover:bg-slate-800 transition-colors duration-500"></div>

                <div className="relative z-10">
                    <item.icon className="w-8 h-8 text-red-600 mb-6" />
                    <h3 className="text-lg font-bold text-slate-900 group-hover:text-white mb-2">{item.title}</h3>
                    <p className="text-xs text-slate-500 group-hover:text-slate-400 mb-6 min-h-[40px]">Expert handling of {item.items[0]} and related compliances.</p>

                    <div className="flex items-center gap-2 text-xs font-bold text-slate-900 group-hover:text-red-400 uppercase tracking-wider">
                        See Pricing <ArrowRight className="w-3 h-3" />
                    </div>
                </div>
            </div>
        </div>
    );

    // --- OPTION 6: CORPORATE LIST ---
    const CorporateCard = ({ item }) => (
        <div className="bg-white border-l-4 border-red-600 p-6 shadow-sm hover:shadow-lg transition-shadow">
            <div className="flex items-start gap-4">
                <div className="shrink-0">
                    <item.icon className="w-10 h-10 text-slate-300" />
                </div>
                <div className="flex-1">
                    <h3 className="text-lg font-bold text-slate-900 mb-3">{item.title}</h3>
                    <div className="grid grid-cols-2 gap-2">
                        {item.items.map((sub, i) => (
                            <a key={i} href="#" className="text-xs text-slate-500 hover:text-red-600 hover:underline decoration-red-600 underline-offset-2 transition-colors">
                                {sub}
                            </a>
                        ))}
                    </div>
                </div>
                <div className="self-center">
                    <ChevronDown className="w-4 h-4 text-slate-300" />
                </div>
            </div>
        </div>
    );


    return (
        <div className="bg-slate-50 min-h-screen font-sans">

            {/* OPTION 1 */}
            <ServicePreviewSection title="Option 1: Modern Minimalist" className="bg-slate-50">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    {MENU_DATA.map(item => <MinimalistCard key={item.id} item={item} />)}
                </div>
            </ServicePreviewSection>

            {/* OPTION 2 */}
            <ServicePreviewSection title="Option 2: Dark Glassmorphism" className="bg-[#0f172a]">
                {/* Background Globs */}
                <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none">
                    <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/20 rounded-full blur-[100px]"></div>
                    <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-red-500/10 rounded-full blur-[100px]"></div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 relative z-10">
                    {MENU_DATA.map(item => <GlassCard key={item.id} item={item} />)}
                </div>
            </ServicePreviewSection>

            {/* OPTION 3 */}
            <ServicePreviewSection title="Option 3: Bento Grid Layout" className="bg-white">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                    {MENU_DATA.map((item, index) => <BentoCard key={item.id} item={item} index={index} />)}
                </div>
            </ServicePreviewSection>

            {/* OPTION 4 */}
            <ServicePreviewSection title="Option 4: Neo-Brutalism" className="bg-yellow-50">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                    {MENU_DATA.map(item => <BrutalCard key={item.id} item={item} />)}
                </div>
            </ServicePreviewSection>

            {/* OPTION 5 */}
            <ServicePreviewSection title="Option 5: High-Contrast Interactives" className="bg-slate-100">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    {MENU_DATA.map(item => <InteractiveCard key={item.id} item={item} />)}
                </div>
            </ServicePreviewSection>

            {/* OPTION 6 */}
            <ServicePreviewSection title="Option 6: Corporate List" className="bg-white">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-6">
                    {MENU_DATA.map(item => <CorporateCard key={item.id} item={item} />)}
                </div>
            </ServicePreviewSection>

        </div>
    );
};

export default ServiceCardDesignOptions;
