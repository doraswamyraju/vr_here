import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lightbulb, Search, ChevronRight, X, ArrowUpRight } from 'lucide-react';
import { MENU_DATA, getServiceLink } from '../SharedComponents';

const ServicesView = ({ setActiveTab, initialQuery = '' }) => {
    const navigate = useNavigate();
    const [searchQuery, setSearchQuery] = useState(initialQuery);

    // Build a flat list of all service items for searching
    const allItems = useMemo(() => {
        const items = [];
        MENU_DATA.forEach((category) => {
            category.columns.forEach((col) => {
                col.items.forEach((item) => {
                    items.push({ item, category });
                });
            });
        });
        return items;
    }, []);

    // Filter categories and items based on search query
    const filteredCategories = useMemo(() => {
        if (!searchQuery.trim()) return MENU_DATA;

        const q = searchQuery.toLowerCase();
        return MENU_DATA
            .map((category) => ({
                ...category,
                columns: category.columns
                    .map((col) => ({
                        ...col,
                        items: col.items.filter((item) =>
                            item.toLowerCase().includes(q) ||
                            col.title?.toLowerCase().includes(q) ||
                            category.title.toLowerCase().includes(q)
                        ),
                    }))
                    .filter((col) => col.items.length > 0),
            }))
            .filter((cat) => cat.columns.length > 0);
    }, [searchQuery]);

    const totalResults = useMemo(() =>
        filteredCategories.reduce((acc, cat) =>
            acc + cat.columns.reduce((a, col) => a + col.items.length, 0), 0),
        [filteredCategories]
    );

    const handleServiceClick = (item) => {
        const computedLink = getServiceLink(item);
        if (computedLink && computedLink.startsWith('/')) {
            navigate(computedLink);
        } else if (item.toLowerCase().includes('accounting') || item.toLowerCase().includes('gst return')) {
            setActiveTab('Accounting');
        } else {
            setActiveTab('New');
        }
    };

    return (
        <div className="space-y-6 pb-20 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex justify-between items-end mb-2 px-1">
                <div>
                    <h1 className="text-2xl lg:text-3xl font-black text-slate-900 tracking-tight">Services Catalog</h1>
                    <p className="text-slate-500 text-sm">Select any specialized service to explore live packages and initiate your filing.</p>
                </div>
            </div>

            {/* Search Bar — Glowing Frame */}
            <div className="relative group">
                <div className="absolute -inset-0.5 bg-gradient-to-r from-red-600 via-rose-500 to-amber-500 rounded-2xl blur-sm opacity-35 group-hover:opacity-75 group-focus-within:opacity-100 transition-all duration-500"></div>
                <div className="relative bg-white rounded-2xl flex items-center px-4 py-3.5 gap-3 shadow-sm border border-slate-200/80">
                    <Search size={18} className="text-red-500 group-hover:scale-110 transition-transform shrink-0" />
                    <input
                        type="text"
                        autoFocus={!!initialQuery}
                        placeholder="Search for legal, registration, tax or industrial services..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="flex-1 bg-transparent border-none outline-none text-sm font-semibold text-slate-800 placeholder:text-slate-400"
                    />
                    {searchQuery && (
                        <button
                            onClick={() => setSearchQuery('')}
                            className="text-slate-400 hover:text-slate-600 p-1"
                        >
                            <X size={16} />
                        </button>
                    )}
                </div>
            </div>

            {/* Search results summary */}
            {searchQuery.trim() && (
                <div className="flex items-center gap-2 px-1">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-widest">
                        {totalResults} result{totalResults !== 1 ? 's' : ''} for
                    </span>
                    <span className="text-xs font-black text-red-600 bg-red-50 border border-red-200/80 px-2.5 py-1 rounded-full">
                        "{searchQuery}"
                    </span>
                </div>
            )}

            {/* Structured Catalog */}
            <div className="space-y-8 mt-8">
                {filteredCategories.length > 0 ? filteredCategories.map((category) => (
                    <div key={category.id} className="bg-white p-6 md:p-8 rounded-3xl border border-slate-200/90 shadow-2xs overflow-hidden">
                        <div className="flex items-center gap-4 mb-8">
                            <div className="w-14 h-14 bg-red-50 text-red-600 border border-red-200/80 rounded-2xl flex items-center justify-center shrink-0">
                                <category.icon size={26} />
                            </div>
                            <div>
                                <h2 className="text-xl lg:text-2xl font-black text-slate-900">{category.title}</h2>
                                <p className="text-xs text-slate-500 font-medium">Real-time updated plans & government compliance</p>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                            {category.columns.map((col, cIdx) => (
                                <div key={cIdx} className="space-y-4">
                                    <h3 className="text-xs font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 pb-3">{col.heading || col.title}</h3>
                                    <ul className="space-y-1">
                                        {col.items.map((item, lIdx) => {
                                            // Highlight matching text in search results
                                            const highlightText = (text) => {
                                                if (!searchQuery.trim()) return text;
                                                const idx = text.toLowerCase().indexOf(searchQuery.toLowerCase());
                                                if (idx === -1) return text;
                                                return (
                                                    <>
                                                        {text.slice(0, idx)}
                                                        <mark className="bg-red-100 text-red-700 rounded px-0.5 not-italic font-black">
                                                            {text.slice(idx, idx + searchQuery.length)}
                                                        </mark>
                                                        {text.slice(idx + searchQuery.length)}
                                                    </>
                                                );
                                            };

                                            return (
                                                <li key={lIdx}>
                                                    <button
                                                        onClick={() => handleServiceClick(item)}
                                                        className="w-full text-left flex items-center justify-between group p-3 rounded-xl hover:bg-slate-50 hover:border-red-200 border border-transparent transition-all"
                                                    >
                                                        <span className="font-bold text-slate-700 text-xs sm:text-sm group-hover:text-red-600 transition-colors line-clamp-1">
                                                            {highlightText(item)}
                                                        </span>
                                                        <ArrowUpRight size={14} className="text-slate-400 opacity-0 group-hover:opacity-100 group-hover:text-red-600 transition-all shrink-0 ml-2" />
                                                    </button>
                                                </li>
                                            );
                                        })}
                                    </ul>
                                </div>
                            ))}
                        </div>
                    </div>
                )) : (
                    /* No results state */
                    <div className="bg-slate-50 border-2 border-dashed border-slate-200 rounded-3xl p-16 text-center">
                        <Search size={36} className="text-slate-300 mx-auto mb-4" />
                        <h4 className="text-slate-800 font-black text-lg mb-2">No services found</h4>
                        <p className="text-slate-400 text-sm mb-6">
                            We couldn't find a match for <span className="font-bold text-slate-600">"{searchQuery}"</span>.
                            <br />Try different keywords or speak directly with our CA advisors.
                        </p>
                        <button
                            onClick={() => setActiveTab('New')}
                            className="bg-red-600 text-white px-8 py-3 rounded-xl text-sm font-black shadow-md hover:bg-red-700 transition-all uppercase tracking-wider"
                        >
                            Talk to an Expert
                        </button>
                    </div>
                )}
            </div>

            {/* Custom Request Card */}
            {!searchQuery.trim() && (
                <div className="bg-slate-950 rounded-3xl p-8 text-white overflow-hidden relative group mt-12 border border-slate-800 shadow-xl">
                    <div className="absolute top-0 right-0 w-64 h-64 bg-red-600/10 rounded-full blur-3xl pointer-events-none"></div>
                    <div className="relative z-10 flex flex-col lg:flex-row items-center justify-between gap-8">
                        <div className="flex flex-col lg:flex-row items-center lg:items-start gap-6">
                            <div className="w-16 h-16 bg-white/10 rounded-2xl flex items-center justify-center shadow-md shrink-0 border border-white/10">
                                <Lightbulb className="text-amber-400" size={32} />
                            </div>
                            <div className="text-center lg:text-left">
                                <h4 className="font-black text-2xl mb-2 tracking-tight">Need a custom business solution?</h4>
                                <p className="text-slate-300 text-xs sm:text-sm leading-relaxed max-w-xl font-medium">Our senior multidisciplinary team can prepare custom project reports, factory licenses, feasibility studies, and turnkey corporate structures.</p>
                            </div>
                        </div>
                        <button
                            onClick={() => setActiveTab('New')}
                            className="whitespace-nowrap bg-red-600 hover:bg-red-700 text-white px-8 py-3.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-all shadow-lg shadow-red-600/30 shrink-0"
                        >
                            Consult Expert
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ServicesView;
