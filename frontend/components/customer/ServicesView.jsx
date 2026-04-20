import React, { useState, useMemo } from 'react';
import { Lightbulb, Search, ChevronRight, X } from 'lucide-react';
import { MENU_DATA, getServiceLink } from '../SharedComponents';
import { SERVICE_CATALOG } from '../../data/serviceCatalog';

const ServicesView = ({ setActiveTab, initialQuery = '' }) => {
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

    return (
        <div className="space-y-6 pb-20 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex justify-between items-end mb-2 px-1">
                <div>
                    <h1 className="text-2xl lg:text-3xl font-black text-slate-800 tracking-tight">Services Catalog</h1>
                    <p className="text-slate-500 text-sm">Select a specialized service to initiate your business journey.</p>
                </div>
            </div>

            {/* Search Bar — fully functional */}
            <div className="relative group">
                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <Search size={18} className="text-slate-400 group-focus-within:text-indigo-500 transition-colors" />
                </div>
                <input
                    type="text"
                    autoFocus={!!initialQuery}
                    placeholder="Search for legal, tax or industrial services..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-11 pr-10 py-4 bg-white border border-slate-100 rounded-2xl shadow-sm outline-none focus:ring-2 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all text-sm font-medium"
                />
                {searchQuery && (
                    <button
                        onClick={() => setSearchQuery('')}
                        className="absolute inset-y-0 right-0 pr-4 flex items-center text-slate-300 hover:text-slate-500 transition-colors"
                    >
                        <X size={16} />
                    </button>
                )}
            </div>

            {/* Search results summary */}
            {searchQuery.trim() && (
                <div className="flex items-center gap-2 px-1">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-widest">
                        {totalResults} result{totalResults !== 1 ? 's' : ''} for
                    </span>
                    <span className="text-xs font-black text-indigo-600 bg-indigo-50 px-2.5 py-1 rounded-full">
                        "{searchQuery}"
                    </span>
                </div>
            )}

            {/* Structured Catalog */}
            <div className="space-y-8 mt-8">
                {filteredCategories.length > 0 ? filteredCategories.map((category) => (
                    <div key={category.id} className="bg-white p-6 md:p-8 rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                        <div className="flex items-center gap-4 mb-8">
                            <div className="w-14 h-14 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center shrink-0">
                                <category.icon size={26} />
                            </div>
                            <h2 className="text-xl lg:text-2xl font-black text-slate-800">{category.title}</h2>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                            {category.columns.map((col, cIdx) => (
                                <div key={cIdx} className="space-y-4">
                                    <h3 className="text-xs font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 pb-3">{col.heading || col.title}</h3>
                                    <ul className="space-y-1">
                                        {col.items.map((item, lIdx) => {
                                            const computedLink = getServiceLink(item);
                                            const serviceKey = computedLink.replace('/', '');
                                            const hasNativeView = SERVICE_CATALOG[serviceKey];
                                            const isAccounting = item.toLowerCase().includes('accounting') || item.toLowerCase().includes('gst return');

                                            // Highlight matching text in search results
                                            const highlightText = (text) => {
                                                if (!searchQuery.trim()) return text;
                                                const idx = text.toLowerCase().indexOf(searchQuery.toLowerCase());
                                                if (idx === -1) return text;
                                                return (
                                                    <>
                                                        {text.slice(0, idx)}
                                                        <mark className="bg-indigo-100 text-indigo-700 rounded px-0.5 not-italic font-black">
                                                            {text.slice(idx, idx + searchQuery.length)}
                                                        </mark>
                                                        {text.slice(idx + searchQuery.length)}
                                                    </>
                                                );
                                            };

                                            return (
                                                <li key={lIdx}>
                                                    <button
                                                        onClick={() => {
                                                            if (hasNativeView) setActiveTab(serviceKey);
                                                            else if (isAccounting) setActiveTab('Accounting');
                                                            else setActiveTab('New');
                                                        }}
                                                        className="w-full text-left flex flex-col group block p-3 rounded-xl hover:bg-slate-50 hover:border-indigo-100 border border-transparent transition-all"
                                                    >
                                                        <span className="font-bold text-slate-700 text-sm flex items-center gap-2 group-hover:text-indigo-600 transition-colors">
                                                            {highlightText(item)} <ChevronRight size={14} className="opacity-0 -ml-3 group-hover:opacity-100 group-hover:ml-0 transition-all text-indigo-400" />
                                                        </span>
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
                        <h4 className="text-slate-700 font-black text-lg mb-2">No services found</h4>
                        <p className="text-slate-400 text-sm mb-6">
                            We couldn't find a match for <span className="font-bold text-slate-600">"{searchQuery}"</span>.
                            <br />Try different keywords or speak with our experts.
                        </p>
                        <button
                            onClick={() => setActiveTab('New')}
                            className="bg-indigo-600 text-white px-8 py-3 rounded-2xl text-sm font-black shadow-lg shadow-indigo-100 hover:bg-indigo-700 transition-all"
                        >
                            Talk to an Expert
                        </button>
                    </div>
                )}
            </div>

            {/* Custom Request Card */}
            {!searchQuery.trim() && (
                <div className="bg-slate-900 rounded-[40px] p-8 text-white overflow-hidden relative group mt-12">
                    <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-500/10 rounded-full -mr-32 -mt-32 blur-3xl"></div>
                    <div className="relative z-10 flex flex-col lg:flex-row items-center justify-between gap-8">
                        <div className="flex flex-col lg:flex-row items-center lg:items-start gap-6">
                            <div className="w-16 h-16 bg-white/10 rounded-[24px] flex items-center justify-center shadow-xl shrink-0">
                                <Lightbulb className="text-amber-400" size={32} />
                            </div>
                            <div className="text-center lg:text-left">
                                <h4 className="font-black text-2xl mb-2 tracking-tight">Need a custom business solution?</h4>
                                <p className="text-slate-400 text-sm leading-relaxed max-w-xl">Our multidisciplinary experts can create tailored end-to-end setups, feasiblity reports, and turnkey projects specifically for your industry.</p>
                            </div>
                        </div>
                        <button
                            onClick={() => setActiveTab('New')}
                            className="whitespace-nowrap bg-indigo-600 hover:bg-indigo-500 text-white px-10 py-4 rounded-2xl text-sm font-black transition-all shadow-2xl shadow-indigo-900/40 hover:-translate-y-1 active:translate-y-0"
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
