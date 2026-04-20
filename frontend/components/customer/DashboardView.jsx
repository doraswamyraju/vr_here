import React, { useState, useRef, useEffect } from 'react';
import {
    Upload, Briefcase, CreditCard, ChevronRight, AlertTriangle, Bell, Plus,
    Search, Gift, Newspaper, Building2, FileCheck, Shield,
    ClipboardCheck, IndianRupee, Settings, Monitor, Stamp, ExternalLink, ArrowRight,
    User as UsersIcon
} from 'lucide-react';

const getStatusProgress = (status) => {
    switch (status) {
        case 'Pending Documents': return 20;
        case 'Documents Verified': return 40;
        case 'Processing at Portal': return 60;
        case 'Waiting for Clarification': return 70;
        case 'Completed': return 100;
        default: return 0;
    }
};

const StatusBadge = ({ status }) => {
    const styles = {
        'Processing at Portal': 'bg-blue-100 text-blue-700',
        'Waiting for Clarification': 'bg-purple-100 text-purple-700',
        'Completed': 'bg-emerald-100 text-emerald-700',
        'Pending Documents': 'bg-amber-100 text-amber-700',
        'Documents Verified': 'bg-emerald-50 text-emerald-600',
    };
    return <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${styles[status] || 'bg-slate-100'}`}>{status}</span>;
};

const DashboardView = ({ setActiveTab, orders, notifications, userInfo, onOpenProject }) => {
    const activeOrders = orders.filter(o => o.status !== 'Completed');
    const pendingActions = orders.filter(o => o.status === 'Pending Documents' || o.status === 'Waiting for Clarification');
    const unreadNotifications = notifications.filter(n => !n.isRead);

    const topServices = [
        { id: 1, name: 'Pvt Ltd', icon: Building2, color: 'bg-blue-50 text-blue-600', key: 'pvt-ltd-registration' },
        { id: 2, name: 'GST', icon: FileCheck, color: 'bg-green-50 text-green-600', key: 'gst-registration' },
        { id: 3, name: 'IT Return', icon: Monitor, color: 'bg-indigo-50 text-indigo-600', key: 'income-tax-return' },
        { id: 4, name: 'Partnership', icon: UsersIcon, color: 'bg-amber-50 text-amber-600', key: 'partnership-firm' },
        { id: 5, name: 'Trademark', icon: Shield, color: 'bg-purple-50 text-purple-600', key: 'New' },
        { id: 6, name: 'Audit', icon: ClipboardCheck, color: 'bg-rose-50 text-rose-600', key: 'New' },
        { id: 7, name: 'Funding', icon: IndianRupee, color: 'bg-emerald-50 text-emerald-600', key: 'New' },
        { id: 8, name: 'Compliance', icon: Settings, color: 'bg-slate-50 text-slate-600', key: 'New' },
    ];

    const SEARCH_SUGGESTIONS = [
        'Private Limited Company Registration',
        'Limited Liability Partnership (LLP)',
        'GST Registration',
        'GST Return Filing',
        'Income Tax Return',
        'MSME / Udyam Registration',
        'Trademark Registration',
        'FSSAI Food License',
        'ISO Certification',
        'Import Export Code (IEC)',
        'Company Annual Compliances',
        'Startup India DPIIT Registration'
    ];

    const [searchQuery, setSearchQuery] = useState('');
    const [showSuggestions, setShowSuggestions] = useState(false);
    const searchRef = useRef(null);

    // Filter suggestions based on input
    const filteredSuggestions = SEARCH_SUGGESTIONS.filter(item => 
        item.toLowerCase().includes(searchQuery.toLowerCase())
    ).slice(0, 5); // Limit to top 5 hits

    // Close suggestions when clicking outside
    useEffect(() => {
        function handleClickOutside(event) {
            if (searchRef.current && !searchRef.current.contains(event.target)) {
                setShowSuggestions(false);
            }
        }
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const handleSelectSuggestion = (suggestion) => {
        setSearchQuery(suggestion);
        setShowSuggestions(false);
        const lower = suggestion.toLowerCase();
        if (lower.includes('pvt ltd') || lower.includes('private limited')) setActiveTab('pvt-ltd-registration');
        else if (lower.includes('gst reg')) setActiveTab('gst-registration');
        else if (lower.includes('partnership')) setActiveTab('partnership-firm');
        else if (lower.includes('income tax') || lower.includes('itr')) setActiveTab('income-tax-return');
        else setActiveTab('Services');
    };

    return (
        <div className="pb-28 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Top Header Section - Spans full width */}
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h1 className="text-2xl lg:text-3xl font-black text-slate-800 tracking-tight">Hello, {userInfo?.name?.split(' ')[0]}!</h1>
                    <p className="text-slate-500 text-sm">Here's what's happening today.</p>
                </div>
                <div className="flex gap-3">
                    <button className="hidden lg:flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-xl shadow-lg shadow-indigo-200 text-xs font-bold hover:bg-indigo-700 transition-all">
                        <Plus size={16} /> New Engagement
                    </button>
                    <div className="relative">
                        <button className="p-2.5 bg-white rounded-xl shadow-sm border border-slate-100 text-slate-400 hover:text-indigo-600 transition-colors">
                            <Bell size={20} />
                        </button>
                        {unreadNotifications.length > 0 && (
                            <span className="absolute -top-1 -right-1 w-4 h-4 bg-rose-500 border-2 border-white rounded-full flex items-center justify-center text-[10px] text-white font-bold">
                                {unreadNotifications.length}
                            </span>
                        )}
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">

                {/* Left Column - Main Activity (2/3) */}
                <div className="lg:col-span-2 space-y-8">
                    {/* Floating Search Bar with Autocomplete */}
                    <div ref={searchRef} className="relative z-20">
                        <div className="bg-white rounded-2xl shadow-xl shadow-slate-200/50 border border-slate-100 flex items-center px-4 py-3.5 gap-3 group focus-within:ring-2 ring-indigo-500/10 transition-all relative">
                            <Search size={18} className="text-slate-400 group-focus-within:text-indigo-500 transition-colors" />
                            <input
                                type="text"
                                placeholder="Search services (e.g. GST, Company...)"
                                value={searchQuery}
                                onChange={(e) => {
                                    setSearchQuery(e.target.value);
                                    setShowSuggestions(true);
                                }}
                                onFocus={() => setShowSuggestions(true)}
                                className="flex-1 bg-transparent border-none outline-none text-sm font-medium text-slate-700 placeholder:text-slate-400"
                            />
                            <div className="w-px h-4 bg-slate-100 mx-1"></div>
                            <button onClick={() => setActiveTab('Services')} className="text-indigo-600 font-black text-xs uppercase tracking-wider hover:text-indigo-700">Find</button>
                        </div>
                        
                        {/* Dropdown Suggestions */}
                        {showSuggestions && searchQuery.length > 0 && (
                            <div className="absolute top-full left-0 right-0 mt-2 bg-white rounded-2xl shadow-2xl border border-slate-100 overflow-hidden transform origin-top animate-in fade-in slide-in-from-top-2 z-50">
                                {filteredSuggestions.length > 0 ? (
                                    <ul className="py-2">
                                        {filteredSuggestions.map((suggestion, index) => (
                                            <li key={index}>
                                                <button
                                                    onClick={() => handleSelectSuggestion(suggestion)}
                                                    className="w-full text-left px-5 py-3 hover:bg-slate-50 text-sm font-medium text-slate-700 flex items-center justify-between group transition-colors"
                                                >
                                                    <span>{suggestion}</span>
                                                    <ArrowRight size={14} className="text-slate-300 group-hover:text-indigo-500 transition-colors opacity-0 group-hover:opacity-100" />
                                                </button>
                                            </li>
                                        ))}
                                    </ul>
                                ) : (
                                    <div className="p-4">
                                        <button 
                                            onClick={() => setActiveTab('New')}
                                            className="w-full text-left p-4 bg-slate-50 rounded-xl border border-slate-100 hover:border-indigo-200 transition-all group"
                                        >
                                            <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Not listed?</p>
                                            <p className="text-sm font-bold text-slate-700 mb-2">Request '{searchQuery}'</p>
                                            <div className="flex items-center gap-2 text-indigo-600 text-xs font-black uppercase tracking-widest">
                                                Contact Us <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
                                            </div>
                                        </button>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Main Hero Card */}
                    <div className="bg-gradient-to-br from-indigo-600 via-indigo-700 to-violet-800 rounded-[32px] p-8 text-white shadow-xl shadow-indigo-200 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 w-64 h-64 bg-white/10 rounded-full -mr-32 -mt-32 blur-3xl group-hover:bg-white/20 transition-all duration-700"></div>
                        <div className="relative z-10">
                            <div className="flex items-center gap-2 mb-6 opacity-80">
                                <Briefcase size={18} />
                                <span className="text-xs font-bold uppercase tracking-widest">Active Portfolio</span>
                            </div>
                            <div className="flex items-end justify-between">
                                <div>
                                    <h2 className="text-5xl font-black mb-2 tracking-tighter">{activeOrders.length}</h2>
                                    <p className="text-indigo-100 text-sm font-bold">Projects currently in progress</p>
                                </div>
                                <button
                                    onClick={() => setActiveTab('Orders')}
                                    className="bg-white text-indigo-600 px-6 py-3 rounded-2xl text-sm font-black hover:bg-slate-50 transition shadow-xl"
                                >
                                    Track Status
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* Top Services Grid */}
                    <div className="bg-white rounded-[40px] p-8 border border-slate-100 shadow-sm relative overflow-hidden">
                        <div className="flex justify-between items-center mb-8">
                            <h3 className="font-black text-slate-800 text-lg">Quick Access Services</h3>
                            <button onClick={() => setActiveTab('Services')} className="text-indigo-600 text-xs font-bold flex items-center gap-1 hover:underline">
                                View Master Catalog <ChevronRight size={14} />
                            </button>
                        </div>
                        <div className="grid grid-cols-4 gap-y-10 gap-x-4">
                            {topServices.map(service => (
                                <button
                                    key={service.id}
                                    onClick={() => setActiveTab(service.key)}
                                    className="flex flex-col items-center gap-3 group"
                                >
                                    <div className={`w-14 h-14 lg:w-16 lg:h-16 ${service.color} rounded-3xl flex items-center justify-center shadow-sm group-hover:shadow-lg group-hover:-translate-y-1 transition-all duration-300`}>
                                        <service.icon size={24} className="group-hover:scale-110 transition-transform" />
                                    </div>
                                    <span className="text-[11px] lg:text-xs font-black text-slate-600 text-center leading-tight group-hover:text-indigo-600 transition-colors">{service.name}</span>
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Active Tracking Section */}
                    <div>
                        <div className="flex justify-between items-center mb-6 px-1">
                            <h3 className="font-black text-slate-800 text-xl">Operational Pipeline</h3>
                            <div className="flex gap-2">
                                <span className="px-3 py-1 bg-indigo-50 text-indigo-600 rounded-full text-[10px] font-black uppercase tracking-tighter">Live Updates</span>
                            </div>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {activeOrders.slice(0, 4).map(proj => (
                                <div key={proj._id} onClick={() => onOpenProject ? onOpenProject(proj._id) : {}} className="bg-white p-6 rounded-[32px] border border-slate-100 shadow-sm hover:shadow-xl hover:border-indigo-100 transition-all group cursor-pointer">
                                    <div className="flex justify-between items-start mb-4">
                                        <div className="max-w-[70%]">
                                            <h4 className="font-black text-slate-800 text-sm group-hover:text-indigo-600 transition-colors line-clamp-1">{proj.serviceName}</h4>
                                            <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-0.5">{proj.packageName}</p>
                                        </div>
                                        <StatusBadge status={proj.status} />
                                    </div>
                                    <div className="space-y-3">
                                        <div className="flex justify-between text-[10px] font-black uppercase tracking-widest text-slate-400">
                                            <span>Completeness</span>
                                            <span className="text-indigo-600">{getStatusProgress(proj.status)}%</span>
                                        </div>
                                        <div className="w-full h-2 bg-slate-50 rounded-full overflow-hidden">
                                            <div
                                                className="h-full bg-gradient-to-r from-indigo-500 via-violet-500 to-indigo-600 rounded-full transition-all duration-1000 ease-out shadow-[0_0_10px_rgba(99,102,241,0.3)]"
                                                style={{ width: `${getStatusProgress(proj.status)}%` }}
                                            ></div>
                                        </div>
                                    </div>
                                </div>
                            ))}
                            {activeOrders.length === 0 && (
                                <div className="md:col-span-2 bg-slate-50 border-2 border-dashed border-slate-200 rounded-[32px] p-12 text-center">
                                    <div className="w-16 h-16 bg-white rounded-3xl flex items-center justify-center mx-auto mb-4 shadow-sm text-slate-300">
                                        <Plus size={32} />
                                    </div>
                                    <p className="text-slate-500 font-bold mb-2 tracking-tight">Your pipeline is empty</p>
                                    <p className="text-slate-400 text-xs mb-6">Start a new project to see it tracked here live.</p>
                                    <button onClick={() => setActiveTab('Services')} className="bg-indigo-600 text-white px-8 py-3 rounded-2xl text-xs font-black uppercase tracking-widest shadow-xl shadow-indigo-100 hover:bg-indigo-700 transition-all">Start Now</button>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* Right Column - Sidebar Stats & Updates (1/3) */}
                <div className="space-y-8 lg:sticky lg:top-24">

                    {/* Stats Stack */}
                    <div className="grid grid-cols-2 lg:grid-cols-1 gap-4">
                        <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm flex items-center gap-5 hover:border-amber-200 transition-colors">
                            <div className="w-14 h-14 bg-amber-50 text-amber-500 rounded-2xl flex items-center justify-center shrink-0">
                                <AlertTriangle size={28} />
                            </div>
                            <div>
                                <p className="text-slate-400 text-[10px] font-black uppercase tracking-widest mb-1">Attention</p>
                                <h3 className="text-2xl font-black text-slate-800">{pendingActions.length}</h3>
                                <p className="text-slate-500 text-[10px] font-medium leading-none">Pending Tasks</p>
                            </div>
                        </div>
                        <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm flex items-center gap-5 hover:border-emerald-200 transition-colors">
                            <div className="w-14 h-14 bg-emerald-50 text-emerald-500 rounded-2xl flex items-center justify-center shrink-0">
                                <IndianRupee size={28} />
                            </div>
                            <div>
                                <p className="text-slate-400 text-[10px] font-black uppercase tracking-widest mb-1">Investment</p>
                                <h3 className="text-2xl font-black text-slate-800">₹{(orders.reduce((acc, curr) => acc + curr.price, 0) / 1000).toFixed(1)}k</h3>
                                <p className="text-slate-500 text-[10px] font-medium leading-none">Total Value</p>
                            </div>
                        </div>
                    </div>

                    {/* Accounting Services CTA */}
                    <div className="bg-emerald-900 rounded-[32px] p-6 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-500/20 rounded-full -mr-16 -mt-16 blur-3xl group-hover:bg-emerald-500/30 transition-all duration-700"></div>
                        <div className="relative z-10">
                            <div className="flex items-center gap-4 mb-4">
                                <div className="w-12 h-12 bg-gradient-to-tr from-emerald-400 to-teal-500 rounded-xl flex items-center justify-center shadow-lg shadow-teal-500/20 transform -rotate-3 transition-transform group-hover:rotate-0">
                                    <ClipboardCheck className="text-white" size={24} />
                                </div>
                                <h3 className="text-white font-black text-lg leading-tight">Accounting Services</h3>
                            </div>
                            <p className="text-emerald-200 text-xs font-medium mb-5 leading-relaxed">Customize your own GST, TDS, and Payroll packages with our multi-select builder.</p>
                            <button onClick={() => setActiveTab('Accounting')} className="w-full bg-white text-emerald-900 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest hover:bg-slate-50 transition-colors shadow-xl">
                                Build Package
                            </button>
                        </div>
                    </div>

                    {/* Refer a Friend Section */}
                    <div className="bg-indigo-900 rounded-[32px] p-6 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/20 rounded-full -mr-16 -mt-16 blur-3xl group-hover:bg-indigo-500/30 transition-all duration-700"></div>
                        <div className="relative z-10">
                            <div className="flex items-center gap-4 mb-4">
                                <div className="w-12 h-12 bg-gradient-to-tr from-yellow-400 to-orange-500 rounded-xl flex items-center justify-center shadow-lg shadow-orange-500/20 transform rotate-3 transition-transform group-hover:rotate-0">
                                    <Gift className="text-white" size={24} />
                                </div>
                                <h3 className="text-white font-black text-lg leading-tight">Refer & Earn ₹1000</h3>
                            </div>
                            <p className="text-indigo-200 text-xs font-medium mb-5 leading-relaxed">Refer a business for incorporation or GST and get immediate wallet credits.</p>
                            <button className="w-full bg-white text-indigo-900 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest hover:bg-slate-50 transition-colors shadow-xl">
                                Invite Now
                            </button>
                        </div>
                    </div>

                    {/* Latest News Feed */}
                    <div className="bg-white rounded-[32px] border border-slate-100 overflow-hidden shadow-sm group">
                        <div className="p-6 border-b border-slate-50 flex justify-between items-center">
                            <h3 className="font-black text-slate-800 flex items-center gap-2"><Newspaper size={18} className="text-indigo-600" /> Insights</h3>
                            <button className="text-[10px] font-black text-indigo-600 tracking-tighter">VIEW ALL</button>
                        </div>
                        <div className="relative h-40 bg-slate-900 flex items-center justify-center overflow-hidden">
                            <div className="absolute inset-0 bg-gradient-to-t from-slate-900/80 to-transparent z-10"></div>
                            <div className="w-full h-full opacity-60 bg-[url('https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&q=80&w=2426&ixlib=rb-4.0.3')] bg-cover bg-center group-hover:scale-110 transition-transform duration-1000"></div>
                            <div className="absolute bottom-4 left-6 z-20">
                                <span className="px-2 py-1 bg-indigo-600 text-[8px] font-black text-white rounded-lg uppercase tracking-widest shadow-lg">Tax alert</span>
                            </div>
                        </div>
                        <div className="p-6">
                            <h4 className="font-black text-slate-800 text-sm mb-2 leading-snug group-hover:text-indigo-600 transition-colors">GST Compliance: New Rules for IT Credit in 2026</h4>
                            <p className="text-xs text-slate-500 mb-5 line-clamp-2 leading-relaxed">Stay ahead with latest amendments in GST laws affecting MSMEs...</p>
                            <button className="w-full py-3 bg-slate-50 rounded-xl text-slate-400 text-[10px] font-black uppercase tracking-widest flex items-center justify-center gap-2 hover:bg-slate-100 transition-colors">
                                Read More <ExternalLink size={12} />
                            </button>
                        </div>
                    </div>

                    {/* Action Items for Pending Projects */}
                    {pendingActions.length > 0 && (
                        <div className="bg-rose-50 border border-rose-100 rounded-[32px] p-6 shadow-sm shadow-rose-100/50">
                            <div className="flex items-start gap-4 mb-4">
                                <div className="w-12 h-12 bg-white rounded-2xl flex items-center justify-center shadow-sm text-rose-500 shrink-0">
                                    <Upload size={24} />
                                </div>
                                <div>
                                    <h4 className="text-sm font-black text-rose-900 tracking-tight">Action Required</h4>
                                    <p className="text-[10px] text-rose-700/70 font-bold uppercase tracking-widest">Document Pending</p>
                                </div>
                            </div>
                            <p className="text-xs text-rose-700/80 mb-5 leading-relaxed font-medium">Please upload the requested identity proofs to continue your business registration.</p>
                            <button
                                onClick={() => setActiveTab('Documents')}
                                className="w-full bg-rose-500 text-white py-3 rounded-2xl text-xs font-black shadow-xl shadow-rose-200 hover:bg-rose-600 transition-all hover:-translate-y-0.5"
                            >
                                GO TO VAULT
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default DashboardView;
