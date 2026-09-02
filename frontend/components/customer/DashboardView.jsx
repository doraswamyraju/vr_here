import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Upload, Briefcase, CreditCard, ChevronRight, AlertTriangle, Bell, Plus,
    Search, Gift, Newspaper, Building2, FileCheck, Shield,
    ClipboardCheck, IndianRupee, Settings, Monitor, Stamp, ExternalLink, ArrowRight,
    User as UsersIcon, CheckCircle2, Phone, Calendar, Clock, Sparkles, FileText, CheckCircle
} from 'lucide-react';

const getStatusProgress = (status) => {
    switch (status) {
        case 'Pending Documents': return 25;
        case 'Documents Verified': return 50;
        case 'Processing at Portal': return 75;
        case 'Waiting for Clarification': return 60;
        case 'Completed': return 100;
        default: return 15;
    }
};

const StatusBadge = ({ status }) => {
    const styles = {
        'Processing at Portal': 'bg-blue-50 text-blue-700 border-blue-200',
        'Waiting for Clarification': 'bg-purple-50 text-purple-700 border-purple-200',
        'Completed': 'bg-emerald-50 text-emerald-700 border-emerald-200',
        'Pending Documents': 'bg-amber-50 text-amber-700 border-amber-200',
        'Documents Verified': 'bg-emerald-50 text-emerald-600 border-emerald-200',
    };
    return (
        <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider border ${styles[status] || 'bg-slate-100 text-slate-700 border-slate-200'}`}>
            {status}
        </span>
    );
};

const DashboardView = ({ setActiveTab, orders, notifications, userInfo, onOpenProject, onOpenNotifications, onSelectService }) => {
    const navigate = useNavigate();
    const activeOrders = orders.filter(o => o.status !== 'Completed');
    const completedOrders = orders.filter(o => o.status === 'Completed');
    const pendingActions = orders.filter(o => o.status === 'Pending Documents' || o.status === 'Waiting for Clarification');
    const unreadNotifications = notifications.filter(n => !n.isRead);

    const topServices = [
        { id: 1, name: 'Pvt Ltd Setup', tag: 'MCA Approval', icon: Building2, color: 'bg-red-50 text-red-600 border-red-200', key: 'pvt-ltd-registration' },
        { id: 2, name: 'GST Filing', tag: 'Monthly / QRMP', icon: FileCheck, color: 'bg-emerald-50 text-emerald-600 border-emerald-200', key: 'gst-registration' },
        { id: 3, name: 'Income Tax', tag: 'ITR 1-7 Assessment', icon: Monitor, color: 'bg-blue-50 text-blue-600 border-blue-200', key: 'income-tax-return' },
        { id: 4, name: 'Partnership', tag: 'Firm & Deed', icon: UsersIcon, color: 'bg-amber-50 text-amber-600 border-amber-200', key: 'partnership-firm' },
        { id: 5, name: 'ISO Standards', tag: '9001 / 27001', icon: Shield, color: 'bg-purple-50 text-purple-600 border-purple-200', key: 'Services' },
        { id: 6, name: 'Audit Support', tag: 'Statutory & Tax', icon: ClipboardCheck, color: 'bg-rose-50 text-rose-600 border-rose-200', key: 'New' },
        { id: 7, name: 'MSME Loans', tag: 'Bank DPR & CMA', icon: IndianRupee, color: 'bg-emerald-50 text-emerald-600 border-emerald-200', key: 'Services' },
        { id: 8, name: 'ROC CCFS-2026', tag: 'Penalty Relief', icon: Sparkles, color: 'bg-orange-50 text-orange-600 border-orange-200', key: '/compliance-scheme-2026' },
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

    const filteredSuggestions = SEARCH_SUGGESTIONS.filter(item => 
        item.toLowerCase().includes(searchQuery.toLowerCase())
    ).slice(0, 5);

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
        setActiveTab('Services', suggestion);
    };

    return (
        <div className="pb-28 lg:pb-12 animate-in fade-in slide-in-from-bottom-3 duration-500 space-y-8">
            
            {/* 1. TOP GREETING & SEARCH BAR */}
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                <div>
                    <h1 className="text-2xl lg:text-3xl font-black text-slate-900 tracking-tight flex items-center gap-2">
                        <span>Welcome, {userInfo?.name || 'Valued Client'}</span>
                        <span className="inline-block animate-bounce">👋</span>
                    </h1>
                    <p className="text-slate-500 text-xs sm:text-sm font-medium mt-0.5">
                        Here is an executive snapshot of your filings, compliance status, and vault.
                    </p>
                </div>

                {/* Quick Search with Glowing Gradient Effect */}
                <div ref={searchRef} className="relative z-20 w-full md:w-80 lg:w-96 group">
                    {/* Glowing Backdrop Gradient */}
                    <div className="absolute -inset-0.5 bg-gradient-to-r from-red-600 via-rose-500 to-amber-500 rounded-2xl blur-sm opacity-35 group-hover:opacity-75 group-focus-within:opacity-100 transition-all duration-500"></div>

                    {/* Main Search Input Container */}
                    <div className="relative bg-white rounded-2xl flex items-center px-4 py-2.5 gap-3 shadow-sm border border-slate-200/80 transition-all">
                        <Search size={16} className="text-red-500 group-hover:scale-110 transition-transform shrink-0" />
                        <input
                            type="text"
                            placeholder="Search any service or filing..."
                            value={searchQuery}
                            onChange={(e) => {
                                setSearchQuery(e.target.value);
                                setShowSuggestions(true);
                            }}
                            onFocus={() => setShowSuggestions(true)}
                            className="flex-1 bg-transparent border-none outline-none text-xs font-semibold text-slate-800 placeholder:text-slate-400"
                        />
                        {searchQuery ? (
                            <button onClick={() => setActiveTab('Services', searchQuery)} className="bg-red-600 hover:bg-red-700 text-white font-black text-[10px] uppercase tracking-wider px-2.5 py-1 rounded-lg transition-colors">
                                Find
                            </button>
                        ) : (
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest bg-slate-100 px-2 py-0.5 rounded-md hidden sm:inline-block">
                                Quick
                            </span>
                        )}
                    </div>
                    
                    {/* Dropdown Suggestions */}
                    {showSuggestions && searchQuery.length > 0 && (
                        <div className="absolute top-full left-0 right-0 mt-2 bg-white rounded-2xl shadow-2xl border border-slate-200 overflow-hidden transform origin-top animate-in fade-in slide-in-from-top-2 z-50">
                            {filteredSuggestions.length > 0 ? (
                                <ul className="py-2 divide-y divide-slate-100">
                                    {filteredSuggestions.map((suggestion, index) => (
                                        <li key={index}>
                                            <button
                                                onClick={() => handleSelectSuggestion(suggestion)}
                                                className="w-full text-left px-4 py-2.5 hover:bg-red-50/60 text-xs font-semibold text-slate-700 flex items-center justify-between group/item transition-colors"
                                            >
                                                <span>{suggestion}</span>
                                                <ArrowRight size={12} className="text-slate-400 group-hover/item:text-red-600 group-hover/item:translate-x-0.5 transition-all" />
                                            </button>
                                        </li>
                                    ))}
                                </ul>
                            ) : (
                                <div className="p-3">
                                    <button 
                                        onClick={() => setActiveTab('New')}
                                        className="w-full text-left p-3 bg-slate-50 rounded-xl border border-slate-200 hover:border-red-200 transition-all group/cta"
                                    >
                                        <p className="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-0.5">Need custom assistance?</p>
                                        <p className="text-xs font-bold text-slate-800 mb-1">Request '{searchQuery}'</p>
                                        <div className="flex items-center gap-1.5 text-red-600 text-[10px] font-black uppercase tracking-wider">
                                            <span>Talk to CA Advisor</span>
                                            <ArrowRight size={12} className="group-hover/cta:translate-x-1 transition-transform" />
                                        </div>
                                    </button>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>

            {/* 2. 4-KPI STAT CARDS (EXECUTIVE OVERVIEW) */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <div 
                    onClick={() => setActiveTab('Orders')}
                    className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-2xs hover:shadow-md hover:border-red-300 transition-all cursor-pointer group"
                >
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Active Orders</span>
                        <div className="w-8 h-8 rounded-xl bg-red-50 text-red-600 flex items-center justify-center group-hover:scale-110 transition-transform">
                            <Briefcase size={16} />
                        </div>
                    </div>
                    <div className="flex items-baseline justify-between">
                        <h3 className="text-2xl font-black text-slate-900">{activeOrders.length}</h3>
                        <span className="text-[11px] font-bold text-red-600">Track &rarr;</span>
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1 font-medium">In-progress filings</p>
                </div>

                <div 
                    onClick={() => setActiveTab('Documents')}
                    className={`rounded-2xl p-5 border shadow-2xs transition-all cursor-pointer group ${
                        pendingActions.length > 0 
                            ? 'bg-rose-50/50 border-rose-200 hover:border-rose-400' 
                            : 'bg-white border-slate-200/90 hover:border-slate-300'
                    }`}
                >
                    <div className="flex items-center justify-between mb-3">
                        <span className={`text-[10px] font-black uppercase tracking-wider ${pendingActions.length > 0 ? 'text-rose-600' : 'text-slate-400'}`}>Action Needed</span>
                        <div className={`w-8 h-8 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform ${pendingActions.length > 0 ? 'bg-rose-100 text-rose-600' : 'bg-slate-100 text-slate-600'}`}>
                            <AlertTriangle size={16} />
                        </div>
                    </div>
                    <div className="flex items-baseline justify-between">
                        <h3 className={`text-2xl font-black ${pendingActions.length > 0 ? 'text-rose-700' : 'text-slate-900'}`}>{pendingActions.length}</h3>
                        <span className={`text-[11px] font-bold ${pendingActions.length > 0 ? 'text-rose-600' : 'text-slate-400'}`}>Upload &rarr;</span>
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1 font-medium">Pending document proofs</p>
                </div>

                <div 
                    onClick={() => setActiveTab('Documents')}
                    className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-2xs hover:shadow-md hover:border-slate-300 transition-all cursor-pointer group"
                >
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Digital Vault</span>
                        <div className="w-8 h-8 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center group-hover:scale-110 transition-transform">
                            <FileText size={16} />
                        </div>
                    </div>
                    <div className="flex items-baseline justify-between">
                        <h3 className="text-2xl font-black text-slate-900">{completedOrders.length > 0 ? completedOrders.length * 3 : 5}</h3>
                        <span className="text-[11px] font-bold text-emerald-600">Vault &rarr;</span>
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1 font-medium">Verified certificates & DIN</p>
                </div>

                <div 
                    onClick={() => setActiveTab('Invoices')}
                    className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-2xs hover:shadow-md hover:border-slate-300 transition-all cursor-pointer group"
                >
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Total Portfolio</span>
                        <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center group-hover:scale-110 transition-transform">
                            <IndianRupee size={16} />
                        </div>
                    </div>
                    <div className="flex items-baseline justify-between">
                        <h3 className="text-2xl font-black text-slate-900">₹{(orders.reduce((acc, curr) => acc + (curr.price || 0), 0) / 1000).toFixed(1)}k</h3>
                        <span className="text-[11px] font-bold text-blue-600">Bills &rarr;</span>
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1 font-medium">Settled engagement volume</p>
                </div>
            </div>

            {/* 3. MAIN WORKSPACE (LEFT 8 COLUMNS) & INTELLIGENCE SIDEBAR (RIGHT 4 COLUMNS) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">

                {/* --- LEFT COLUMN: OPERATIONAL COMMAND CENTER (8 COLS) --- */}
                <div className="lg:col-span-8 space-y-8">
                    
                    {/* Hero Action Card */}
                    <div className="bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 rounded-3xl p-7 text-white relative overflow-hidden shadow-xl border border-slate-800 group">
                        <div className="absolute top-0 right-0 w-80 h-80 bg-red-600/10 rounded-full blur-3xl pointer-events-none group-hover:bg-red-600/20 transition-all duration-700"></div>
                        <div className="relative z-10">
                            <div className="flex items-center justify-between mb-4">
                                <span className="bg-red-500/20 border border-red-500/30 text-red-300 text-[10px] font-black uppercase tracking-widest px-3 py-1 rounded-full">
                                    Enterprise Client Hub
                                </span>
                                <span className="text-[11px] text-slate-400 font-semibold flex items-center gap-1.5">
                                    <Clock size={13} className="text-emerald-400" />
                                    <span>Real-Time MCA Sync</span>
                                </span>
                            </div>

                            <h2 className="text-xl sm:text-2xl font-black tracking-tight mb-2">
                                Manage Filings, Upload Vault Docs & Track Milestones
                            </h2>
                            <p className="text-slate-300 text-xs sm:text-sm font-medium leading-relaxed max-w-xl mb-6">
                                All government submissions are managed directly by our senior team of Chartered Accountants and Company Secretaries.
                            </p>

                            <div className="flex flex-wrap items-center gap-3">
                                <button
                                    onClick={() => setActiveTab('Orders')}
                                    className="bg-red-600 hover:bg-red-700 text-white font-bold text-xs uppercase tracking-wider px-5 py-3 rounded-xl transition-all shadow-lg shadow-red-600/30 flex items-center gap-2"
                                >
                                    <span>View Active Pipeline ({activeOrders.length})</span>
                                    <ArrowRight size={14} />
                                </button>
                                <button
                                    onClick={() => setActiveTab('Services')}
                                    className="bg-white/10 hover:bg-white/20 text-white font-bold text-xs uppercase tracking-wider px-4 py-3 rounded-xl transition-all border border-white/10"
                                >
                                    Explore Catalog
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* Operational Pipeline Tracker */}
                    <div className="bg-white rounded-3xl p-6 sm:p-7 border border-slate-200/90 shadow-2xs space-y-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <h3 className="text-lg font-black text-slate-900 tracking-tight">Active Operational Pipeline</h3>
                                <p className="text-xs text-slate-500 font-medium">Live stage progress for your ongoing engagements</p>
                            </div>
                            <button
                                onClick={() => setActiveTab('Orders')}
                                className="text-xs font-black text-red-600 hover:text-red-700 uppercase tracking-wider flex items-center gap-1"
                            >
                                <span>All Orders</span>
                                <ChevronRight size={14} />
                            </button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {activeOrders.slice(0, 4).map(proj => (
                                <div
                                    key={proj._id}
                                    onClick={() => onOpenProject ? onOpenProject(proj._id) : setActiveTab('Orders')}
                                    className="bg-slate-50/80 hover:bg-white p-5 rounded-2xl border border-slate-200/80 hover:border-red-300 shadow-2xs hover:shadow-lg transition-all group cursor-pointer"
                                >
                                    <div className="flex justify-between items-start mb-3">
                                        <div className="max-w-[70%]">
                                            <h4 className="font-black text-slate-900 text-sm group-hover:text-red-600 transition-colors truncate">
                                                {proj.serviceName}
                                            </h4>
                                            <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-0.5">
                                                {proj.packageName || 'Standard Execution'}
                                            </p>
                                        </div>
                                        <StatusBadge status={proj.status} />
                                    </div>

                                    <div className="space-y-2 mt-4">
                                        <div className="flex justify-between text-[10px] font-black uppercase tracking-wider text-slate-500">
                                            <span>Milestone Progress</span>
                                            <span className="text-red-600 font-bold">{getStatusProgress(proj.status)}%</span>
                                        </div>
                                        <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                                            <div
                                                className="h-full bg-gradient-to-r from-red-600 to-rose-500 rounded-full transition-all duration-700"
                                                style={{ width: `${getStatusProgress(proj.status)}%` }}
                                            ></div>
                                        </div>
                                    </div>

                                    <div className="mt-4 pt-3 border-t border-slate-200/60 flex items-center justify-between text-[11px] text-slate-500 font-semibold">
                                        <span>ID: #{String(proj._id).slice(-6).toUpperCase()}</span>
                                        <span className="text-red-600 group-hover:translate-x-0.5 transition-transform font-bold flex items-center gap-1">
                                            Details &rarr;
                                        </span>
                                    </div>
                                </div>
                            ))}

                            {activeOrders.length === 0 && (
                                <div className="md:col-span-2 bg-slate-50 border-2 border-dashed border-slate-200 rounded-2xl p-8 text-center">
                                    <div className="w-12 h-12 bg-white rounded-2xl flex items-center justify-center mx-auto mb-3 shadow-xs text-slate-400">
                                        <Plus size={24} />
                                    </div>
                                    <h4 className="text-sm font-bold text-slate-700 mb-1">No Active Orders in Pipeline</h4>
                                    <p className="text-xs text-slate-500 mb-4 max-w-sm mx-auto">Start a new registration, tax filing, or consultation to track it live.</p>
                                    <button
                                        onClick={() => setActiveTab('Services')}
                                        className="bg-red-600 hover:bg-red-700 text-white px-5 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider shadow-md transition-all"
                                    >
                                        Browse Services
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Quick Access Services (4x2 Bento Grid) */}
                    <div className="bg-white rounded-3xl p-6 sm:p-7 border border-slate-200/90 shadow-2xs">
                        <div className="flex justify-between items-center mb-6">
                            <div>
                                <h3 className="text-lg font-black text-slate-900 tracking-tight">Quick Action Launchpad</h3>
                                <p className="text-xs text-slate-500 font-medium">One-click jump to your most frequent business requirements</p>
                            </div>
                            <button
                                onClick={() => setActiveTab('Services')}
                                className="text-xs font-black text-red-600 hover:text-red-700 uppercase tracking-wider flex items-center gap-1"
                            >
                                <span>Master Catalog</span>
                                <ChevronRight size={14} />
                            </button>
                        </div>

                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                            {topServices.map(service => (
                                <button
                                    key={service.id}
                                    onClick={() => {
                                        if (service.key.startsWith('/')) {
                                            navigate(service.key);
                                        } else if (onSelectService && service.key !== 'Services' && service.key !== 'New') {
                                            onSelectService({ title: service.name, slug: service.key });
                                        } else {
                                            setActiveTab(service.key);
                                        }
                                    }}
                                    className="flex flex-col items-center p-4 rounded-2xl bg-slate-50/80 hover:bg-white border border-slate-200/80 hover:border-red-300 shadow-2xs hover:shadow-md transition-all duration-200 group text-center"
                                >
                                    <div className={`w-12 h-12 ${service.color} rounded-2xl flex items-center justify-center shadow-xs group-hover:scale-110 transition-transform mb-3 border`}>
                                        <service.icon size={20} />
                                    </div>
                                    <span className="text-xs font-black text-slate-800 leading-snug group-hover:text-red-600 transition-colors mb-0.5">
                                        {service.name}
                                    </span>
                                    <span className="text-[10px] font-semibold text-slate-400">
                                        {service.tag}
                                    </span>
                                </button>
                            ))}
                        </div>
                    </div>
                </div>

                {/* --- RIGHT COLUMN: INTELLIGENCE & ADVISOR PANEL (4 COLS) --- */}
                <div className="lg:col-span-4 space-y-6">

                    {/* Dedicated CA/CS Relationship Manager Card */}
                    <div className="bg-slate-900 rounded-3xl p-6 text-white border border-slate-800 shadow-xl relative overflow-hidden">
                        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Dedicated Advisor</span>
                            <span className="bg-emerald-500/20 text-emerald-400 text-[9px] font-black px-2 py-0.5 rounded-full border border-emerald-500/30">Available</span>
                        </div>

                        <div className="flex items-center gap-3.5 my-4">
                            <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-red-600 to-rose-600 flex items-center justify-center font-black text-lg text-white shadow-md">
                                CA
                            </div>
                            <div>
                                <h4 className="text-sm font-black text-white">S. Doraswamy Raju & Team</h4>
                                <p className="text-[11px] text-slate-400 font-medium">Senior CA / CS Advisory Partner</p>
                            </div>
                        </div>

                        <p className="text-xs text-slate-300 font-medium leading-relaxed mb-5">
                            Need priority clarification on your filing or tax audit? Reach your assigned manager directly.
                        </p>

                        <div className="grid grid-cols-2 gap-2">
                            <a
                                href="tel:+918008530606"
                                className="flex items-center justify-center gap-2 py-2.5 bg-white/10 hover:bg-white/20 text-white rounded-xl text-xs font-bold transition-all"
                            >
                                <Phone size={13} />
                                <span>Call CA</span>
                            </a>
                            <a
                                href="https://wa.me/918008530606?text=Hi%20VR%20HERE%20Team,%20I%20need%20assistance%20with%20my%20customer%20portal%20engagement."
                                target="_blank"
                                rel="noreferrer"
                                className="flex items-center justify-center gap-2 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition-all"
                            >
                                <span>WhatsApp</span>
                            </a>
                        </div>
                    </div>

                    {/* Statutory Compliance Calendar */}
                    <div className="bg-white rounded-3xl p-6 border border-slate-200/90 shadow-2xs">
                        <div className="flex items-center justify-between mb-4">
                            <h4 className="text-xs font-black uppercase tracking-wider text-slate-900 flex items-center gap-2">
                                <Calendar size={14} className="text-red-600" />
                                <span>Compliance Calendar</span>
                            </h4>
                            <span className="text-[10px] font-bold text-slate-400">March 2026</span>
                        </div>

                        <div className="space-y-3">
                            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80 flex items-center justify-between">
                                <div>
                                    <p className="text-xs font-bold text-slate-800">GST-3B Filing</p>
                                    <p className="text-[10px] text-slate-400">Monthly Return</p>
                                </div>
                                <span className="text-[10px] font-black px-2 py-0.5 bg-red-50 text-red-600 rounded-md border border-red-200">20th Mar</span>
                            </div>

                            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80 flex items-center justify-between">
                                <div>
                                    <p className="text-xs font-bold text-slate-800">Advance Tax Q4</p>
                                    <p className="text-[10px] text-slate-400">Direct Tax Installment</p>
                                </div>
                                <span className="text-[10px] font-black px-2 py-0.5 bg-amber-50 text-amber-700 rounded-md border border-amber-200">15th Mar</span>
                            </div>

                            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80 flex items-center justify-between">
                                <div>
                                    <p className="text-xs font-bold text-slate-800">CCFS-2026 Amnesty</p>
                                    <p className="text-[10px] text-slate-400">ROC Late Filing Waiver</p>
                                </div>
                                <span className="text-[10px] font-black px-2 py-0.5 bg-emerald-50 text-emerald-700 rounded-md border border-emerald-200">Active</span>
                            </div>
                        </div>
                    </div>

                    {/* Refer & Earn Card */}
                    <div className="bg-gradient-to-br from-amber-50 to-orange-50 rounded-3xl p-6 border border-amber-200/80 shadow-2xs">
                        <div className="flex items-center gap-3 mb-3">
                            <div className="w-10 h-10 rounded-xl bg-amber-500 text-white flex items-center justify-center shadow-xs font-bold">
                                <Gift size={20} />
                            </div>
                            <div>
                                <h4 className="text-xs font-black uppercase tracking-wider text-amber-900">Refer & Earn ₹1,000</h4>
                                <p className="text-[10px] text-amber-700 font-medium">Instant wallet credits per referral</p>
                            </div>
                        </div>
                        <p className="text-xs text-slate-600 leading-relaxed mb-4">
                            Refer another founder for company registration or ISO certification and receive ₹1,000 credit on your next filing.
                        </p>
                        <button
                            onClick={() => setActiveTab('Account')}
                            className="w-full bg-slate-900 hover:bg-slate-800 text-white font-bold text-xs py-2.5 rounded-xl transition-all"
                        >
                            Get Referral Link
                        </button>
                    </div>

                </div>
            </div>
        </div>
    );
};

export default DashboardView;

