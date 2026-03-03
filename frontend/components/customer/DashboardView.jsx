import React from 'react';
import {
    Upload, Briefcase, CreditCard, ChevronRight, AlertTriangle, Bell, Plus,
    Search, Gift, Newspaper, Building2, FileCheck, Shield,
    ClipboardCheck, IndianRupee, Settings, Monitor, Stamp, ExternalLink
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

const DashboardView = ({ setActiveTab, orders, notifications, userInfo }) => {
    const activeOrders = orders.filter(o => o.status !== 'Completed');
    const pendingActions = orders.filter(o => o.status === 'Pending Documents' || o.status === 'Waiting for Clarification');
    const unreadNotifications = notifications.filter(n => !n.isRead);

    const topServices = [
        { id: 1, name: 'Pvt Ltd', icon: Building2, color: 'bg-blue-50 text-blue-600' },
        { id: 2, name: 'GST', icon: FileCheck, color: 'bg-green-50 text-green-600' },
        { id: 3, name: 'IT Return', icon: Monitor, color: 'bg-indigo-50 text-indigo-600' },
        { id: 4, name: 'MSME', icon: Stamp, color: 'bg-amber-50 text-amber-600' },
        { id: 5, name: 'Trademark', icon: Shield, color: 'bg-purple-50 text-purple-600' },
        { id: 6, name: 'Audit', icon: ClipboardCheck, color: 'bg-rose-50 text-rose-600' },
        { id: 7, name: 'Funding', icon: IndianRupee, color: 'bg-emerald-50 text-emerald-600' },
        { id: 8, name: 'Compliance', icon: Settings, color: 'bg-slate-50 text-slate-600' },
    ];

    return (
        <div className="space-y-6 pb-28 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Header / Welcome Area */}
            <div className="flex justify-between items-center mb-2">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Hello, {userInfo?.name?.split(' ')[0]}!</h1>
                    <p className="text-slate-500 text-sm">Here's what's happening today.</p>
                </div>
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

            {/* Floating Search Bar */}
            <div className="relative z-10 -mt-2">
                <div className="bg-white rounded-2xl shadow-xl shadow-slate-200/50 border border-slate-100 flex items-center px-4 py-3 gap-3">
                    <Search size={18} className="text-slate-400" />
                    <input
                        type="text"
                        placeholder="Search services (e.g. GST, Company...)"
                        className="flex-1 bg-transparent border-none outline-none text-sm font-medium text-slate-700 placeholder:text-slate-400"
                    />
                    <div className="w-px h-4 bg-slate-100 mx-1"></div>
                    <button onClick={() => setActiveTab('Services')} className="text-indigo-600 font-black text-[10px] uppercase tracking-wider">Find</button>
                </div>
            </div>

            {/* Main Hero Card */}
            <div className="bg-gradient-to-br from-indigo-600 via-indigo-700 to-violet-800 rounded-3xl p-6 text-white shadow-xl shadow-indigo-200 relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-32 h-32 bg-white/10 rounded-full -mr-16 -mt-16 blur-2xl group-hover:bg-white/20 transition-all duration-700"></div>
                <div className="relative z-10">
                    <div className="flex items-center gap-2 mb-4 opacity-80">
                        <Briefcase size={16} />
                        <span className="text-xs font-bold uppercase tracking-wider">Active Portfolio</span>
                    </div>
                    <div className="flex items-end justify-between">
                        <div>
                            <h2 className="text-4xl font-black mb-1">{activeOrders.length}</h2>
                            <p className="text-indigo-100 text-sm font-medium">Running Projects</p>
                        </div>
                        <button
                            onClick={() => setActiveTab('Orders')}
                            className="bg-white/20 backdrop-blur-md px-4 py-2 rounded-xl text-sm font-bold hover:bg-white/30 transition shadow-lg"
                        >
                            Track All
                        </button>
                    </div>
                </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-2 gap-4">
                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex flex-col gap-3">
                    <div className="w-10 h-10 bg-amber-50 text-amber-500 rounded-2xl flex items-center justify-center">
                        <AlertTriangle size={20} />
                    </div>
                    <div>
                        <p className="text-slate-500 text-[10px] font-bold uppercase tracking-wider">Actions</p>
                        <h3 className="text-xl font-black text-slate-800">{pendingActions.length}</h3>
                    </div>
                </div>
                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex flex-col gap-3">
                    <div className="w-10 h-10 bg-emerald-50 text-emerald-500 rounded-2xl flex items-center justify-center">
                        <CreditCard size={20} />
                    </div>
                    <div>
                        <p className="text-slate-500 text-[10px] font-bold uppercase tracking-wider">Invested</p>
                        <h3 className="text-xl font-black text-slate-800">₹{orders.reduce((acc, curr) => acc + curr.price, 0).toLocaleString()}</h3>
                    </div>
                </div>
            </div>

            {/* Top Services Grid (2x4) */}
            <div className="bg-white rounded-[32px] p-6 border border-slate-100 shadow-sm">
                <div className="flex justify-between items-center mb-6">
                    <h3 className="font-black text-slate-800">Top Services</h3>
                    <div className="w-8 h-1 bg-indigo-100 rounded-full"></div>
                </div>
                <div className="grid grid-cols-4 gap-y-6 gap-x-2">
                    {topServices.map(service => (
                        <button
                            key={service.id}
                            onClick={() => setActiveTab('Services')}
                            className="flex flex-col items-center gap-2 group"
                        >
                            <div className={`w-12 h-12 ${service.color} rounded-2xl flex items-center justify-center shadow-sm group-active:scale-90 transition-transform`}>
                                <service.icon size={20} />
                            </div>
                            <span className="text-[10px] font-bold text-slate-600 text-center leading-tight">{service.name}</span>
                        </button>
                    ))}
                </div>
                <button
                    onClick={() => setActiveTab('Services')}
                    className="w-full mt-6 py-3 bg-slate-50 rounded-2xl text-slate-500 text-xs font-black uppercase tracking-widest flex items-center justify-center gap-2 hover:bg-slate-100 transition-colors"
                >
                    View All Services <ChevronRight size={14} />
                </button>
            </div>

            {/* Recent Tracking Section */}
            <div>
                <div className="flex justify-between items-center mb-4 px-1">
                    <h3 className="font-black text-slate-800 text-lg">Active Tracking</h3>
                    <button onClick={() => setActiveTab('Orders')} className="text-indigo-600 text-xs font-bold flex items-center gap-1">
                        View All <ChevronRight size={14} />
                    </button>
                </div>
                <div className="space-y-4">
                    {activeOrders.slice(0, 3).map(proj => (
                        <div key={proj._id} className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm hover:shadow-md transition-shadow group">
                            <div className="flex justify-between items-start mb-3">
                                <div className="max-w-[70%]">
                                    <h4 className="font-bold text-slate-800 text-sm group-hover:text-indigo-600 transition-colors line-clamp-1">{proj.serviceName}</h4>
                                    <p className="text-[10px] text-slate-400 font-medium">{proj.packageName}</p>
                                </div>
                                <StatusBadge status={proj.status} />
                            </div>
                            <div className="space-y-2">
                                <div className="flex justify-between text-[10px] font-bold text-slate-400">
                                    <span>Progress</span>
                                    <span className="text-indigo-600">{getStatusProgress(proj.status)}%</span>
                                </div>
                                <div className="w-full h-1.5 bg-slate-50 rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-gradient-to-r from-indigo-500 to-violet-500 rounded-full transition-all duration-1000 ease-out"
                                        style={{ width: `${getStatusProgress(proj.status)}%` }}
                                    ></div>
                                </div>
                            </div>
                        </div>
                    ))}
                    {activeOrders.length === 0 && (
                        <div className="bg-slate-50 border-2 border-dashed border-slate-200 rounded-3xl p-8 text-center">
                            <div className="w-12 h-12 bg-white rounded-full flex items-center justify-center mx-auto mb-3 shadow-sm">
                                <Plus className="text-slate-300" size={24} />
                            </div>
                            <p className="text-slate-400 text-sm font-medium">No active projects</p>
                            <button onClick={() => setActiveTab('Services')} className="mt-2 text-indigo-600 text-xs font-bold">Explore Services</button>
                        </div>
                    )}
                </div>
            </div>

            {/* Latest News Section */}
            <div>
                <div className="flex justify-between items-center mb-4 px-1">
                    <h3 className="font-black text-slate-800 text-lg">Latest Business News</h3>
                </div>
                <div className="bg-white rounded-3xl border border-slate-100 overflow-hidden shadow-sm group">
                    <div className="h-40 bg-slate-900 relative flex items-center justify-center overflow-hidden">
                        <div className="absolute inset-0 bg-gradient-to-t from-slate-900 to-transparent z-10"></div>
                        <div className="w-full h-full opacity-40 bg-[url('https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&q=80&w=2426&ixlib=rb-4.0.3')] bg-cover bg-center group-hover:scale-105 transition-transform duration-700"></div>
                        <div className="absolute bottom-4 left-6 z-20">
                            <span className="px-2 py-1 bg-red-600 text-[10px] font-black text-white rounded-lg uppercase tracking-widest">Update</span>
                        </div>
                    </div>
                    <div className="p-6">
                        <h4 className="font-black text-slate-800 mb-2 leading-tight">GST Compliance: New Rules for IT Credit in 2026</h4>
                        <p className="text-xs text-slate-500 mb-4 line-clamp-2">Stay ahead of the curve with the latest amendments in GST laws affecting MSMEs...</p>
                        <button className="text-indigo-600 text-xs font-black uppercase tracking-widest flex items-center gap-1">
                            Read Full Article <ExternalLink size={12} />
                        </button>
                    </div>
                </div>
                <button className="w-full mt-4 py-3 border-2 border-dashed border-slate-200 rounded-2xl text-slate-400 text-[10px] font-black uppercase tracking-widest flex items-center justify-center gap-2 hover:bg-slate-50 transition-colors">
                    See All Articles <Newspaper size={14} />
                </button>
            </div>

            {/* Refer a Friend Section */}
            <div className="bg-indigo-900 rounded-[32px] p-6 relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/20 rounded-full -mr-16 -mt-16 blur-3xl group-hover:bg-indigo-500/30 transition-all duration-700"></div>
                <div className="relative z-10 flex items-center gap-5">
                    <div className="w-16 h-16 bg-gradient-to-tr from-yellow-400 to-orange-500 rounded-2xl flex items-center justify-center shadow-lg shadow-orange-500/20 transform -rotate-6 group-hover:rotate-0 transition-transform">
                        <Gift className="text-white" size={32} />
                    </div>
                    <div>
                        <h3 className="text-white font-black text-lg leading-tight mb-1">Refer & Earn ₹1000</h3>
                        <p className="text-indigo-200 text-xs font-medium mb-3">Get credit for every business you refer.</p>
                        <button className="bg-white text-indigo-900 px-5 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-slate-50 transition-colors">
                            Invite Now
                        </button>
                    </div>
                </div>
            </div>

            {/* Action Items for Pending Projects */}
            {pendingActions.length > 0 && (
                <div className="bg-rose-50 border border-rose-100 rounded-3xl p-5 flex items-start gap-4 shadow-sm shadow-rose-100/50">
                    <div className="w-10 h-10 bg-white rounded-2xl flex items-center justify-center shadow-sm text-rose-500 shrink-0">
                        <Upload size={20} />
                    </div>
                    <div>
                        <h4 className="text-sm font-bold text-rose-900 mb-1">Upload Documents</h4>
                        <p className="text-xs text-rose-700/70 mb-3 leading-relaxed">Some of your projects are pending documents. Please upload them to avoid delays.</p>
                        <button
                            onClick={() => setActiveTab('Documents')}
                            className="bg-rose-500 text-white px-4 py-2 rounded-xl text-xs font-black shadow-lg shadow-rose-200 hover:bg-rose-600 transition-colors"
                        >
                            Fix Now
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DashboardView;
