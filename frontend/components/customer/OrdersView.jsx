import React from 'react';
import {
    CheckSquare, Clock, Package, CheckCircle2,
    AlertCircle, ChevronRight, FileText, Search
} from 'lucide-react';
import ProjectDetailsView from './ProjectDetailsView';

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
        'Processing at Portal': 'bg-blue-100 text-blue-700 border-blue-200',
        'Waiting for Clarification': 'bg-amber-100 text-amber-700 border-amber-200',
        'Completed': 'bg-emerald-100 text-emerald-700 border-emerald-200',
        'Pending Documents': 'bg-rose-100 text-rose-700 border-rose-200',
        'Documents Verified': 'bg-indigo-100 text-indigo-700 border-indigo-200',
    };
    return (
        <span className={`px-2 py-0.5 rounded-lg text-[10px] font-black uppercase tracking-wider border ${styles[status] || 'bg-slate-100 border-slate-200 text-slate-500'}`}>
            {status}
        </span>
    );
};

const OrdersView = ({ orders, notifications, selectedOrderId, setSelectedOrderId, onOpenVault, payments, setActiveTab }) => {
    if (selectedOrderId) {
        const order = orders.find(o => o._id === selectedOrderId);
        if (order) {
            return (
                <ProjectDetailsView 
                    order={order} 
                    payments={payments} 
                    onBack={() => setSelectedOrderId(null)} 
                    onOpenVault={onOpenVault}
                />
            );
        }
    }

    return (
        <div className="space-y-6 pb-20 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex justify-between items-end mb-2 px-1">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Your Orders</h1>
                    <p className="text-slate-500 text-sm">Track the progress of your active requests.</p>
                </div>
            </div>

            {/* Filter / Search Tags */}
            <div className="flex gap-2 overflow-x-auto pb-2 scrollbar-none">
                {['All', 'Active', 'Completed', 'Action Required'].map((tag, i) => (
                    <button
                        key={tag}
                        className={`px-4 py-1.5 rounded-full text-xs font-bold whitespace-nowrap border transition-all ${i === 0 ? 'bg-red-600 border-red-600 text-white shadow-md shadow-red-600/20' : 'bg-white border-slate-200/90 text-slate-600 hover:border-slate-300'}`}
                    >
                        {tag}
                    </button>
                ))}
            </div>

            {/* Orders List */}
            <div className="space-y-4 mt-6 pb-2 cursor-pointer">
                {orders.map((proj) => (
                    <div 
                        key={proj._id} 
                        onClick={() => setSelectedOrderId ? setSelectedOrderId(proj._id) : {}} 
                        className="bg-white rounded-3xl border border-slate-200/90 shadow-2xs overflow-hidden group hover:shadow-lg hover:border-red-300 transition-all"
                    >
                        <div className="p-5 lg:flex lg:items-center lg:justify-between lg:gap-6">
                            
                            {/* Title & ID (Left) */}
                            <div className="mb-4 lg:mb-0 lg:w-1/4">
                                <h3 className="font-black text-slate-900 text-sm mb-1 group-hover:text-red-600 transition-colors line-clamp-1">{proj.serviceName}</h3>
                                <div className="flex items-center gap-1.5 text-[10px] text-slate-400 font-bold uppercase tracking-wider">
                                    <Package size={12} />
                                    <span>ID: {proj._id.slice(-8).toUpperCase()}</span>
                                </div>
                            </div>

                            {/* Status Badge (Center-Left) */}
                            <div className="hidden lg:flex lg:w-1/6">
                                <StatusBadge status={proj.status} />
                            </div>

                            {/* Progress Section (Center) */}
                            <div className="mb-4 lg:mb-0 bg-slate-50/80 p-4 lg:p-3 rounded-2xl lg:flex-1 lg:max-w-md border border-slate-100">
                                <div className="flex justify-between items-center text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2 border-b border-transparent lg:border-none">
                                    <div className="flex items-center gap-1 lg:hidden">
                                        <Clock size={10} />
                                        <span>Current Phase</span>
                                    </div>
                                    <span className="text-red-600 lg:text-right lg:w-full font-bold">{getStatusProgress(proj.status)}% Complete</span>
                                </div>
                                <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-gradient-to-r from-red-600 to-rose-500 rounded-full transition-all duration-1000 ease-out"
                                        style={{ width: `${getStatusProgress(proj.status)}%` }}
                                    ></div>
                                </div>
                            </div>

                            {/* Price & Details Button (Right) */}
                            <div className="flex items-center justify-between lg:w-48 lg:justify-end gap-4 lg:gap-6">
                                <div className="lg:hidden">
                                    <StatusBadge status={proj.status} />
                                </div>
                                <div className="hidden lg:flex items-center gap-1 text-slate-900 font-black text-sm text-right shrink-0">
                                    <span className="text-slate-400 font-bold text-xs mr-0.5">₹</span>
                                    {proj.price?.toLocaleString() || '0'}
                                </div>
                                <button className="flex items-center gap-1.5 bg-red-50 text-red-600 px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-wider group-hover:bg-red-600 group-hover:text-white transition-all shrink-0">
                                    Details <ChevronRight size={12} />
                                </button>
                            </div>
                        </div>
                    </div>
                ))}

                {orders.length === 0 && (
                    <div className="bg-slate-50 border-2 border-dashed border-slate-200 rounded-3xl p-12 text-center">
                        <div className="w-16 h-16 bg-white rounded-3xl flex items-center justify-center mx-auto mb-4 shadow-2xs text-slate-300">
                            <CheckSquare size={32} />
                        </div>
                        <h4 className="text-slate-800 font-black mb-1">No Orders Found</h4>
                        <p className="text-slate-400 text-xs font-medium mb-6">Looks like you haven't started any projects yet.</p>
                        <button onClick={() => setActiveTab?.('Services')} className="bg-red-600 text-white px-6 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider shadow-md hover:bg-red-700 transition-all">
                            Browse Services
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default OrdersView;
