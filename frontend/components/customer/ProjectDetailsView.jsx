import React from 'react';
import { 
    ArrowLeft, Clock, FileText, Mail, Phone, User, 
    CheckCircle2, Circle, AlertCircle, FileCheck, IndianRupee 
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

const ProjectDetailsView = ({ order, payments = [], onBack, onOpenVault }) => {
    // Filter payments for this order
    const orderPayments = payments.filter((p) => {
        const pOrderId = p.order?._id || p.order;
        return pOrderId === order._id;
    });
    const totalPaid = orderPayments.reduce((acc, curr) => acc + (curr.status === 'Completed' ? curr.amount : 0), 0);
    const balance = Math.max(0, order.price - totalPaid);

    return (
        <div className="space-y-6 pb-20 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Header */}
            <div className="flex items-center gap-4 mb-2 px-1">
                <button 
                    onClick={onBack}
                    className="p-2 bg-white border border-slate-200 rounded-xl text-slate-600 hover:bg-slate-50 transition-colors"
                >
                    <ArrowLeft size={20} />
                </button>
                <div>
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">{order.serviceName}</h1>
                    <p className="text-slate-500 text-sm">ID: {order._id.slice(-8).toUpperCase()} • {order.packageName}</p>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Main Content (2/3) */}
                <div className="lg:col-span-2 space-y-6">
                    {/* Status & Progress */}
                    <div className="bg-white rounded-3xl border border-slate-100 shadow-sm p-6">
                        <h3 className="text-sm font-black text-slate-800 mb-4">Project Completion Status</h3>
                        <div className="space-y-4">
                            <div className="flex justify-between text-xs font-black uppercase tracking-widest text-slate-500">
                                <span>Current Phase: {order.status}</span>
                                <span className="text-indigo-600">{getStatusProgress(order.status)}% Complete</span>
                            </div>
                            <div className="w-full h-3 bg-slate-100 rounded-full overflow-hidden">
                                <div
                                    className="h-full bg-gradient-to-r from-indigo-500 via-indigo-600 to-indigo-700 rounded-full transition-all duration-1000 ease-out shadow-[0_0_8px_rgba(99,102,241,0.5)]"
                                    style={{ width: `${getStatusProgress(order.status)}%` }}
                                ></div>
                            </div>
                        </div>
                    </div>

                    {/* Latest Updates / Tasks */}
                    <div className="bg-white rounded-3xl border border-slate-100 shadow-sm p-6">
                        <h3 className="text-sm font-black text-slate-800 mb-4">Latest Updates & Tasks</h3>
                        {order.tasks && order.tasks.length > 0 ? (
                            <div className="space-y-4">
                                {order.tasks.map((task) => (
                                    <div key={task._id} className="flex gap-4">
                                        <div className="mt-1">
                                            {task.status === 'Completed' ? (
                                                <CheckCircle2 size={20} className="text-emerald-500" />
                                            ) : task.status === 'In Progress' ? (
                                                <Clock size={20} className="text-indigo-500" />
                                            ) : (
                                                <Circle size={20} className="text-slate-300" />
                                            )}
                                        </div>
                                        <div>
                                            <p className={`text-sm font-bold ${task.status === 'Completed' ? 'text-slate-700' : 'text-slate-800'}`}>
                                                {task.title}
                                            </p>
                                            <p className="text-xs text-slate-500 mt-0.5">{task.description}</p>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="text-center py-6 text-slate-400">
                                <AlertCircle size={32} className="mx-auto mb-2 opacity-50" />
                                <p className="text-xs font-bold">No tasks or updates available yet.</p>
                            </div>
                        )}
                    </div>

                    {/* Documents Summary */}
                    <div className="bg-white rounded-3xl border border-slate-100 shadow-sm p-6">
                        <div className="flex justify-between items-center mb-4">
                            <h3 className="text-sm font-black text-slate-800">Documents</h3>
                            <button 
                                onClick={onOpenVault}
                                className="text-xs font-black text-indigo-600 hover:text-indigo-700 uppercase tracking-widest"
                            >
                                Open Vault
                            </button>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="bg-slate-50 rounded-2xl p-4">
                                <h4 className="text-xs font-black text-slate-600 mb-3 flex items-center gap-2">
                                    <FileCheck size={14} className="text-indigo-500" /> My Uploads
                                </h4>
                                {order.clientDocuments && order.clientDocuments.length > 0 ? (
                                    <ul className="space-y-2">
                                        {(order.clientDocuments || []).slice(0, 3).map((doc) => (
                                            <li key={doc._id} className="text-xs text-slate-700 line-clamp-1">
                                                • {doc.name}
                                            </li>
                                        ))}
                                        {order.clientDocuments.length > 3 && (
                                            <li className="text-[10px] text-slate-500 font-bold italic">+{order.clientDocuments.length - 3} more...</li>
                                        )}
                                    </ul>
                                ) : (
                                    <p className="text-xs text-slate-400 italic">No documents uploaded.</p>
                                )}
                            </div>
                            <div className="bg-slate-50 rounded-2xl p-4">
                                <h4 className="text-xs font-black text-slate-600 mb-3 flex items-center gap-2">
                                    <FileText size={14} className="text-amber-500" /> Admin Docs
                                </h4>
                                {order.adminDocuments && order.adminDocuments.length > 0 ? (
                                    <ul className="space-y-2">
                                        {(order.adminDocuments || []).slice(0, 3).map((doc) => (
                                            <li key={doc._id} className="text-xs text-slate-700 line-clamp-1">
                                                • {doc.name}
                                            </li>
                                        ))}
                                        {order.adminDocuments.length > 3 && (
                                            <li className="text-[10px] text-slate-500 font-bold italic">+{order.adminDocuments.length - 3} more...</li>
                                        )}
                                    </ul>
                                ) : (
                                    <p className="text-xs text-slate-400 italic">No admin documents yet.</p>
                                )}
                            </div>
                        </div>
                    </div>
                </div>

                {/* Sidebar (1/3) */}
                <div className="space-y-6">
                    {/* Assigned Employee */}
                    <div className="bg-white rounded-3xl border border-slate-100 shadow-sm p-6 overflow-hidden relative">
                        <div className="absolute top-0 right-0 w-24 h-24 bg-indigo-50 rounded-full -mr-10 -mt-10"></div>
                        <h3 className="text-sm font-black text-slate-800 mb-4 relative z-10">Assigned Expert</h3>
                        {order.assignedEmployee ? (
                            <div className="relative z-10 space-y-3">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 bg-indigo-100 text-indigo-700 rounded-xl flex items-center justify-center font-black">
                                        {order.assignedEmployee.name ? order.assignedEmployee.name.charAt(0).toUpperCase() : 'E'}
                                    </div>
                                    <div>
                                        <p className="text-sm font-bold text-slate-800">{order.assignedEmployee.name}</p>
                                        <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest">{order.assignedEmployee.role || 'Expert'}</p>
                                    </div>
                                </div>
                                <div className="pt-2 border-t border-slate-100 space-y-2">
                                    {order.assignedEmployee.email && (
                                        <div className="flex items-center gap-2 text-xs text-slate-600">
                                            <Mail size={14} className="text-slate-400" />
                                            {order.assignedEmployee.email}
                                        </div>
                                    )}
                                    {order.assignedEmployee.phone && (
                                        <div className="flex items-center gap-2 text-xs text-slate-600">
                                            <Phone size={14} className="text-slate-400" />
                                            {order.assignedEmployee.phone}
                                        </div>
                                    )}
                                </div>
                            </div>
                        ) : (
                            <div className="relative z-10 text-center py-4 text-slate-500">
                                <User size={24} className="mx-auto mb-2 opacity-50" />
                                <p className="text-xs font-bold">Expert assignment pending.</p>
                            </div>
                        )}
                    </div>

                    {/* Financial Summary */}
                    <div className="bg-emerald-50 rounded-3xl border border-emerald-100 shadow-sm p-6">
                        <h3 className="text-sm font-black text-emerald-900 mb-4 flex items-center gap-2">
                            <IndianRupee size={18} /> Financial Summary
                        </h3>
                        <div className="space-y-3">
                            <div className="flex justify-between items-center text-sm font-bold text-emerald-800">
                                <span>Total Price</span>
                                <span>₹{order.price?.toLocaleString()}</span>
                            </div>
                            <div className="flex justify-between items-center text-sm text-emerald-700/80">
                                <span>Amount Paid</span>
                                <span>₹{totalPaid.toLocaleString()}</span>
                            </div>
                            <div className="pt-3 border-t border-emerald-200/50 flex justify-between items-center font-black text-emerald-900">
                                <span>Balance Due</span>
                                <span>₹{balance.toLocaleString()}</span>
                            </div>
                        </div>
                        {orderPayments.length > 0 && (
                            <div className="mt-4 pt-4 border-t border-emerald-200/50">
                                <p className="text-[10px] font-black uppercase tracking-widest text-emerald-700/70 mb-2">Recent Invoices</p>
                                <div className="space-y-2">
                                    {orderPayments.map((p) => (
                                        <div key={p._id} className="flex justify-between items-center text-xs">
                                            <span className="text-emerald-800 font-medium">{new Date(p.createdAt).toLocaleDateString()}</span>
                                            <span className="font-bold text-emerald-900">₹{p.amount.toLocaleString()} ({p.status})</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ProjectDetailsView;
