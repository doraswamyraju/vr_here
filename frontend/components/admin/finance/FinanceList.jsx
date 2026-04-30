import React from 'react';
import { Eye, Edit3, Trash2, Download, Clock, CheckCircle2, AlertCircle, XCircle } from 'lucide-react';

const FinanceList = ({ records, loading, onView, onEdit, onDelete, type }) => {
    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center py-20 bg-white rounded-3xl border border-slate-100">
                <div className="w-12 h-12 border-4 border-slate-200 border-t-red-600 rounded-full animate-spin mb-4"></div>
                <p className="text-slate-400 font-bold text-xs uppercase tracking-widest">Fetching Records...</p>
            </div>
        );
    }

    if (records.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center py-20 bg-white rounded-3xl border border-dashed border-slate-200">
                <div className="w-16 h-16 bg-slate-50 text-slate-300 rounded-2xl flex items-center justify-center mb-4">
                    <Clock size={32} />
                </div>
                <p className="text-slate-900 font-black text-lg">No {type}s Found</p>
                <p className="text-slate-400 text-sm font-medium mt-1">Start by creating your first record using the button above.</p>
            </div>
        );
    }

    const getStatusStyle = (status) => {
        switch (status) {
            case 'Paid':
            case 'Accepted':
                return { bg: 'bg-green-50', text: 'text-green-600', icon: CheckCircle2 };
            case 'Sent':
            case 'Draft':
                return { bg: 'bg-blue-50', text: 'text-blue-600', icon: Clock };
            case 'Cancelled':
            case 'Rejected':
                return { bg: 'bg-red-50', text: 'text-red-600', icon: XCircle };
            case 'Partially Paid':
                return { bg: 'bg-amber-50', text: 'text-amber-600', icon: AlertCircle };
            default:
                return { bg: 'bg-slate-50', text: 'text-slate-600', icon: Clock };
        }
    };

    return (
        <div className="bg-white rounded-3xl border border-slate-100 overflow-hidden shadow-xl shadow-slate-200/50">
            <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="bg-slate-50/50 text-slate-400">
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest">Document</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest">Client</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center">Date</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center">Amount</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center">Status</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-50">
                        {records.map((record) => {
                            const statusStyle = getStatusStyle(record.status);
                            const StatusIcon = statusStyle.icon;
                            return (
                                <tr key={record._id} className="hover:bg-slate-50/80 transition-colors group">
                                    <td className="px-6 py-4">
                                        <div>
                                            <p className="text-sm font-black text-slate-900 leading-none">#{record.number}</p>
                                            <p className="text-[10px] text-slate-400 font-bold uppercase mt-1 tracking-tighter">{record.type}</p>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4">
                                        <div>
                                            <p className="text-sm font-bold text-slate-700 leading-none">{record.client.name}</p>
                                            <p className="text-[10px] text-slate-400 font-medium mt-1 truncate max-w-[150px]">{record.client.email || 'No Email'}</p>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 text-center">
                                        <p className="text-xs font-black text-slate-900">{new Date(record.date).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })}</p>
                                    </td>
                                    <td className="px-6 py-4 text-center">
                                        <p className="text-sm font-black text-slate-900 tracking-tight">₹{record.totals.total.toLocaleString()}</p>
                                    </td>
                                    <td className="px-6 py-4">
                                        <div className="flex justify-center">
                                            <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[10px] font-black uppercase tracking-widest ${statusStyle.bg} ${statusStyle.text}`}>
                                                <StatusIcon size={12} /> {record.status}
                                            </span>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4">
                                        <div className="flex justify-end gap-2">
                                            <button 
                                                onClick={() => onView(record)}
                                                className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition-all"
                                                title="View/Print"
                                            >
                                                <Eye size={18} />
                                            </button>
                                            <button 
                                                onClick={() => onEdit(record)}
                                                className="p-2 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-xl transition-all"
                                                title="Edit"
                                            >
                                                <Edit3 size={18} />
                                            </button>
                                            <button 
                                                onClick={() => onDelete(record._id)}
                                                className="p-2 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-xl transition-all"
                                                title="Delete"
                                            >
                                                <Trash2 size={18} />
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default FinanceList;
