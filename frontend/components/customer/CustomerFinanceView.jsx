import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Eye, Download, Printer, FileText, Clock, CheckCircle2, XCircle, AlertCircle, Search } from 'lucide-react';
import GSTInvoiceTemplate from '../admin/finance/GSTInvoiceTemplate';

const CustomerFinanceView = ({ token }) => {
    const [records, setRecords] = useState([]);
    const [loading, setLoading] = useState(false);
    const [selectedRecord, setSelectedRecord] = useState(null);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    const fetchRecords = async () => {
        setLoading(true);
        try {
            const { data } = await axios.get('/api/finance', config);
            setRecords(data);
        } catch (error) {
            console.error('Failed to fetch invoices:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchRecords();
    }, []);

    const getStatusStyle = (status) => {
        switch (status) {
            case 'Paid': return { bg: 'bg-green-50', text: 'text-green-600', icon: CheckCircle2 };
            case 'Sent': return { bg: 'bg-blue-50', text: 'text-blue-600', icon: Clock };
            case 'Cancelled': return { bg: 'bg-red-50', text: 'text-red-600', icon: XCircle };
            default: return { bg: 'bg-slate-50', text: 'text-slate-600', icon: Clock };
        }
    };

    if (selectedRecord) {
        return (
            <div className="space-y-6 animate-in fade-in zoom-in-95 duration-500 pb-20">
                <div className="flex justify-between items-center bg-white p-4 rounded-2xl border border-slate-100 sticky top-0 z-10 shadow-sm">
                    <button onClick={() => setSelectedRecord(null)} className="flex items-center gap-2 text-slate-600 font-bold text-sm hover:text-slate-900 transition">
                         Back to Billing
                    </button>
                    <div className="flex gap-2">
                        <button onClick={() => window.print()} className="bg-slate-900 text-white px-6 py-2.5 rounded-xl font-bold text-sm hover:bg-slate-800 transition flex items-center gap-2 shadow-lg shadow-slate-200">
                            <Printer size={18} /> Print / Save PDF
                        </button>
                    </div>
                </div>
                <GSTInvoiceTemplate data={selectedRecord} />
            </div>
        );
    }

    return (
        <div className="space-y-8 pb-20">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h2 className="text-3xl font-black text-slate-900 tracking-tight leading-none mb-2">Billing & Invoices</h2>
                    <p className="text-sm text-slate-500 font-medium">View and download your service estimates, proforma, and tax invoices.</p>
                </div>
                <div className="bg-white px-4 py-2 rounded-xl border border-slate-100 flex items-center gap-2 text-xs font-black text-slate-400 uppercase tracking-widest">
                    <CheckCircle2 size={14} className="text-green-500" /> GST Compliant Billing
                </div>
            </div>

            {loading ? (
                <div className="flex flex-col items-center justify-center py-20 bg-white rounded-[2.5rem] border border-slate-100 shadow-xl shadow-slate-200/50">
                    <div className="w-12 h-12 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin mb-4"></div>
                    <p className="text-slate-400 font-bold text-xs uppercase tracking-widest">Loading Invoices...</p>
                </div>
            ) : records.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-20 bg-white rounded-[2.5rem] border border-dashed border-slate-200">
                    <div className="w-16 h-16 bg-slate-50 text-slate-300 rounded-2xl flex items-center justify-center mb-4">
                        <FileText size={32} />
                    </div>
                    <p className="text-slate-900 font-black text-lg">No Billing History Yet</p>
                    <p className="text-slate-400 text-sm font-medium mt-1">Your invoices will appear here once your projects are initiated.</p>
                </div>
            ) : (
                <div className="bg-white rounded-[2.5rem] border border-slate-100 overflow-hidden shadow-xl shadow-slate-200/50">
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-50/50 text-slate-400">
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Type</th>
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest">Invoice #</th>
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-center">Date</th>
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-center">Amount</th>
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-center">Status</th>
                                    <th className="px-8 py-5 text-[10px] font-black uppercase tracking-widest text-right">View</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-50">
                                {records.map((record) => {
                                    const style = getStatusStyle(record.status);
                                    const Icon = style.icon;
                                    return (
                                        <tr key={record._id} className="hover:bg-slate-50/80 transition-all group">
                                            <td className="px-8 py-6">
                                                <span className="text-xs font-black text-indigo-600 bg-indigo-50 px-3 py-1 rounded-lg uppercase tracking-tighter">{record.type}</span>
                                            </td>
                                            <td className="px-8 py-6">
                                                <p className="text-sm font-black text-slate-900">#{record.number}</p>
                                            </td>
                                            <td className="px-8 py-6 text-center">
                                                <p className="text-xs font-bold text-slate-600">{new Date(record.date).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })}</p>
                                            </td>
                                            <td className="px-8 py-6 text-center">
                                                <p className="text-sm font-black text-slate-900 tracking-tight">₹{record.totals.total.toLocaleString()}</p>
                                            </td>
                                            <td className="px-8 py-6">
                                                <div className="flex justify-center">
                                                    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest ${style.bg} ${style.text}`}>
                                                        <Icon size={12} /> {record.status}
                                                    </span>
                                                </div>
                                            </td>
                                            <td className="px-8 py-6 text-right">
                                                <button 
                                                    onClick={() => setSelectedRecord(record)}
                                                    className="p-2.5 bg-slate-50 text-slate-400 group-hover:text-indigo-600 group-hover:bg-indigo-50 rounded-xl transition-all"
                                                >
                                                    <Eye size={20} />
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
};

export default CustomerFinanceView;
