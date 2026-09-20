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
            if (Array.isArray(data) && data.length > 0) {
                setRecords(data);
            } else {
                // Fallback to payments data mapped to GST invoice template schema
                const paymentsRes = await axios.get('/api/payments', config);
                const mapped = (paymentsRes.data || []).map(p => {
                    valAmount = p.amount || 0;
                    valSub = Math.round(valAmount / 1.18);
                    valTax = valAmount - valSub;
                    valCgst = Math.round(valTax / 2);
                    valSgst = valTax - valCgst;
                    return {
                        _id: p._id || p.id,
                        type: 'TAX INVOICE',
                        number: (p.id || p._id || 'INV').slice(-8).toUpperCase(),
                        date: p.createdAt || new Date().toISOString(),
                        client: {
                            name: p.customerName || 'Valued Client',
                            email: p.email || '',
                            phone: p.phone || '',
                            address: 'Registered Office / Business Premises'
                        },
                        items: [
                            {
                                description: p.serviceName || 'Professional Compliance & Legal Services',
                                hsn: '998311',
                                qty: 1,
                                rate: valSub,
                                taxRate: 18,
                                amount: valSub
                            }
                        ],
                        totals: {
                            subtotal: valSub,
                            cgst: valCgst,
                            sgst: valSgst,
                            total: valAmount
                        },
                        status: (p.status === 'Completed' || p.status === 'Paid') ? 'Paid' : p.status,
                        url: p.invoiceUrl || ''
                    };
                });
                setRecords(mapped);
            }
        } catch (error) {
            console.error('Failed to fetch invoices, trying payments fallback:', error);
            try {
                const paymentsRes = await axios.get('/api/payments', config);
                const mapped = (paymentsRes.data || []).map(p => {
                    const valAmount = p.amount || 0;
                    const valSub = Math.round(valAmount / 1.18);
                    const valTax = valAmount - valSub;
                    const valCgst = Math.round(valTax / 2);
                    const valSgst = valTax - valCgst;
                    return {
                        _id: p._id || p.id,
                        type: 'TAX INVOICE',
                        number: (p.id || p._id || 'INV').slice(-8).toUpperCase(),
                        date: p.createdAt || new Date().toISOString(),
                        client: {
                            name: p.customerName || 'Valued Client',
                            email: p.email || '',
                            phone: p.phone || '',
                            address: 'Registered Office / Business Premises'
                        },
                        items: [
                            {
                                description: p.serviceName || 'Professional Compliance & Legal Services',
                                hsn: '998311',
                                qty: 1,
                                rate: valSub,
                                taxRate: 18,
                                amount: valSub
                            }
                        ],
                        totals: {
                            subtotal: valSub,
                            cgst: valCgst,
                            sgst: valSgst,
                            total: valAmount
                        },
                        status: (p.status === 'Completed' || p.status === 'Paid') ? 'Paid' : p.status,
                        url: p.invoiceUrl || ''
                    };
                });
                setRecords(mapped);
            } catch (err) {
                console.error('Failed fetching payments fallback:', err);
            }
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
        <div className="space-y-6 pb-20">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h2 className="text-2xl font-black text-slate-900 tracking-tight leading-none mb-1">Billing & Invoices</h2>
                    <p className="text-xs text-slate-500 font-medium">View and download your service estimates, proforma, and tax invoices.</p>
                </div>
                <div className="bg-white px-3 py-1.5 rounded-xl border border-slate-100 flex items-center gap-2 text-[10px] font-black text-slate-400 uppercase tracking-widest">
                    <CheckCircle2 size={12} className="text-green-500" /> GST Compliant Billing
                </div>
            </div>

            {loading ? (
                <div className="flex flex-col items-center justify-center py-16 bg-white rounded-3xl border border-slate-100 shadow-sm">
                    <div className="w-10 h-10 border-4 border-slate-200 border-t-red-600 rounded-full animate-spin mb-3"></div>
                    <p className="text-slate-400 font-bold text-xs uppercase tracking-widest">Loading Invoices...</p>
                </div>
            ) : records.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 bg-white rounded-3xl border border-dashed border-slate-200">
                    <div className="w-14 h-14 bg-slate-50 text-slate-300 rounded-2xl flex items-center justify-center mb-3">
                        <FileText size={28} />
                    </div>
                    <p className="text-slate-900 font-black text-base">No Billing History Yet</p>
                    <p className="text-slate-400 text-xs font-medium mt-1">Your invoices will appear here once your projects are initiated.</p>
                </div>
            ) : (
                <div className="bg-white rounded-3xl border border-slate-200/80 overflow-hidden shadow-sm">
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-50/80 text-slate-500 border-b border-slate-200/60">
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest">Type</th>
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest">Invoice #</th>
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center">Date</th>
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center">Amount</th>
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-center">Status</th>
                                    <th className="px-6 py-4 text-[10px] font-black uppercase tracking-widest text-right">View / PDF</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {records.map((record) => {
                                    const style = getStatusStyle(record.status);
                                    const Icon = style.icon;
                                    return (
                                        <tr 
                                            key={record._id} 
                                            onClick={() => setSelectedRecord(record)}
                                            className="hover:bg-slate-50/80 transition-all group cursor-pointer"
                                        >
                                            <td className="px-6 py-4">
                                                <span className="text-[10px] font-black text-red-600 bg-red-50 px-2.5 py-1 rounded-md uppercase tracking-wider">{record.type}</span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <p className="text-xs font-black text-slate-900">#{record.number}</p>
                                            </td>
                                            <td className="px-6 py-4 text-center">
                                                <p className="text-xs font-bold text-slate-600">{new Date(record.date).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })}</p>
                                            </td>
                                            <td className="px-6 py-4 text-center">
                                                <p className="text-xs font-black text-slate-900 tracking-tight">₹{record.totals?.total?.toLocaleString() || '0'}</p>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex justify-center">
                                                    <span className={`inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full text-[10px] font-black uppercase tracking-widest ${style.bg} ${style.text}`}>
                                                        <Icon size={12} /> {record.status}
                                                    </span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 text-right flex items-center justify-end gap-2" onClick={e => e.stopPropagation()}>
                                                {record.url && record.status !== 'Paid' && record.status !== 'Cancelled' && (
                                                    <a 
                                                        href={record.url}
                                                        target="_blank"
                                                        rel="noreferrer"
                                                        className="px-3 py-1 bg-red-600 text-white font-black text-[10px] rounded-lg uppercase tracking-wider hover:bg-red-700 transition shadow-sm flex items-center gap-1"
                                                    >
                                                        Pay Now
                                                    </a>
                                                )}
                                                <button 
                                                    onClick={() => setSelectedRecord(record)}
                                                    className="p-2 bg-slate-100 text-slate-500 group-hover:text-red-600 group-hover:bg-red-50 rounded-xl transition-all flex items-center gap-1 text-[11px] font-bold"
                                                    title="View Tax Invoice PDF"
                                                >
                                                    <Eye size={16} /> View Invoice
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
