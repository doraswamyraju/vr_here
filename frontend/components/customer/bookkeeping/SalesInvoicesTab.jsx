import React, { useState } from 'react';
import { Plus, Search, Eye, Trash2, MessageCircle, FileText, CheckCircle2, Clock, AlertCircle } from 'lucide-react';

const SalesInvoicesTab = ({
    transactions = [],
    onAddNew,
    onViewInvoice,
    onDeleteInvoice,
    onWhatsAppShare,
    company
}) => {
    const [search, setSearch] = useState('');
    const [statusFilter, setStatusFilter] = useState('All');

    const salesInvoices = transactions.filter(t => t.transactionType === 'Sales');

    const filtered = salesInvoices.filter(t => {
        const matchesSearch = (t.docNumber || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.partyName || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.partyGstin || '').toLowerCase().includes(search.toLowerCase());
        const matchesStatus = statusFilter === 'All' || (t.paymentStatus || 'Unpaid') === statusFilter;
        return matchesSearch && matchesStatus;
    });

    const totalSalesValue = salesInvoices.reduce((acc, curr) => acc + (curr.summary?.totalAmount || 0), 0);
    const totalTaxCollected = salesInvoices.reduce((acc, curr) => acc + ((curr.summary?.totalCgst || 0) + (curr.summary?.totalSgst || 0) + (curr.summary?.totalIgst || 0)), 0);
    const unpaidCount = salesInvoices.filter(t => (t.paymentStatus || 'Unpaid') === 'Unpaid').length;

    return (
        <div className="space-y-6">
            {/* Metric KPI Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Total Sales Invoiced</p>
                        <h3 className="text-2xl font-black text-slate-900 mt-1">₹{totalSalesValue.toLocaleString('en-IN')}</h3>
                        <p className="text-[11px] text-emerald-600 font-bold mt-0.5">{salesInvoices.length} Invoices Generated</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-emerald-50 text-emerald-600 flex items-center justify-center font-black">
                        ₹
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Output GST Liability</p>
                        <h3 className="text-2xl font-black text-indigo-950 mt-1">₹{totalTaxCollected.toLocaleString('en-IN')}</h3>
                        <p className="text-[11px] text-indigo-600 font-bold mt-0.5">CGST + SGST + IGST</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center font-black">
                        GST
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Payment Status</p>
                        <h3 className="text-2xl font-black text-amber-600 mt-1">{unpaidCount} Pending</h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">Awaiting Bank Settlement</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-amber-50 text-amber-600 flex items-center justify-center font-black">
                        <Clock size={20} />
                    </div>
                </div>
            </div>

            {/* Filter & Search Bar */}
            <div className="bg-white p-4 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row gap-3 items-center justify-between">
                <div className="relative w-full md:w-80">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
                    <input 
                        type="text" 
                        value={search} 
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search invoice no, party, GSTIN..."
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs font-medium text-slate-900 focus:outline-none focus:border-indigo-500"
                    />
                </div>

                <div className="flex items-center gap-2 w-full md:w-auto justify-between md:justify-end">
                    <div className="flex bg-slate-100 p-1 rounded-2xl text-xs font-bold">
                        {['All', 'Paid', 'Unpaid'].map(tab => (
                            <button
                                key={tab}
                                onClick={() => setStatusFilter(tab)}
                                className={`px-3 py-1.5 rounded-xl transition ${
                                    statusFilter === tab ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-600 hover:text-slate-900'
                                }`}
                            >
                                {tab}
                            </button>
                        ))}
                    </div>

                    <button 
                        onClick={onAddNew}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-2xl font-black text-xs uppercase tracking-wider flex items-center gap-1.5 transition shadow-md shadow-indigo-100"
                    >
                        <Plus size={16} /> Create Sales Invoice
                    </button>
                </div>
            </div>

            {/* Invoices Table */}
            <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden">
                {filtered.length === 0 ? (
                    <div className="text-center py-20 space-y-3">
                        <FileText size={48} className="mx-auto text-slate-300" />
                        <p className="text-slate-500 font-bold text-sm">No sales invoices found</p>
                        <button 
                            onClick={onAddNew}
                            className="text-xs text-indigo-600 font-black hover:underline"
                        >
                            + Generate your first invoice
                        </button>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="bg-slate-50/75 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-100">
                                    <th className="px-6 py-4">Invoice No</th>
                                    <th className="px-6 py-4">Date</th>
                                    <th className="px-6 py-4">Customer (Party)</th>
                                    <th className="px-6 py-4">Place of Supply</th>
                                    <th className="px-6 py-4">Taxable (₹)</th>
                                    <th className="px-6 py-4">Total Amount (₹)</th>
                                    <th className="px-6 py-4">Payment</th>
                                    <th className="px-6 py-4 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filtered.map((inv) => (
                                    <tr key={inv._id} className="hover:bg-slate-50/60 transition group">
                                        <td className="px-6 py-4 font-black font-mono text-slate-900">{inv.docNumber}</td>
                                        <td className="px-6 py-4 text-slate-600 font-medium">
                                            {inv.docDate ? new Date(inv.docDate).toLocaleDateString('en-GB') : '-'}
                                        </td>
                                        <td className="px-6 py-4">
                                            <p className="font-bold text-slate-900">{inv.partyName}</p>
                                            {inv.partyGstin && <p className="text-[10px] font-mono text-slate-400">{inv.partyGstin}</p>}
                                        </td>
                                        <td className="px-6 py-4 text-slate-600 font-medium">{inv.placeOfSupply}</td>
                                        <td className="px-6 py-4 font-mono font-bold text-slate-700">
                                            ₹{(inv.summary?.totalTaxableValue || 0).toLocaleString('en-IN')}
                                        </td>
                                        <td className="px-6 py-4 font-mono font-black text-slate-900 text-sm">
                                            ₹{(inv.summary?.totalAmount || 0).toLocaleString('en-IN')}
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                                inv.paymentStatus === 'Paid' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                                                inv.paymentStatus === 'Partially Paid' ? 'bg-blue-50 text-blue-700 border border-blue-200' :
                                                'bg-amber-50 text-amber-700 border border-amber-200'
                                            }`}>
                                                {inv.paymentStatus || 'Unpaid'}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-right space-x-1">
                                            <button 
                                                onClick={() => onViewInvoice(inv)}
                                                title="View / Print Tax Invoice"
                                                className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition inline-flex items-center"
                                            >
                                                <Eye size={16} />
                                            </button>
                                            <button 
                                                onClick={() => onWhatsAppShare(inv)}
                                                title="Share via WhatsApp"
                                                className="p-2 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-xl transition inline-flex items-center"
                                            >
                                                <MessageCircle size={16} />
                                            </button>
                                            <button 
                                                onClick={() => onDeleteInvoice(inv._id)}
                                                title="Delete Invoice"
                                                className="p-2 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-xl transition inline-flex items-center"
                                            >
                                                <Trash2 size={16} />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};

export default SalesInvoicesTab;
