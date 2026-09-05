import React, { useState } from 'react';
import axios from 'axios';
import { 
    Plus, Search, Eye, Edit2, Trash2, MessageCircle, FileText, 
    CheckCircle2, Clock, AlertCircle, ArrowDownLeft, Check, X, Wallet 
} from 'lucide-react';

const SalesInvoicesTab = ({
    token,
    transactions = [],
    onAddNew,
    onEditInvoice,
    onViewInvoice,
    onDeleteInvoice,
    onWhatsAppShare,
    onRefreshData,
    company
}) => {
    const [search, setSearch] = useState('');
    const [statusFilter, setStatusFilter] = useState('All');

    // Payment In Modal State
    const [activePaymentInvoice, setActivePaymentInvoice] = useState(null);
    const [paymentAmount, setPaymentAmount] = useState('');
    const [paymentDate, setPaymentDate] = useState(new Date().toISOString().split('T')[0]);
    const [paymentMode, setPaymentMode] = useState('UPI');
    const [referenceNo, setReferenceNo] = useState('');
    const [paymentNotes, setPaymentNotes] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    const salesInvoices = transactions.filter(t => t.transactionType === 'Sales');

    const filtered = salesInvoices.filter(t => {
        const matchesSearch = (t.docNumber || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.partyName || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.partyGstin || '').toLowerCase().includes(search.toLowerCase());
        const matchesStatus = statusFilter === 'All' || (t.paymentStatus || 'Unpaid') === statusFilter;
        return matchesSearch && matchesStatus;
    });

    const totalSalesValue = salesInvoices.reduce((acc, curr) => acc + (curr.summary?.totalAmount || curr.totalAmount || 0), 0);
    const totalCollected = salesInvoices.reduce((acc, curr) => acc + (Number(curr.paidAmount) || 0), 0);
    const totalPending = Math.max(0, totalSalesValue - totalCollected);
    const unpaidCount = salesInvoices.filter(t => (t.paymentStatus || 'Unpaid') !== 'Paid').length;

    // Open Payment In Modal
    const handleOpenPaymentModal = (inv) => {
        const total = Number(inv.summary?.totalAmount || inv.totalAmount || 0);
        const paid = Number(inv.paidAmount) || 0;
        const due = Math.max(0, total - paid);

        setActivePaymentInvoice(inv);
        setPaymentAmount(due > 0 ? String(due) : String(total));
        setPaymentDate(new Date().toISOString().split('T')[0]);
        setPaymentMode(inv.paymentMode || 'UPI');
        setReferenceNo(`PAYIN${Math.floor(100000 + Math.random() * 900000)}`);
        setPaymentNotes('');
    };

    // Submit Payment In
    const handleSubmitPayment = async (e) => {
        e.preventDefault();
        if (!activePaymentInvoice) return;

        const numAmount = parseFloat(paymentAmount);
        if (isNaN(numAmount) || numAmount <= 0) {
            alert('Please enter a valid received payment amount.');
            return;
        }

        setIsSubmitting(true);
        try {
            await axios.post(`/api/accounting/transactions/${activePaymentInvoice._id}/payment`, {
                amount: numAmount,
                paymentDate,
                paymentMode,
                referenceNo,
                notes: paymentNotes
            }, config);

            alert(`Payment of ₹${numAmount.toLocaleString('en-IN')} recorded successfully!`);
            setActivePaymentInvoice(null);
            if (onRefreshData) onRefreshData();
        } catch (error) {
            alert('Failed to record payment: ' + (error.response?.data?.message || error.message));
        } finally {
            setIsSubmitting(false);
        }
    };

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
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Customer Collections</p>
                        <h3 className="text-2xl font-black text-indigo-950 mt-1">₹{totalCollected.toLocaleString('en-IN')}</h3>
                        <p className="text-[11px] text-indigo-600 font-bold mt-0.5">Settled Inward Funds</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center font-black">
                        <Wallet size={20} />
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Outstanding Receivables</p>
                        <h3 className="text-2xl font-black text-amber-600 mt-1">₹{totalPending.toLocaleString('en-IN')}</h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">{unpaidCount} Invoices Pending Settlement</p>
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
                        {['All', 'Paid', 'Partially Paid', 'Unpaid'].map(tab => (
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
                                    <th className="px-6 py-4">Invoice Total (₹)</th>
                                    <th className="px-6 py-4">Paid / Due</th>
                                    <th className="px-6 py-4">Payment Status</th>
                                    <th className="px-6 py-4 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filtered.map((inv) => {
                                    const total = Number(inv.summary?.totalAmount || inv.totalAmount || 0);
                                    const paid = Number(inv.paidAmount) || 0;
                                    const due = Math.max(0, total - paid);

                                    return (
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
                                            <td className="px-6 py-4 font-mono font-black text-slate-900 text-sm">
                                                ₹{total.toLocaleString('en-IN')}
                                            </td>
                                            <td className="px-6 py-4">
                                                <p className="font-mono font-bold text-emerald-700">₹{paid.toLocaleString('en-IN')}</p>
                                                {due > 0 && <p className="text-[10px] font-mono font-bold text-rose-500">Due: ₹{due.toLocaleString('en-IN')}</p>}
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
                                                {inv.paymentStatus !== 'Paid' && (
                                                    <button
                                                        onClick={() => handleOpenPaymentModal(inv)}
                                                        title="Record Payment In (Customer Collection)"
                                                        className="bg-emerald-50 hover:bg-emerald-600 hover:text-white text-emerald-700 px-2.5 py-1.5 rounded-xl font-bold transition inline-flex items-center gap-1 text-[11px] border border-emerald-200 mr-1"
                                                    >
                                                        <ArrowDownLeft size={13} /> Payment In
                                                    </button>
                                                )}
                                                <button 
                                                    onClick={() => onViewInvoice(inv)}
                                                    title="View / Print Tax Invoice"
                                                    className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition inline-flex items-center"
                                                >
                                                    <Eye size={16} />
                                                </button>
                                                {onEditInvoice && (
                                                    <button 
                                                        onClick={() => onEditInvoice(inv)}
                                                        title="Edit Tax Invoice"
                                                        className="p-2 text-slate-400 hover:text-amber-600 hover:bg-amber-50 rounded-xl transition inline-flex items-center"
                                                    >
                                                        <Edit2 size={16} />
                                                    </button>
                                                )}
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
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Direct Payment In Modal */}
            {activePaymentInvoice && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <div>
                                <h3 className="font-black text-slate-900 text-sm">
                                    Record Payment In (Customer Collection)
                                </h3>
                                <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                                    {activePaymentInvoice.docNumber} • {activePaymentInvoice.partyName}
                                </p>
                            </div>
                            <button onClick={() => setActivePaymentInvoice(null)} className="text-slate-400 hover:text-slate-600">
                                <X size={18} />
                            </button>
                        </div>

                        <form onSubmit={handleSubmitPayment} className="p-6 space-y-4 text-xs">
                            <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 flex items-center justify-between">
                                <div>
                                    <span className="text-[10px] font-bold text-slate-400 uppercase block">Invoice Total</span>
                                    <span className="text-sm font-black font-mono text-slate-800">
                                        ₹{Number(activePaymentInvoice.summary?.totalAmount || activePaymentInvoice.totalAmount || 0).toLocaleString('en-IN')}
                                    </span>
                                </div>
                                <div>
                                    <span className="text-[10px] font-bold text-slate-400 uppercase block">Already Paid</span>
                                    <span className="text-sm font-black font-mono text-emerald-600">
                                        ₹{Number(activePaymentInvoice.paidAmount || 0).toLocaleString('en-IN')}
                                    </span>
                                </div>
                                <div>
                                    <span className="text-[10px] font-bold text-slate-400 uppercase block">Pending Due</span>
                                    <span className="text-sm font-black font-mono text-rose-600">
                                        ₹{Math.max(0, Number(activePaymentInvoice.summary?.totalAmount || activePaymentInvoice.totalAmount || 0) - Number(activePaymentInvoice.paidAmount || 0)).toLocaleString('en-IN')}
                                    </span>
                                </div>
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                                    Received Payment Amount (₹) <span className="text-rose-500">*</span>
                                </label>
                                <input 
                                    type="number" 
                                    step="0.01" 
                                    value={paymentAmount}
                                    onChange={(e) => setPaymentAmount(e.target.value)}
                                    placeholder="Enter received amount"
                                    className="w-full bg-white border border-slate-300 rounded-xl p-3 font-mono font-black text-slate-900 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    required
                                />
                            </div>

                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                                        Payment Mode
                                    </label>
                                    <select
                                        value={paymentMode}
                                        onChange={(e) => setPaymentMode(e.target.value)}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-bold text-slate-800 focus:outline-none"
                                    >
                                        <option value="UPI">UPI / GPay / PhonePe</option>
                                        <option value="Bank Transfer">NEFT / RTGS / IMPS</option>
                                        <option value="Cash">Cash</option>
                                        <option value="Cheque">Cheque</option>
                                    </select>
                                </div>

                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                                        Payment Date
                                    </label>
                                    <input 
                                        type="date" 
                                        value={paymentDate}
                                        onChange={(e) => setPaymentDate(e.target.value)}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-bold text-slate-800 focus:outline-none"
                                        required
                                    />
                                </div>
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                                    UTR / Reference / Cheque No
                                </label>
                                <input 
                                    type="text" 
                                    value={referenceNo}
                                    onChange={(e) => setReferenceNo(e.target.value)}
                                    placeholder="e.g. UPI5829104812"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-mono text-xs text-slate-800 focus:outline-none"
                                />
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                                    Collection Notes
                                </label>
                                <input 
                                    type="text" 
                                    value={paymentNotes}
                                    onChange={(e) => setPaymentNotes(e.target.value)}
                                    placeholder="Optional notes or remarks"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 text-xs text-slate-800 focus:outline-none"
                                />
                            </div>

                            <div className="pt-2 flex justify-end gap-2">
                                <button
                                    type="button"
                                    onClick={() => setActivePaymentInvoice(null)}
                                    className="px-4 py-2 rounded-xl text-slate-600 font-bold hover:bg-slate-100 transition"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={isSubmitting}
                                    className="bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-6 py-2 rounded-xl font-bold transition shadow-md shadow-emerald-100 flex items-center gap-1.5"
                                >
                                    <Check size={14} /> {isSubmitting ? 'Recording...' : 'Record Payment In'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default SalesInvoicesTab;

