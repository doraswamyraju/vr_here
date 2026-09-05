import React, { useState } from 'react';
import axios from 'axios';
import { 
    Plus, Search, Eye, Edit2, Trash2, FileText, UploadCloud, 
    ShieldCheck, AlertCircle, ArrowUpRight, Check, X, Clock, Wallet 
} from 'lucide-react';

const PurchaseBillsTab = ({
    token,
    transactions = [],
    onAddNew,
    onEditInvoice,
    onViewInvoice,
    onDeleteInvoice,
    onRefreshData
}) => {
    const [search, setSearch] = useState('');
    const [itcFilter, setItcFilter] = useState('All');
    const [paymentFilter, setPaymentFilter] = useState('All');

    // Payment Out Modal State
    const [activePaymentBill, setActivePaymentBill] = useState(null);
    const [paymentAmount, setPaymentAmount] = useState('');
    const [paymentDate, setPaymentDate] = useState(new Date().toISOString().split('T')[0]);
    const [paymentMode, setPaymentMode] = useState('Bank Transfer');
    const [referenceNo, setReferenceNo] = useState('');
    const [paymentNotes, setPaymentNotes] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    const purchaseBills = transactions.filter(t => t.transactionType === 'Purchase');

    const filtered = purchaseBills.filter(t => {
        const matchesSearch = (t.docNumber || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.partyName || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.partyGstin || '').toLowerCase().includes(search.toLowerCase());
        const matchesItc = itcFilter === 'All' || t.itcEligibility === itcFilter;
        const matchesPayment = paymentFilter === 'All' || (t.paymentStatus || 'Unpaid') === paymentFilter;
        return matchesSearch && matchesItc && matchesPayment;
    });

    const totalPurchases = purchaseBills.reduce((acc, curr) => acc + (curr.summary?.totalAmount || curr.totalAmount || 0), 0);
    const totalPaidOut = purchaseBills.reduce((acc, curr) => acc + (Number(curr.paidAmount) || 0), 0);
    const totalPendingPayable = Math.max(0, totalPurchases - totalPaidOut);
    const eligibleItc = purchaseBills
        .filter(t => t.itcEligibility !== 'Ineligible')
        .reduce((acc, curr) => acc + ((curr.summary?.totalCgst || 0) + (curr.summary?.totalSgst || 0) + (curr.summary?.totalIgst || 0)), 0);

    // Open Payment Out Modal
    const handleOpenPaymentModal = (bill) => {
        const total = Number(bill.summary?.totalAmount || bill.totalAmount || 0);
        const paid = Number(bill.paidAmount) || 0;
        const due = Math.max(0, total - paid);

        setActivePaymentBill(bill);
        setPaymentAmount(due > 0 ? String(due) : String(total));
        setPaymentDate(new Date().toISOString().split('T')[0]);
        setPaymentMode(bill.paymentMode || 'Bank Transfer');
        setReferenceNo(`PAYOUT${Math.floor(100000 + Math.random() * 900000)}`);
        setPaymentNotes('');
    };

    // Submit Payment Out
    const handleSubmitPayment = async (e) => {
        e.preventDefault();
        if (!activePaymentBill) return;

        const numAmount = parseFloat(paymentAmount);
        if (isNaN(numAmount) || numAmount <= 0) {
            alert('Please enter a valid vendor payment amount.');
            return;
        }

        setIsSubmitting(true);
        try {
            await axios.post(`/api/accounting/transactions/${activePaymentBill._id}/payment`, {
                amount: numAmount,
                paymentDate,
                paymentMode,
                referenceNo,
                notes: paymentNotes
            }, config);

            alert(`Vendor payment of ₹${numAmount.toLocaleString('en-IN')} recorded successfully!`);
            setActivePaymentBill(null);
            if (onRefreshData) onRefreshData();
        } catch (error) {
            alert('Failed to record vendor payment: ' + (error.response?.data?.message || error.message));
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <div className="space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Total Inward Purchases</p>
                        <h3 className="text-2xl font-black text-slate-900 mt-1">₹{totalPurchases.toLocaleString('en-IN')}</h3>
                        <p className="text-[11px] text-indigo-600 font-bold mt-0.5">{purchaseBills.length} Vendor Bills</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center font-black">
                        📥
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Vendor Payables Due</p>
                        <h3 className="text-2xl font-black text-rose-600 mt-1">₹{totalPendingPayable.toLocaleString('en-IN')}</h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">Paid: ₹{totalPaidOut.toLocaleString('en-IN')}</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-rose-50 text-rose-600 flex items-center justify-center font-black">
                        <Clock size={20} />
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Eligible Input Credit (ITC)</p>
                        <h3 className="text-2xl font-black text-emerald-600 mt-1">
                            ₹{eligibleItc.toLocaleString('en-IN')}
                        </h3>
                        <p className="text-[11px] text-slate-400 font-semibold mt-0.5">Claimable in GSTR-3B Table 4</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-emerald-50 text-emerald-600 flex items-center justify-center font-black">
                        <ShieldCheck size={22} />
                    </div>
                </div>
            </div>

            {/* Actions & Filters */}
            <div className="bg-white p-4 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row gap-3 items-center justify-between">
                <div className="relative w-full md:w-80">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
                    <input 
                        type="text" 
                        value={search} 
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search bill no, vendor name, GSTIN..."
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs font-medium text-slate-900 focus:outline-none focus:border-indigo-500"
                    />
                </div>

                <div className="flex flex-wrap items-center gap-2 w-full md:w-auto justify-between md:justify-end">
                    <div className="flex bg-slate-100 p-1 rounded-2xl text-xs font-bold">
                        {['All', 'Paid', 'Unpaid'].map(tab => (
                            <button
                                key={tab}
                                onClick={() => setPaymentFilter(tab)}
                                className={`px-2.5 py-1.5 rounded-xl transition text-[11px] ${
                                    paymentFilter === tab ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-600 hover:text-slate-900'
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
                        <Plus size={16} /> Add Purchase Bill
                    </button>
                </div>
            </div>

            {/* Inward Bills Table */}
            <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden">
                {filtered.length === 0 ? (
                    <div className="text-center py-20 space-y-3">
                        <FileText size={48} className="mx-auto text-slate-300" />
                        <p className="text-slate-500 font-bold text-sm">No purchase bills found</p>
                        <button 
                            onClick={onAddNew}
                            className="text-xs text-indigo-600 font-black hover:underline"
                        >
                            + Record your first purchase bill
                        </button>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="bg-slate-50/75 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-100">
                                    <th className="px-6 py-4">Bill No</th>
                                    <th className="px-6 py-4">Date</th>
                                    <th className="px-6 py-4">Vendor Name</th>
                                    <th className="px-6 py-4">ITC Category</th>
                                    <th className="px-6 py-4">Bill Total (₹)</th>
                                    <th className="px-6 py-4">Paid / Due</th>
                                    <th className="px-6 py-4">Payment</th>
                                    <th className="px-6 py-4 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filtered.map((bill) => {
                                    const total = Number(bill.summary?.totalAmount || bill.totalAmount || 0);
                                    const paid = Number(bill.paidAmount) || 0;
                                    const due = Math.max(0, total - paid);

                                    return (
                                        <tr key={bill._id} className="hover:bg-slate-50/60 transition group">
                                            <td className="px-6 py-4 font-black font-mono text-slate-900">{bill.docNumber}</td>
                                            <td className="px-6 py-4 text-slate-600 font-medium">
                                                {bill.docDate ? new Date(bill.docDate).toLocaleDateString('en-GB') : '-'}
                                            </td>
                                            <td className="px-6 py-4">
                                                <p className="font-bold text-slate-900">{bill.partyName}</p>
                                                {bill.partyGstin && <p className="text-[10px] font-mono text-slate-400">{bill.partyGstin}</p>}
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                                    bill.itcEligibility === 'Ineligible' ? 'bg-rose-50 text-rose-700 border border-rose-200' : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                                                }`}>
                                                    {bill.itcEligibility || 'Inputs'}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 font-mono font-black text-slate-900 text-sm">
                                                ₹{total.toLocaleString('en-IN')}
                                            </td>
                                            <td className="px-6 py-4">
                                                <p className="font-mono font-bold text-emerald-700">₹{paid.toLocaleString('en-IN')}</p>
                                                {due > 0 && <p className="text-[10px] font-mono font-bold text-rose-500">Due: ₹{due.toLocaleString('en-IN')}</p>}
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                                    bill.paymentStatus === 'Paid' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                                                    bill.paymentStatus === 'Partially Paid' ? 'bg-blue-50 text-blue-700 border border-blue-200' :
                                                    'bg-amber-50 text-amber-700 border border-amber-200'
                                                }`}>
                                                    {bill.paymentStatus || 'Unpaid'}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 text-right space-x-1">
                                                {bill.paymentStatus !== 'Paid' && (
                                                    <button
                                                        onClick={() => handleOpenPaymentModal(bill)}
                                                        title="Record Payment Out (Vendor Settlement)"
                                                        className="bg-rose-50 hover:bg-rose-600 hover:text-white text-rose-700 px-2.5 py-1.5 rounded-xl font-bold transition inline-flex items-center gap-1 text-[11px] border border-rose-200 mr-1"
                                                    >
                                                        <ArrowUpRight size={13} /> Payment Out
                                                    </button>
                                                )}
                                                <button 
                                                    onClick={() => onViewInvoice(bill)}
                                                    title="View Purchase Bill"
                                                    className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition inline-flex items-center"
                                                >
                                                    <Eye size={16} />
                                                </button>
                                                {onEditInvoice && (
                                                    <button 
                                                        onClick={() => onEditInvoice(bill)}
                                                        title="Edit Purchase Bill"
                                                        className="p-2 text-slate-400 hover:text-amber-600 hover:bg-amber-50 rounded-xl transition inline-flex items-center"
                                                    >
                                                        <Edit2 size={16} />
                                                    </button>
                                                )}
                                                <button 
                                                    onClick={() => onDeleteInvoice(bill._id)}
                                                    title="Delete Bill"
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

            {/* Direct Payment Out Modal */}
            {activePaymentBill && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <div>
                                <h3 className="font-black text-slate-900 text-sm">
                                    Record Payment Out (Vendor Settlement)
                                </h3>
                                <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                                    {activePaymentBill.docNumber} • {activePaymentBill.partyName}
                                </p>
                            </div>
                            <button onClick={() => setActivePaymentBill(null)} className="text-slate-400 hover:text-slate-600">
                                <X size={18} />
                            </button>
                        </div>

                        <form onSubmit={handleSubmitPayment} className="p-6 space-y-4 text-xs">
                            <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 flex items-center justify-between">
                                <div>
                                    <span className="text-[10px] font-bold text-slate-400 uppercase block">Bill Total</span>
                                    <span className="text-sm font-black font-mono text-slate-800">
                                        ₹{Number(activePaymentBill.summary?.totalAmount || activePaymentBill.totalAmount || 0).toLocaleString('en-IN')}
                                    </span>
                                </div>
                                <div>
                                    <span className="text-[10px] font-bold text-slate-400 uppercase block">Already Paid</span>
                                    <span className="text-sm font-black font-mono text-emerald-600">
                                        ₹{Number(activePaymentBill.paidAmount || 0).toLocaleString('en-IN')}
                                    </span>
                                </div>
                                <div>
                                    <span className="text-[10px] font-bold text-slate-400 uppercase block">Payable Due</span>
                                    <span className="text-sm font-black font-mono text-rose-600">
                                        ₹{Math.max(0, Number(activePaymentBill.summary?.totalAmount || activePaymentBill.totalAmount || 0) - Number(activePaymentBill.paidAmount || 0)).toLocaleString('en-IN')}
                                    </span>
                                </div>
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                                    Payment Amount to Vendor (₹) <span className="text-rose-500">*</span>
                                </label>
                                <input 
                                    type="number" 
                                    step="0.01" 
                                    value={paymentAmount}
                                    onChange={(e) => setPaymentAmount(e.target.value)}
                                    placeholder="Enter amount paid"
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
                                        <option value="Bank Transfer">Bank Transfer (NEFT/RTGS)</option>
                                        <option value="UPI">UPI / QR Code</option>
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
                                    placeholder="e.g. UTR9981273910"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-mono text-xs text-slate-800 focus:outline-none"
                                />
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                                    Settlement Notes
                                </label>
                                <input 
                                    type="text" 
                                    value={paymentNotes}
                                    onChange={(e) => setPaymentNotes(e.target.value)}
                                    placeholder="Optional notes or vendor reference"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 text-xs text-slate-800 focus:outline-none"
                                />
                            </div>

                            <div className="pt-2 flex justify-end gap-2">
                                <button
                                    type="button"
                                    onClick={() => setActivePaymentBill(null)}
                                    className="px-4 py-2 rounded-xl text-slate-600 font-bold hover:bg-slate-100 transition"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={isSubmitting}
                                    className="bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white px-6 py-2 rounded-xl font-bold transition shadow-md shadow-rose-100 flex items-center gap-1.5"
                                >
                                    <Check size={14} /> {isSubmitting ? 'Recording...' : 'Record Payment Out'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default PurchaseBillsTab;
