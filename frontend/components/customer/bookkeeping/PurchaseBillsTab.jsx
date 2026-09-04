import React, { useState } from 'react';
import { Plus, Search, Eye, Edit2, Trash2, FileText, UploadCloud, ShieldCheck, AlertCircle } from 'lucide-react';

const PurchaseBillsTab = ({
    transactions = [],
    onAddNew,
    onEditInvoice,
    onViewInvoice,
    onDeleteInvoice
}) => {
    const [search, setSearch] = useState('');
    const [itcFilter, setItcFilter] = useState('All');

    const purchaseBills = transactions.filter(t => t.transactionType === 'Purchase');

    const filtered = purchaseBills.filter(t => {
        const matchesSearch = (t.docNumber || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.partyName || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.partyGstin || '').toLowerCase().includes(search.toLowerCase());
        const matchesItc = itcFilter === 'All' || t.itcEligibility === itcFilter;
        return matchesSearch && matchesItc;
    });

    const totalPurchases = purchaseBills.reduce((acc, curr) => acc + (curr.summary?.totalAmount || 0), 0);
    const eligibleItc = purchaseBills
        .filter(t => t.itcEligibility !== 'Ineligible')
        .reduce((acc, curr) => acc + ((curr.summary?.totalCgst || 0) + (curr.summary?.totalSgst || 0) + (curr.summary?.totalIgst || 0)), 0);

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
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Eligible Input Tax Credit (ITC)</p>
                        <h3 className="text-2xl font-black text-emerald-600 mt-1">₹{eligibleItc.toLocaleString('en-IN')}</h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">Claimable in GSTR-3B Table 4</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-emerald-50 text-emerald-600 flex items-center justify-center font-black">
                        <ShieldCheck size={22} />
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Vendor Records</p>
                        <h3 className="text-2xl font-black text-slate-800 mt-1">
                            {new Set(purchaseBills.map(p => p.partyName)).size} Active Vendors
                        </h3>
                        <p className="text-[11px] text-slate-400 font-semibold mt-0.5">ITC Verified & Logged</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-slate-100 text-slate-600 flex items-center justify-center font-black">
                        👥
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

                <div className="flex items-center gap-2 w-full md:w-auto justify-between md:justify-end">
                    <div className="flex bg-slate-100 p-1 rounded-2xl text-xs font-bold">
                        {['All', 'Inputs', 'Input Services', 'Capital Goods', 'Ineligible'].map(tab => (
                            <button
                                key={tab}
                                onClick={() => setItcFilter(tab)}
                                className={`px-2.5 py-1.5 rounded-xl transition text-[11px] ${
                                    itcFilter === tab ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-600 hover:text-slate-900'
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

            {/* Table */}
            <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden">
                {filtered.length === 0 ? (
                    <div className="text-center py-20 space-y-3">
                        <FileText size={48} className="mx-auto text-slate-300" />
                        <p className="text-slate-500 font-bold text-sm">No purchase bills recorded</p>
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
                                    <th className="px-6 py-4">Taxable (₹)</th>
                                    <th className="px-6 py-4">Total Amount (₹)</th>
                                    <th className="px-6 py-4">Status</th>
                                    <th className="px-6 py-4 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filtered.map((bill) => (
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
                                        <td className="px-6 py-4 font-mono font-bold text-slate-700">
                                            ₹{(bill.summary?.totalTaxableValue || 0).toLocaleString('en-IN')}
                                        </td>
                                        <td className="px-6 py-4 font-mono font-black text-slate-900 text-sm">
                                            ₹{(bill.summary?.totalAmount || 0).toLocaleString('en-IN')}
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className="px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider bg-slate-100 text-slate-700 border border-slate-200">
                                                {bill.status || 'Recorded'}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-right space-x-1">
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
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};

export default PurchaseBillsTab;
