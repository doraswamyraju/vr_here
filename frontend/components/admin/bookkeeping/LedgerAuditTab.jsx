import React, { useState } from 'react';
import { FileText, Eye, Check, X, Search, RefreshCw, Filter } from 'lucide-react';

const LedgerAuditTab = ({
    transactions = [],
    selectedClient,
    onVerifyTransaction,
    onViewInvoice,
    onRefresh
}) => {
    const [search, setSearch] = useState('');
    const [typeFilter, setTypeFilter] = useState('All');
    const [statusFilter, setStatusFilter] = useState('All');

    const filtered = transactions.filter(t => {
        const matchesSearch = (t.docNumber || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.partyName || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.partyGstin || '').toLowerCase().includes(search.toLowerCase());
        const matchesType = typeFilter === 'All' || t.transactionType === typeFilter;
        const matchesStatus = statusFilter === 'All' || t.status === statusFilter;
        return matchesSearch && matchesType && matchesStatus;
    });

    return (
        <div className="space-y-6">
            {/* Search and Filters */}
            <div className="bg-white p-4 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row gap-3 items-center justify-between">
                <div className="relative w-full md:w-80">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
                    <input 
                        type="text" 
                        value={search} 
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search voucher, party, GSTIN..."
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs font-medium text-slate-900 focus:outline-none focus:border-indigo-500"
                    />
                </div>

                <div className="flex items-center gap-2 flex-wrap w-full md:w-auto justify-end">
                    <div className="flex bg-slate-100 p-1 rounded-2xl text-xs font-bold">
                        {['All', 'Sales', 'Purchase', 'Income', 'Expense'].map(tab => (
                            <button
                                key={tab}
                                onClick={() => setTypeFilter(tab)}
                                className={`px-2.5 py-1.5 rounded-xl transition text-[11px] ${
                                    typeFilter === tab ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-600 hover:text-slate-900'
                                }`}
                            >
                                {tab}
                            </button>
                        ))}
                    </div>

                    <div className="flex bg-slate-100 p-1 rounded-2xl text-xs font-bold">
                        {['All', 'Verified', 'Recorded', 'Flagged'].map(tab => (
                            <button
                                key={tab}
                                onClick={() => setStatusFilter(tab)}
                                className={`px-2.5 py-1.5 rounded-xl transition text-[11px] ${
                                    statusFilter === tab ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-600 hover:text-slate-900'
                                }`}
                            >
                                {tab}
                            </button>
                        ))}
                    </div>

                    <button 
                        onClick={onRefresh}
                        className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-xl transition"
                        title="Refresh"
                    >
                        <RefreshCw size={15} />
                    </button>
                </div>
            </div>

            {/* Vouchers Table */}
            <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden">
                <div className="p-5 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                    <h4 className="font-black text-slate-900 text-sm">Transactional Vouchers & Line Verification</h4>
                    <span className="text-[10px] font-black uppercase tracking-wider bg-indigo-50 text-indigo-700 px-3 py-1 rounded-full border border-indigo-200">
                        {filtered.length} Vouchers Listed
                    </span>
                </div>

                {filtered.length === 0 ? (
                    <div className="text-center py-20 text-slate-400">
                        <FileText size={48} className="mx-auto mb-3 opacity-30" />
                        <p className="font-bold">No bookkeeping records match your filters</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="bg-slate-50/75 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-100">
                                    <th className="px-6 py-4">Type</th>
                                    <th className="px-6 py-4">Doc No</th>
                                    <th className="px-6 py-4">Date</th>
                                    <th className="px-6 py-4">Party Name</th>
                                    <th className="px-6 py-4">Taxable</th>
                                    <th className="px-6 py-4">Total Amount</th>
                                    <th className="px-6 py-4">Status</th>
                                    <th className="px-6 py-4 text-right">Audit Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filtered.map((tx) => (
                                    <tr key={tx._id} className="hover:bg-slate-50/60 transition group">
                                        <td className="px-6 py-4">
                                            <span className={`px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wide ${
                                                tx.transactionType === 'Sales' ? 'bg-emerald-50 text-emerald-700' :
                                                tx.transactionType === 'Purchase' ? 'bg-indigo-50 text-indigo-700' : 'bg-rose-50 text-rose-700'
                                            }`}>
                                                {tx.transactionType}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 font-black font-mono text-slate-900">{tx.docNumber}</td>
                                        <td className="px-6 py-4 text-slate-600 font-medium">
                                            {tx.docDate ? new Date(tx.docDate).toLocaleDateString('en-GB') : '-'}
                                        </td>
                                        <td className="px-6 py-4">
                                            <p className="font-bold text-slate-900">{tx.partyName}</p>
                                            {tx.partyGstin && <p className="text-[10px] font-mono text-slate-400">{tx.partyGstin}</p>}
                                        </td>
                                        <td className="px-6 py-4 font-mono font-bold text-slate-700">
                                            ₹{(tx.summary?.totalTaxableValue || 0).toLocaleString('en-IN')}
                                        </td>
                                        <td className="px-6 py-4 font-mono font-black text-slate-900 text-sm">
                                            ₹{(tx.summary?.totalAmount || 0).toLocaleString('en-IN')}
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                                tx.status === 'Verified' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                                                tx.status === 'Flagged' ? 'bg-rose-50 text-rose-700 border border-rose-200' :
                                                'bg-amber-50 text-amber-700 border border-amber-200'
                                            }`}>
                                                {tx.status || 'Recorded'}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-right space-x-1">
                                            <button 
                                                onClick={() => onViewInvoice(tx)}
                                                title="View Voucher Sheet"
                                                className="p-1.5 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition"
                                            >
                                                <Eye size={15} />
                                            </button>
                                            {tx.status !== 'Verified' && (
                                                <button 
                                                    onClick={() => onVerifyTransaction(tx._id, 'Verified')}
                                                    title="Mark Verified"
                                                    className="bg-emerald-50 text-emerald-700 hover:bg-emerald-600 hover:text-white px-2.5 py-1 rounded-lg transition text-xs font-bold inline-flex items-center gap-1"
                                                >
                                                    <Check size={12} /> Verify
                                                </button>
                                            )}
                                            {tx.status !== 'Flagged' && (
                                                <button 
                                                    onClick={() => onVerifyTransaction(tx._id, 'Flagged')}
                                                    title="Flag Discrepancy"
                                                    className="bg-rose-50 text-rose-700 hover:bg-rose-600 hover:text-white px-2.5 py-1 rounded-lg transition text-xs font-bold inline-flex items-center gap-1"
                                                >
                                                    <X size={12} /> Flag
                                                </button>
                                            )}
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

export default LedgerAuditTab;
