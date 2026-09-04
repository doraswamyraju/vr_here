import React, { useState } from 'react';
import { Plus, Search, Eye, Trash2, FileText, ArrowUpRight, ArrowDownRight, Tag } from 'lucide-react';

const IncomeExpensesTab = ({
    transactions = [],
    onAddNewIncome,
    onAddNewExpense,
    onViewInvoice,
    onDeleteInvoice
}) => {
    const [search, setSearch] = useState('');
    const [typeFilter, setTypeFilter] = useState('All');

    const vouchers = transactions.filter(t => t.transactionType === 'Income' || t.transactionType === 'Expense');

    const filtered = vouchers.filter(t => {
        const matchesSearch = (t.docNumber || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.partyName || '').toLowerCase().includes(search.toLowerCase()) ||
            (t.notes || '').toLowerCase().includes(search.toLowerCase());
        const matchesType = typeFilter === 'All' || t.transactionType === typeFilter;
        return matchesSearch && matchesType;
    });

    const totalIncome = vouchers
        .filter(t => t.transactionType === 'Income')
        .reduce((acc, curr) => acc + (curr.summary?.totalAmount || 0), 0);

    const totalExpense = vouchers
        .filter(t => t.transactionType === 'Expense')
        .reduce((acc, curr) => acc + (curr.summary?.totalAmount || 0), 0);

    return (
        <div className="space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Other Business Income</p>
                        <h3 className="text-2xl font-black text-teal-600 mt-1">₹{totalIncome.toLocaleString('en-IN')}</h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">Interest, Commission, Direct Receipts</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-teal-50 text-teal-600 flex items-center justify-center font-black">
                        <ArrowDownRight size={22} />
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Operational Expenses</p>
                        <h3 className="text-2xl font-black text-rose-600 mt-1">₹{totalExpense.toLocaleString('en-IN')}</h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">Rent, Salaries, Utilities, Office</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-rose-50 text-rose-600 flex items-center justify-center font-black">
                        <ArrowUpRight size={22} />
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Net Operating Flow</p>
                        <h3 className={`text-2xl font-black mt-1 ${totalIncome - totalExpense >= 0 ? 'text-emerald-600' : 'text-rose-600'}`}>
                            ₹{(totalIncome - totalExpense).toLocaleString('en-IN')}
                        </h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">Non-trading operational balance</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-slate-100 text-slate-700 flex items-center justify-center font-black">
                        ⚖️
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
                        placeholder="Search voucher no, account, notes..."
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs font-medium text-slate-900 focus:outline-none focus:border-indigo-500"
                    />
                </div>

                <div className="flex items-center gap-2 w-full md:w-auto justify-between md:justify-end">
                    <div className="flex bg-slate-100 p-1 rounded-2xl text-xs font-bold">
                        {['All', 'Income', 'Expense'].map(tab => (
                            <button
                                key={tab}
                                onClick={() => setTypeFilter(tab)}
                                className={`px-3 py-1.5 rounded-xl transition ${
                                    typeFilter === tab ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-600 hover:text-slate-900'
                                }`}
                            >
                                {tab}
                            </button>
                        ))}
                    </div>

                    <div className="flex gap-2">
                        <button 
                            onClick={onAddNewIncome}
                            className="bg-teal-600 hover:bg-teal-700 text-white px-4 py-2.5 rounded-2xl font-black text-xs uppercase tracking-wider flex items-center gap-1 transition shadow-sm"
                        >
                            <Plus size={15} /> + Income
                        </button>
                        <button 
                            onClick={onAddNewExpense}
                            className="bg-rose-600 hover:bg-rose-700 text-white px-4 py-2.5 rounded-2xl font-black text-xs uppercase tracking-wider flex items-center gap-1 transition shadow-sm"
                        >
                            <Plus size={15} /> + Expense
                        </button>
                    </div>
                </div>
            </div>

            {/* Table */}
            <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden">
                {filtered.length === 0 ? (
                    <div className="text-center py-20 space-y-3">
                        <FileText size={48} className="mx-auto text-slate-300" />
                        <p className="text-slate-500 font-bold text-sm">No income or expense vouchers recorded</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="bg-slate-50/75 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-100">
                                    <th className="px-6 py-4">Voucher No</th>
                                    <th className="px-6 py-4">Date</th>
                                    <th className="px-6 py-4">Type</th>
                                    <th className="px-6 py-4">Ledger / Description</th>
                                    <th className="px-6 py-4">Payment Mode</th>
                                    <th className="px-6 py-4">Amount (₹)</th>
                                    <th className="px-6 py-4 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filtered.map((vx) => (
                                    <tr key={vx._id} className="hover:bg-slate-50/60 transition group">
                                        <td className="px-6 py-4 font-black font-mono text-slate-900">{vx.docNumber}</td>
                                        <td className="px-6 py-4 text-slate-600 font-medium">
                                            {vx.docDate ? new Date(vx.docDate).toLocaleDateString('en-GB') : '-'}
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                                vx.transactionType === 'Income' ? 'bg-teal-50 text-teal-700 border border-teal-200' : 'bg-rose-50 text-rose-700 border border-rose-200'
                                            }`}>
                                                {vx.transactionType}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4">
                                            <p className="font-bold text-slate-900">{vx.partyName || vx.items?.[0]?.description || 'General'}</p>
                                            {vx.notes && <p className="text-[10px] text-slate-400 truncate max-w-xs">{vx.notes}</p>}
                                        </td>
                                        <td className="px-6 py-4 text-slate-600 font-medium">{vx.paymentMode || 'Cash'}</td>
                                        <td className="px-6 py-4 font-mono font-black text-slate-900 text-sm">
                                            ₹{(vx.summary?.totalAmount || 0).toLocaleString('en-IN')}
                                        </td>
                                        <td className="px-6 py-4 text-right space-x-1">
                                            <button 
                                                onClick={() => onViewInvoice(vx)}
                                                title="View Voucher"
                                                className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition inline-flex items-center"
                                            >
                                                <Eye size={16} />
                                            </button>
                                            <button 
                                                onClick={() => onDeleteInvoice(vx._id)}
                                                title="Delete Voucher"
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

export default IncomeExpensesTab;
