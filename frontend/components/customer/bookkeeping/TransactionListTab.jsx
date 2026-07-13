import React from 'react';
import { Search, Calendar, RefreshCw, FileText, Eye, Trash2 } from 'lucide-react';

const TransactionListTab = ({ 
    transactions, loading, filterType, setFilterType,
    searchQuery, setSearchQuery, onRefresh,
    totalSales, totalPurchases, totalExpenses, totalIncome,
    onViewInvoice, onDeleteTransaction
}) => {
    // Totals card block
    return (
        <div className="space-y-6">
            {/* Summary metrics cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-white border border-slate-200 p-5 rounded-2xl shadow-sm flex flex-col justify-center">
                    <span className="text-slate-400 text-[10px] uppercase font-black tracking-wider">Total Sales</span>
                    <span className="text-xl font-bold text-emerald-600 mt-1">₹{totalSales.toLocaleString()}</span>
                </div>
                <div className="bg-white border border-slate-200 p-5 rounded-2xl shadow-sm flex flex-col justify-center">
                    <span className="text-slate-400 text-[10px] uppercase font-black tracking-wider">Total Purchases</span>
                    <span className="text-xl font-bold text-blue-600 mt-1">₹{totalPurchases.toLocaleString()}</span>
                </div>
                <div className="bg-white border border-slate-200 p-5 rounded-2xl shadow-sm flex flex-col justify-center">
                    <span className="text-slate-400 text-[10px] uppercase font-black tracking-wider">Other Income</span>
                    <span className="text-xl font-bold text-teal-600 mt-1">₹{totalIncome.toLocaleString()}</span>
                </div>
                <div className="bg-white border border-slate-200 p-5 rounded-2xl shadow-sm flex flex-col justify-center">
                    <span className="text-slate-400 text-[10px] uppercase font-black tracking-wider">Expenses</span>
                    <span className="text-xl font-bold text-rose-600 mt-1">₹{totalExpenses.toLocaleString()}</span>
                </div>
            </div>

            {/* Table Search & Filters bar */}
            <div className="flex justify-between items-center gap-4 bg-white p-3 rounded-2xl border border-slate-200 flex-wrap">
                <div className="relative flex-1 max-w-md">
                    <Search className="absolute left-3.5 top-2.5 text-slate-400" size={16} />
                    <input 
                        type="text" 
                        placeholder="Search Transactions..."
                        value={searchQuery}
                        onChange={e => setSearchQuery(e.target.value)}
                        className="w-full bg-slate-50 border border-slate-300 rounded-xl pl-10 pr-4 py-2 text-xs focus:outline-none focus:bg-white"
                    />
                </div>
                <div className="flex gap-2">
                    <select 
                        value={filterType} 
                        onChange={e => setFilterType(e.target.value)}
                        className="bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs font-semibold focus:outline-none"
                    >
                        <option value="All">All Vouchers</option>
                        <option value="Sales">Sales Vouchers</option>
                        <option value="Purchase">Purchase Bills</option>
                        <option value="Income">Other Income</option>
                        <option value="Expense">Expenses</option>
                    </select>
                    <button onClick={onRefresh} className="flex items-center gap-1 border border-slate-300 px-3 py-2 rounded-xl bg-white hover:bg-slate-50 text-xs">
                        <RefreshCw size={14} /> Refresh
                    </button>
                </div>
            </div>

            {/* Ledger list */}
            <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
                {loading ? (
                    <div className="flex justify-center py-20">
                        <div className="w-8 h-8 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                    </div>
                ) : transactions.length === 0 ? (
                    <div className="text-center py-20 text-slate-300">
                        <FileText size={48} className="mx-auto mb-3 opacity-30" />
                        <p className="font-bold text-sm text-slate-500">No transactions recorded yet</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="bg-slate-50/80 text-slate-500 font-bold border-b border-slate-200">
                                    <th className="px-6 py-4">Date</th>
                                    <th className="px-6 py-4">Voucher No</th>
                                    <th className="px-6 py-4">Party / Details</th>
                                    <th className="px-6 py-4">Type</th>
                                    <th className="px-6 py-4">Amount</th>
                                    <th className="px-6 py-4 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {transactions.map(tx => (
                                    <tr key={tx._id} className="hover:bg-slate-50/50 transition">
                                        <td className="px-6 py-4 text-slate-600">{new Date(tx.docDate).toLocaleDateString()}</td>
                                        <td className="px-6 py-4 font-bold text-slate-800">{tx.docNumber}</td>
                                        <td className="px-6 py-4 text-slate-700 font-medium">{tx.partyName}</td>
                                        <td className="px-6 py-4">
                                            <span className={`px-2.5 py-0.5 rounded-full text-[9px] font-bold ${
                                                tx.transactionType === 'Sales' ? 'bg-emerald-50 text-emerald-600' :
                                                tx.transactionType === 'Purchase' ? 'bg-blue-50 text-blue-600' :
                                                tx.transactionType === 'Income' ? 'bg-indigo-50 text-indigo-600' : 'bg-rose-50 text-rose-600'
                                            }`}>
                                                {tx.transactionType}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 font-bold text-slate-900">₹{tx.summary.totalAmount.toLocaleString()}</td>
                                        <td className="px-6 py-4 text-right space-x-1">
                                            <button 
                                                onClick={() => onViewInvoice(tx)}
                                                className="text-indigo-600 hover:bg-indigo-50 p-2 rounded-lg transition"
                                                title="View / Print Tax Invoice"
                                            >
                                                <Eye size={14} />
                                            </button>
                                            <button 
                                                onClick={() => onDeleteTransaction(tx._id)}
                                                className="text-rose-500 hover:bg-rose-50 p-2 rounded-lg transition"
                                            >
                                                <Trash2 size={14} />
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

export default TransactionListTab;
