import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Landmark, Search, Check, RefreshCw, Filter, 
    ArrowDownRight, ArrowUpRight, Tag, AlertCircle, CheckCircle2 
} from 'lucide-react';

const AdminBankReconTab = ({
    token,
    selectedClient,
    transactions = [],
    selectedMonth,
    onRefreshLedger
}) => {
    const [statements, setStatements] = useState([]);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState('');
    const [typeFilter, setTypeFilter] = useState('ALL');
    const [statusFilter, setStatusFilter] = useState('ALL');
    const [taggingTx, setTaggingTx] = useState(null);
    const [tagVoucherId, setTagVoucherId] = useState('');
    const [tagCategory, setTagCategory] = useState('Sales Collection');
    const [savingTag, setSavingTag] = useState(false);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    const fetchStatements = async () => {
        if (!selectedClient) return;
        setLoading(true);
        try {
            const { data } = await axios.get(`/api/accounting/bank-statements/admin/${selectedClient._id}`, config);
            setStatements(data || []);
        } catch (error) {
            console.error('Failed to load bank statements:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStatements();
    }, [selectedClient, selectedMonth]);

    const allBankTransactions = statements.flatMap(s => (s.transactions || []).map(tx => ({ ...tx, statementId: s._id, bankName: s.bankName, accountNumber: s.accountNumber })));

    const filtered = allBankTransactions.filter(tx => {
        const matchesSearch = (tx.description || '').toLowerCase().includes(search.toLowerCase()) ||
            (tx.referenceNumber || '').toLowerCase().includes(search.toLowerCase()) ||
            (tx.category || '').toLowerCase().includes(search.toLowerCase());
        const matchesType = typeFilter === 'ALL' || tx.type === typeFilter;
        const matchesStatus = statusFilter === 'ALL' || tx.reconciliationStatus === statusFilter;
        return matchesSearch && matchesType && matchesStatus;
    });

    const totalMoneyIn = allBankTransactions.filter(t => t.type === 'CREDIT').reduce((acc, t) => acc + (Number(t.amount) || 0), 0);
    const totalMoneyOut = allBankTransactions.filter(t => t.type === 'DEBIT').reduce((acc, t) => acc + (Number(t.amount) || 0), 0);
    const taggedCount = allBankTransactions.filter(t => t.reconciliationStatus === 'TAGGED').length;
    const reconPercentage = allBankTransactions.length > 0 ? Math.round((taggedCount / allBankTransactions.length) * 100) : 100;

    // Handle Tagging
    const handleSaveTag = async () => {
        if (!taggingTx) return;
        setSavingTag(true);
        try {
            await axios.post(`/api/accounting/bank-statements/${taggingTx.statementId}/tag`, {
                transactionId: taggingTx._id,
                category: tagCategory,
                taggedVoucherId: tagVoucherId || null,
                notes: `Tagged by Admin auditor for ${tagCategory}`
            }, config);

            // If tagged against open invoice/bill, update its payment status
            if (tagVoucherId) {
                try {
                    await axios.post(`/api/accounting/transactions/${tagVoucherId}/payment`, {
                        amountPaid: taggingTx.amount,
                        paymentMode: 'Bank Transfer',
                        paymentDate: taggingTx.date || new Date(),
                        referenceNumber: taggingTx.referenceNumber || 'BANK-RECON',
                        notes: `Auto-settled via Bank Recon audit: ${taggingTx.description}`
                    }, config);
                } catch (e) {}
            }

            setTaggingTx(null);
            setTagVoucherId('');
            await fetchStatements();
            if (onRefreshLedger) onRefreshLedger();
            alert('Bank entry tagged and reconciled successfully!');
        } catch (error) {
            alert('Failed to tag entry: ' + (error.response?.data?.message || error.message));
        } finally {
            setSavingTag(false);
        }
    };

    return (
        <div className="space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Total Money In (Credits)</p>
                        <h3 className="text-2xl font-black text-teal-600 mt-1">₹{totalMoneyIn.toLocaleString('en-IN')}</h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">Bank Inward Receipts</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-teal-50 text-teal-600 flex items-center justify-center font-black">
                        <ArrowDownRight size={22} />
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Total Money Out (Debits)</p>
                        <h3 className="text-2xl font-black text-rose-600 mt-1">₹{totalMoneyOut.toLocaleString('en-IN')}</h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">Bank Disbursements</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-rose-50 text-rose-600 flex items-center justify-center font-black">
                        <ArrowUpRight size={22} />
                    </div>
                </div>

                <div className="bg-white p-5 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between">
                    <div>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Reconciliation Health</p>
                        <h3 className={`text-2xl font-black mt-1 ${reconPercentage === 100 ? 'text-emerald-600' : 'text-amber-600'}`}>
                            {reconPercentage}% Reconciled
                        </h3>
                        <p className="text-[11px] text-slate-500 font-semibold mt-0.5">{taggedCount} of {allBankTransactions.length} Tagged</p>
                    </div>
                    <div className="w-12 h-12 rounded-2xl bg-slate-100 text-slate-700 flex items-center justify-center font-black">
                        <Landmark size={22} />
                    </div>
                </div>
            </div>

            {/* Filter and Search */}
            <div className="bg-white p-4 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row gap-3 items-center justify-between">
                <div className="relative w-full md:w-80">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
                    <input 
                        type="text" 
                        value={search} 
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search narration, ref no, category..."
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs font-medium text-slate-900 focus:outline-none focus:border-indigo-500"
                    />
                </div>

                <div className="flex items-center gap-2 flex-wrap w-full md:w-auto justify-end">
                    <div className="flex bg-slate-100 p-1 rounded-2xl text-xs font-bold">
                        {['ALL', 'CREDIT', 'DEBIT'].map(tab => (
                            <button
                                key={tab}
                                onClick={() => setTypeFilter(tab)}
                                className={`px-2.5 py-1.5 rounded-xl transition text-[11px] ${
                                    typeFilter === tab ? 'bg-white text-indigo-600 shadow-sm font-black' : 'text-slate-600 hover:text-slate-900'
                                }`}
                            >
                                {tab}
                            </button>
                        ))}
                    </div>

                    <div className="flex bg-slate-100 p-1 rounded-2xl text-xs font-bold">
                        {['ALL', 'UNTAGGED', 'TAGGED'].map(tab => (
                            <button
                                key={tab}
                                onClick={() => setStatusFilter(tab)}
                                className={`px-2.5 py-1.5 rounded-xl transition text-[11px] ${
                                    statusFilter === tab ? 'bg-white text-indigo-600 shadow-sm font-black' : 'text-slate-600 hover:text-slate-900'
                                }`}
                            >
                                {tab}
                            </button>
                        ))}
                    </div>

                    <button 
                        onClick={fetchStatements}
                        className="p-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-2xl transition"
                    >
                        <RefreshCw size={15} />
                    </button>
                </div>
            </div>

            {/* Table */}
            <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden">
                <div className="p-5 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                    <h4 className="font-black text-slate-900 text-sm">Client Bank Transactions Ledger</h4>
                    <span className="text-[10px] font-black uppercase tracking-wider bg-indigo-50 text-indigo-700 px-3 py-1 rounded-full border border-indigo-200">
                        {filtered.length} Transactions Listed
                    </span>
                </div>

                {loading ? (
                    <div className="flex justify-center py-20">
                        <div className="w-10 h-10 border-4 border-slate-200 border-t-indigo-600 rounded-full animate-spin"></div>
                    </div>
                ) : filtered.length === 0 ? (
                    <div className="text-center py-20 text-slate-400">
                        <Landmark size={48} className="mx-auto mb-3 opacity-30" />
                        <p className="font-bold text-sm">No bank transactions recorded for this client</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="bg-slate-50/75 text-slate-400 font-black text-[10px] uppercase tracking-wider border-b border-slate-100">
                                    <th className="px-6 py-4">Date</th>
                                    <th className="px-6 py-4">Narration / Description</th>
                                    <th className="px-6 py-4">Type</th>
                                    <th className="px-6 py-4">Amount (₹)</th>
                                    <th className="px-6 py-4">Reconciliation Status</th>
                                    <th className="px-6 py-4 text-right">Audit Tagging</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {filtered.map((tx) => (
                                    <tr key={tx._id} className="hover:bg-slate-50/60 transition group">
                                        <td className="px-6 py-4 font-mono text-slate-600">
                                            {tx.date ? new Date(tx.date).toLocaleDateString('en-GB') : '-'}
                                        </td>
                                        <td className="px-6 py-4">
                                            <p className="font-bold text-slate-900 max-w-md truncate">{tx.description}</p>
                                            {tx.referenceNumber && (
                                                <p className="text-[10px] text-slate-400 font-mono">Ref: {tx.referenceNumber}</p>
                                            )}
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className={`px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wider ${
                                                tx.type === 'CREDIT' ? 'bg-teal-50 text-teal-700 border border-teal-200' : 'bg-rose-50 text-rose-700 border border-rose-200'
                                            }`}>
                                                {tx.type}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 font-mono font-black text-slate-900 text-sm">
                                            ₹{(Number(tx.amount) || 0).toLocaleString('en-IN')}
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                                tx.reconciliationStatus === 'TAGGED' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-amber-50 text-amber-700 border border-amber-200'
                                            }`}>
                                                {tx.reconciliationStatus || 'UNTAGGED'}
                                            </span>
                                            {tx.category && (
                                                <p className="text-[10px] text-indigo-600 font-bold mt-0.5">{tx.category}</p>
                                            )}
                                        </td>
                                        <td className="px-6 py-4 text-right">
                                            <button
                                                onClick={() => {
                                                    setTaggingTx(tx);
                                                    setTagCategory(tx.type === 'CREDIT' ? 'Sales Collection' : 'Vendor Payment');
                                                    setTagVoucherId('');
                                                }}
                                                className="bg-indigo-50 hover:bg-indigo-600 hover:text-white text-indigo-700 border border-indigo-200 px-3 py-1.5 rounded-xl font-bold text-xs transition flex items-center gap-1 ml-auto"
                                            >
                                                <Tag size={12} />
                                                <span>{tx.reconciliationStatus === 'TAGGED' ? 'Edit Tag' : 'Tag Entry'}</span>
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Tagging Modal */}
            {taggingTx && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <h3 className="font-black text-slate-900 text-sm">Reconcile & Tag Bank Transaction</h3>
                            <button onClick={() => setTaggingTx(null)} className="text-slate-400 hover:text-slate-600 font-bold">✕</button>
                        </div>

                        <div className="p-6 space-y-4 text-xs">
                            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200 space-y-1">
                                <p className="font-bold text-slate-900">{taggingTx.description}</p>
                                <div className="flex justify-between items-center text-[11px]">
                                    <span className="text-slate-500">{taggingTx.date ? new Date(taggingTx.date).toLocaleDateString('en-GB') : '-'}</span>
                                    <span className="font-mono font-black text-slate-900">₹{(Number(taggingTx.amount) || 0).toLocaleString('en-IN')}</span>
                                </div>
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Select Ledger Category *</label>
                                <select 
                                    value={tagCategory} 
                                    onChange={(e) => setTagCategory(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-bold text-slate-800"
                                >
                                    <option value="Sales Collection">Sales Collection (Inward Customer Payment)</option>
                                    <option value="Vendor Payment">Vendor Payment (Supplier Settlement)</option>
                                    <option value="Salary & Wages">Staff Salary & Wages</option>
                                    <option value="Rent & Utilities">Office Rent & Utilities</option>
                                    <option value="Bank Charges">Bank Service Charges & GST</option>
                                    <option value="Taxes Paid">Statutory Taxes / GST / TDS Paid</option>
                                    <option value="Director Withdrawal">Director Loan / Withdrawal</option>
                                    <option value="Capital Infusion">Share Capital / Partner Capital</option>
                                    <option value="Other Expenses">Other General Expenses</option>
                                </select>
                            </div>

                            {/* Option to link against open invoice */}
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">
                                    Match / Auto-Settle Open Voucher (Optional)
                                </label>
                                <select 
                                    value={tagVoucherId} 
                                    onChange={(e) => setTagVoucherId(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-medium text-slate-800"
                                >
                                    <option value="">-- No direct voucher link (Category only) --</option>
                                    {transactions.filter(t => t.paymentStatus !== 'Paid').map(v => (
                                        <option key={v._id} value={v._id}>
                                            {v.transactionType} | {v.docNumber} | {v.partyName} (Due: ₹{Math.max(0, (v.summary?.totalAmount || 0) - (v.paidAmount || 0)).toLocaleString('en-IN')})
                                        </option>
                                    ))}
                                </select>
                            </div>

                            <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
                                <button type="button" onClick={() => setTaggingTx(null)} className="px-4 py-2 rounded-xl text-slate-600 font-bold">Cancel</button>
                                <button 
                                    type="button" 
                                    disabled={savingTag}
                                    onClick={handleSaveTag} 
                                    className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2 rounded-xl font-black uppercase tracking-wider shadow-md"
                                >
                                    {savingTag ? 'Reconciling...' : 'Save & Reconcile'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AdminBankReconTab;
