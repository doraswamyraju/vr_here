import React, { useState, useMemo } from 'react';
import axios from 'axios';
import { 
    TrendingUp, TrendingDown, Clock, CheckCircle2, AlertCircle, ArrowUpRight, 
    ArrowDownLeft, FileText, ShoppingCart, Landmark, Users, Calendar, Plus, 
    ArrowRight, DollarSign, Wallet, ShieldCheck, PieChart, Sparkles, Check, X
} from 'lucide-react';

const BookkeepingDashboardTab = ({
    token,
    transactions = [],
    bankStatements = [],
    company,
    selectedMonth = 'ALL',
    onNavigateTab,
    onRefreshData
}) => {
    // Payment In / Out Modal State
    const [activePaymentVoucher, setActivePaymentVoucher] = useState(null); // invoice or bill object
    const [paymentAmount, setPaymentAmount] = useState('');
    const [paymentDate, setPaymentDate] = useState(new Date().toISOString().split('T')[0]);
    const [paymentMode, setPaymentMode] = useState('UPI');
    const [referenceNo, setReferenceNo] = useState('');
    const [paymentNotes, setPaymentNotes] = useState('');
    const [isSubmittingPayment, setIsSubmittingPayment] = useState(false);

    const config = { headers: { Authorization: `Bearer ${token}` } };

    // Filter transactions for the selected month
    const filteredTxs = useMemo(() => {
        if (selectedMonth === 'ALL') return transactions;
        return transactions.filter(t => {
            if (!t.docDate) return false;
            const d = new Date(t.docDate);
            const mStr = d.toLocaleDateString('en-GB', { month: 'long', year: 'numeric' });
            return mStr.toLowerCase() === selectedMonth.toLowerCase();
        });
    }, [transactions, selectedMonth]);

    // Categorized transactions
    const salesInvoices = useMemo(() => filteredTxs.filter(t => t.transactionType === 'Sales'), [filteredTxs]);
    const purchaseBills = useMemo(() => filteredTxs.filter(t => t.transactionType === 'Purchase'), [filteredTxs]);
    const directIncomes = useMemo(() => filteredTxs.filter(t => t.transactionType === 'Income'), [filteredTxs]);
    const directExpenses = useMemo(() => filteredTxs.filter(t => t.transactionType === 'Expense'), [filteredTxs]);

    // 1. Receivables Metrics (Sales)
    const totalSalesAmount = useMemo(() => salesInvoices.reduce((acc, s) => acc + (s.summary?.totalAmount || s.totalAmount || 0), 0), [salesInvoices]);
    const totalSalesCollected = useMemo(() => salesInvoices.reduce((acc, s) => acc + (Number(s.paidAmount) || 0), 0), [salesInvoices]);
    const totalSalesPending = Math.max(0, totalSalesAmount - totalSalesCollected);
    const pendingSalesCount = useMemo(() => salesInvoices.filter(s => s.paymentStatus !== 'Paid').length, [salesInvoices]);

    // 2. Payables Metrics (Purchases)
    const totalPurchasesAmount = useMemo(() => purchaseBills.reduce((acc, p) => acc + (p.summary?.totalAmount || p.totalAmount || 0), 0), [purchaseBills]);
    const totalPurchasesPaid = useMemo(() => purchaseBills.reduce((acc, p) => acc + (Number(p.paidAmount) || 0), 0), [purchaseBills]);
    const totalPurchasesPending = Math.max(0, totalPurchasesAmount - totalPurchasesPaid);
    const pendingPurchasesCount = useMemo(() => purchaseBills.filter(p => p.paymentStatus !== 'Paid').length, [purchaseBills]);

    // 3. GST Metrics
    const outputGst = useMemo(() => {
        return salesInvoices.reduce((acc, s) => acc + (s.summary?.totalCgst || 0) + (s.summary?.totalSgst || 0) + (s.summary?.totalIgst || 0), 0);
    }, [salesInvoices]);

    const inputItc = useMemo(() => {
        return purchaseBills
            .filter(p => p.itcEligibility !== 'Ineligible')
            .reduce((acc, p) => acc + (p.summary?.totalCgst || 0) + (p.summary?.totalSgst || 0) + (p.summary?.totalIgst || 0), 0);
    }, [purchaseBills]);

    const netGstPayable = Math.max(0, outputGst - inputItc);

    // 4. Banking Health Metrics
    const allBankTransactions = useMemo(() => {
        return bankStatements.flatMap(s => s.transactions || []);
    }, [bankStatements]);

    const bankMoneyIn = useMemo(() => {
        return allBankTransactions
            .filter(tx => tx.type === 'CREDIT')
            .reduce((acc, tx) => acc + (Number(tx.amount) || 0), 0);
    }, [allBankTransactions]);

    const bankMoneyOut = useMemo(() => {
        return allBankTransactions
            .filter(tx => tx.type === 'DEBIT')
            .reduce((acc, tx) => acc + (Number(tx.amount) || 0), 0);
    }, [allBankTransactions]);

    const bankTaggedCount = useMemo(() => allBankTransactions.filter(tx => tx.reconciliationStatus === 'TAGGED').length, [allBankTransactions]);
    const totalBankTxCount = allBankTransactions.length;

    // 5. Net Business Margin
    const totalRevenue = totalSalesAmount + directIncomes.reduce((acc, i) => acc + (i.summary?.totalAmount || i.totalAmount || 0), 0);
    const totalCosts = totalPurchasesAmount + directExpenses.reduce((acc, e) => acc + (e.summary?.totalAmount || e.totalAmount || 0), 0);
    const netProfitMargin = totalRevenue - totalCosts;

    // Open Payment In/Out Modal
    const handleOpenPaymentModal = (voucher) => {
        const total = Number(voucher.summary?.totalAmount || voucher.totalAmount || 0);
        const alreadyPaid = Number(voucher.paidAmount) || 0;
        const due = Math.max(0, total - alreadyPaid);

        setActivePaymentVoucher(voucher);
        setPaymentAmount(due > 0 ? String(due) : String(total));
        setPaymentDate(new Date().toISOString().split('T')[0]);
        setPaymentMode(voucher.paymentMode || 'UPI');
        setReferenceNo(`REF${Math.floor(100000 + Math.random() * 900000)}`);
        setPaymentNotes('');
    };

    // Submit Payment In / Out
    const handleSubmitPayment = async (e) => {
        e.preventDefault();
        if (!activePaymentVoucher) return;

        const numAmount = parseFloat(paymentAmount);
        if (isNaN(numAmount) || numAmount <= 0) {
            alert('Please enter a valid payment amount.');
            return;
        }

        setIsSubmittingPayment(true);
        try {
            await axios.post(`/api/accounting/transactions/${activePaymentVoucher._id}/payment`, {
                amount: numAmount,
                paymentDate,
                paymentMode,
                referenceNo,
                notes: paymentNotes
            }, config);

            alert(`Payment of ₹${numAmount.toLocaleString('en-IN')} recorded successfully!`);
            setActivePaymentVoucher(null);
            if (onRefreshData) onRefreshData();
        } catch (error) {
            alert('Failed to record payment: ' + (error.response?.data?.message || error.message));
        } finally {
            setIsSubmittingPayment(false);
        }
    };

    return (
        <div className="space-y-8 animate-in fade-in duration-300">
            {/* Header Executive Title */}
            <div className="bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 rounded-3xl p-6 sm:p-8 text-white shadow-2xl relative overflow-hidden">
                <div className="absolute right-0 top-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
                <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                    <div>
                        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 text-indigo-200 text-xs font-bold mb-3 backdrop-blur-md">
                            <Sparkles size={13} /> Real-Time Accounting & AaaS Command Center
                        </div>
                        <h2 className="text-2xl sm:text-3xl font-black tracking-tight">
                            {company?.businessName || company?.tradeName || 'Business Ledger & Bookkeeping'}
                        </h2>
                        <p className="text-slate-300 text-xs sm:text-sm mt-1 max-w-2xl font-medium">
                            Comprehensive financial visibility for <strong className="text-white">{selectedMonth}</strong>. Track receivables, vendor payables, GST liability, and bank reconciliation.
                        </p>
                    </div>

                    <div className="flex flex-wrap gap-2 shrink-0">
                        <button
                            onClick={() => onNavigateTab && onNavigateTab('sales')}
                            className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2.5 rounded-2xl font-black text-xs uppercase tracking-wider transition shadow-lg shadow-indigo-600/30 flex items-center gap-1.5"
                        >
                            <Plus size={14} /> New Invoice
                        </button>
                        <button
                            onClick={() => onNavigateTab && onNavigateTab('statements')}
                            className="bg-white/10 hover:bg-white/20 text-white px-4 py-2.5 rounded-2xl font-black text-xs uppercase tracking-wider transition backdrop-blur-md flex items-center gap-1.5"
                        >
                            <Landmark size={14} /> Import Statement
                        </button>
                    </div>
                </div>
            </div>

            {/* Core KPI Cards Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
                {/* 1. Receivables / Sales Card */}
                <div className="bg-white rounded-3xl p-5 border border-slate-100 shadow-xl shadow-slate-200/50 relative overflow-hidden group hover:border-indigo-200 transition">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Total Receivables</span>
                        <span className="w-8 h-8 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center font-bold text-xs">
                            <ArrowDownLeft size={16} />
                        </span>
                    </div>
                    <div className="space-y-1">
                        <h3 className="text-2xl font-black text-slate-900 font-mono tracking-tight">
                            ₹{totalSalesAmount.toLocaleString('en-IN')}
                        </h3>
                        <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-50">
                            <span className="text-slate-500 font-bold">Pending Collection:</span>
                            <span className="font-mono font-black text-rose-600">₹{totalSalesPending.toLocaleString('en-IN')}</span>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-slate-400">
                            <span>Collected: ₹{totalSalesCollected.toLocaleString('en-IN')}</span>
                            <span className="font-bold text-amber-600">{pendingSalesCount} Unsettled</span>
                        </div>
                    </div>
                </div>

                {/* 2. Payables / Purchases Card */}
                <div className="bg-white rounded-3xl p-5 border border-slate-100 shadow-xl shadow-slate-200/50 relative overflow-hidden group hover:border-indigo-200 transition">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Vendor Payables</span>
                        <span className="w-8 h-8 rounded-xl bg-rose-50 text-rose-600 flex items-center justify-center font-bold text-xs">
                            <ArrowUpRight size={16} />
                        </span>
                    </div>
                    <div className="space-y-1">
                        <h3 className="text-2xl font-black text-slate-900 font-mono tracking-tight">
                            ₹{totalPurchasesAmount.toLocaleString('en-IN')}
                        </h3>
                        <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-50">
                            <span className="text-slate-500 font-bold">Pending Payment:</span>
                            <span className="font-mono font-black text-rose-600">₹{totalPurchasesPending.toLocaleString('en-IN')}</span>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-slate-400">
                            <span>Paid Out: ₹{totalPurchasesPaid.toLocaleString('en-IN')}</span>
                            <span className="font-bold text-amber-600">{pendingPurchasesCount} Bills Open</span>
                        </div>
                    </div>
                </div>

                {/* 3. Bank Health Card */}
                <div className="bg-white rounded-3xl p-5 border border-slate-100 shadow-xl shadow-slate-200/50 relative overflow-hidden group hover:border-indigo-200 transition">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Bank Statement Activity</span>
                        <span className="w-8 h-8 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center font-bold text-xs">
                            <Landmark size={16} />
                        </span>
                    </div>
                    <div className="space-y-1">
                        <div className="flex items-baseline gap-2">
                            <h3 className="text-2xl font-black text-slate-900 font-mono tracking-tight">
                                {totalBankTxCount}
                            </h3>
                            <span className="text-xs text-slate-500 font-bold">Txns</span>
                        </div>
                        <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-50 font-mono">
                            <span className="text-emerald-600 font-bold">+₹{bankMoneyIn.toLocaleString('en-IN')}</span>
                            <span className="text-rose-600 font-bold">-₹{bankMoneyOut.toLocaleString('en-IN')}</span>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-slate-400">
                            <span>Reconciliation Status</span>
                            <span className="font-bold text-indigo-600">{bankTaggedCount} / {totalBankTxCount} Tagged</span>
                        </div>
                    </div>
                </div>

                {/* 4. GST Computation Card */}
                <div className="bg-white rounded-3xl p-5 border border-slate-100 shadow-xl shadow-slate-200/50 relative overflow-hidden group hover:border-indigo-200 transition">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Net GST Liability (3B)</span>
                        <span className="w-8 h-8 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center font-bold text-xs">
                            <ShieldCheck size={16} />
                        </span>
                    </div>
                    <div className="space-y-1">
                        <h3 className="text-2xl font-black text-slate-900 font-mono tracking-tight">
                            ₹{netGstPayable.toLocaleString('en-IN')}
                        </h3>
                        <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-50 text-slate-500">
                            <span>Output GST: <strong className="text-slate-800">₹{outputGst.toLocaleString('en-IN')}</strong></span>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-slate-400">
                            <span>Input ITC Credit:</span>
                            <span className="font-bold text-emerald-600">₹{inputItc.toLocaleString('en-IN')}</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Quick Navigation Short-cuts to Modules */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                {[
                    { id: 'sales', label: 'Sales Invoices', count: `${salesInvoices.length} Invoices`, icon: FileText, color: 'text-indigo-600 bg-indigo-50 border-indigo-100' },
                    { id: 'purchases', label: 'Purchase Bills', count: `${purchaseBills.length} Bills`, icon: ShoppingCart, color: 'text-rose-600 bg-rose-50 border-rose-100' },
                    { id: 'income_expenses', label: 'Income & Expenses', count: `${directIncomes.length + directExpenses.length} Records`, icon: Wallet, color: 'text-amber-600 bg-amber-50 border-amber-100' },
                    { id: 'statements', label: 'Bank Statements', count: `${bankStatements.length} Accounts`, icon: Landmark, color: 'text-emerald-600 bg-emerald-50 border-emerald-100' },
                    { id: 'parties', label: 'Parties Directory', count: 'Client / Vendor Master', icon: Users, color: 'text-cyan-600 bg-cyan-50 border-cyan-100' },
                    { id: 'reports', label: 'Statutory Reports', count: 'P&L, GST, Balance Sheet', icon: PieChart, color: 'text-purple-600 bg-purple-50 border-purple-100' }
                ].map(nav => (
                    <button
                        key={nav.id}
                        onClick={() => onNavigateTab && onNavigateTab(nav.id)}
                        className="bg-white p-4 rounded-2xl border border-slate-100 shadow-sm hover:shadow-md hover:border-slate-300 transition text-left group flex flex-col justify-between"
                    >
                        <div className={`w-8 h-8 rounded-xl ${nav.color} border flex items-center justify-center mb-2 group-hover:scale-110 transition shrink-0`}>
                            <nav.icon size={16} />
                        </div>
                        <div>
                            <h4 className="font-black text-slate-900 text-xs group-hover:text-indigo-600 transition">{nav.label}</h4>
                            <p className="text-[10px] text-slate-400 font-bold mt-0.5">{nav.count}</p>
                        </div>
                    </button>
                ))}
            </div>

            {/* Action Tables Grid: Pending Invoices vs Pending Vendor Bills */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* 1. Pending Sales Invoices Table */}
                <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden flex flex-col">
                    <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
                        <div className="flex items-center gap-2">
                            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                            <h3 className="font-black text-slate-900 text-sm">Pending Sales Invoices (Payment In)</h3>
                        </div>
                        <button
                            onClick={() => onNavigateTab && onNavigateTab('sales')}
                            className="text-indigo-600 hover:text-indigo-800 font-bold text-xs inline-flex items-center gap-1"
                        >
                            View All <ArrowRight size={13} />
                        </button>
                    </div>

                    <div className="divide-y divide-slate-100 overflow-x-auto flex-1">
                        {salesInvoices.filter(s => s.paymentStatus !== 'Paid').length === 0 ? (
                            <div className="p-10 text-center text-slate-400 text-xs font-medium">
                                <CheckCircle2 size={32} className="mx-auto mb-2 text-emerald-500 opacity-60" />
                                All sales invoices are completely settled for this period!
                            </div>
                        ) : (
                            salesInvoices.filter(s => s.paymentStatus !== 'Paid').slice(0, 5).map(inv => {
                                const total = Number(inv.summary?.totalAmount || inv.totalAmount || 0);
                                const paid = Number(inv.paidAmount) || 0;
                                const due = Math.max(0, total - paid);

                                return (
                                    <div key={inv._id} className="p-4 flex items-center justify-between gap-3 hover:bg-slate-50/75 transition">
                                        <div className="min-w-0">
                                            <div className="flex items-center gap-2">
                                                <h4 className="font-black text-slate-900 text-xs truncate">{inv.partyName}</h4>
                                                <span className="font-mono text-[10px] bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded font-bold">
                                                    {inv.docNumber}
                                                </span>
                                            </div>
                                            <p className="text-[11px] text-slate-400 mt-0.5">
                                                Date: {inv.docDate ? new Date(inv.docDate).toLocaleDateString('en-GB') : '-'} • Total: ₹{total.toLocaleString('en-IN')}
                                            </p>
                                        </div>

                                        <div className="flex items-center gap-3 shrink-0">
                                            <div className="text-right">
                                                <span className="block font-mono font-black text-rose-600 text-xs">
                                                    ₹{due.toLocaleString('en-IN')}
                                                </span>
                                                <span className="text-[9px] font-bold text-slate-400 uppercase">Due Balance</span>
                                            </div>
                                            <button
                                                onClick={() => handleOpenPaymentModal(inv)}
                                                className="bg-emerald-600 hover:bg-emerald-700 text-white px-3 py-1.5 rounded-xl font-black text-[11px] transition shadow-sm shadow-emerald-200 inline-flex items-center gap-1"
                                            >
                                                <ArrowDownLeft size={12} /> Payment In
                                            </button>
                                        </div>
                                    </div>
                                );
                            })
                        )}
                    </div>
                </div>

                {/* 2. Pending Purchase Bills Table */}
                <div className="bg-white rounded-3xl border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden flex flex-col">
                    <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
                        <div className="flex items-center gap-2">
                            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />
                            <h3 className="font-black text-slate-900 text-sm">Pending Purchase Bills (Payment Out)</h3>
                        </div>
                        <button
                            onClick={() => onNavigateTab && onNavigateTab('purchases')}
                            className="text-indigo-600 hover:text-indigo-800 font-bold text-xs inline-flex items-center gap-1"
                        >
                            View All <ArrowRight size={13} />
                        </button>
                    </div>

                    <div className="divide-y divide-slate-100 overflow-x-auto flex-1">
                        {purchaseBills.filter(p => p.paymentStatus !== 'Paid').length === 0 ? (
                            <div className="p-10 text-center text-slate-400 text-xs font-medium">
                                <CheckCircle2 size={32} className="mx-auto mb-2 text-emerald-500 opacity-60" />
                                No pending vendor purchase bills to pay!
                            </div>
                        ) : (
                            purchaseBills.filter(p => p.paymentStatus !== 'Paid').slice(0, 5).map(bill => {
                                const total = Number(bill.summary?.totalAmount || bill.totalAmount || 0);
                                const paid = Number(bill.paidAmount) || 0;
                                const due = Math.max(0, total - paid);

                                return (
                                    <div key={bill._id} className="p-4 flex items-center justify-between gap-3 hover:bg-slate-50/75 transition">
                                        <div className="min-w-0">
                                            <div className="flex items-center gap-2">
                                                <h4 className="font-black text-slate-900 text-xs truncate">{bill.partyName}</h4>
                                                <span className="font-mono text-[10px] bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded font-bold">
                                                    {bill.docNumber}
                                                </span>
                                            </div>
                                            <p className="text-[11px] text-slate-400 mt-0.5">
                                                Date: {bill.docDate ? new Date(bill.docDate).toLocaleDateString('en-GB') : '-'} • Total: ₹{total.toLocaleString('en-IN')}
                                            </p>
                                        </div>

                                        <div className="flex items-center gap-3 shrink-0">
                                            <div className="text-right">
                                                <span className="block font-mono font-black text-rose-600 text-xs">
                                                    ₹{due.toLocaleString('en-IN')}
                                                </span>
                                                <span className="text-[9px] font-bold text-slate-400 uppercase">Payable Due</span>
                                            </div>
                                            <button
                                                onClick={() => handleOpenPaymentModal(bill)}
                                                className="bg-rose-600 hover:bg-rose-700 text-white px-3 py-1.5 rounded-xl font-black text-[11px] transition shadow-sm shadow-rose-200 inline-flex items-center gap-1"
                                            >
                                                <ArrowUpRight size={12} /> Payment Out
                                            </button>
                                        </div>
                                    </div>
                                );
                            })
                        )}
                    </div>
                </div>
            </div>

            {/* Direct Payment In / Payment Out Modal */}
            {activePaymentVoucher && (
                <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <div>
                                <h3 className="font-black text-slate-900 text-sm">
                                    Record {activePaymentVoucher.transactionType === 'Sales' ? 'Payment In (Collection)' : 'Payment Out (Settlement)'}
                                </h3>
                                <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                                    {activePaymentVoucher.docNumber} • {activePaymentVoucher.partyName}
                                </p>
                            </div>
                            <button onClick={() => setActivePaymentVoucher(null)} className="text-slate-400 hover:text-slate-600">
                                <X size={18} />
                            </button>
                        </div>

                        <form onSubmit={handleSubmitPayment} className="p-6 space-y-4 text-xs">
                            {/* Summary Card */}
                            <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 flex items-center justify-between">
                                <div>
                                    <span className="text-[10px] font-bold text-slate-400 uppercase block">Total Document Value</span>
                                    <span className="text-sm font-black font-mono text-slate-800">
                                        ₹{Number(activePaymentVoucher.summary?.totalAmount || activePaymentVoucher.totalAmount || 0).toLocaleString('en-IN')}
                                    </span>
                                </div>
                                <div>
                                    <span className="text-[10px] font-bold text-slate-400 uppercase block">Already Settled</span>
                                    <span className="text-sm font-black font-mono text-emerald-600">
                                        ₹{Number(activePaymentVoucher.paidAmount || 0).toLocaleString('en-IN')}
                                    </span>
                                </div>
                                <div>
                                    <span className="text-[10px] font-bold text-slate-400 uppercase block">Pending Due</span>
                                    <span className="text-sm font-black font-mono text-rose-600">
                                        ₹{Math.max(0, Number(activePaymentVoucher.summary?.totalAmount || activePaymentVoucher.totalAmount || 0) - Number(activePaymentVoucher.paidAmount || 0)).toLocaleString('en-IN')}
                                    </span>
                                </div>
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                                    Payment Amount (₹) <span className="text-rose-500">*</span>
                                </label>
                                <input 
                                    type="number" 
                                    step="0.01" 
                                    value={paymentAmount}
                                    onChange={(e) => setPaymentAmount(e.target.value)}
                                    placeholder="Enter received / paid amount"
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
                                    placeholder="e.g. UPI3829104812"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-2.5 font-mono text-xs text-slate-800 focus:outline-none"
                                />
                            </div>

                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                                    Payment Notes
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
                                    onClick={() => setActivePaymentVoucher(null)}
                                    className="px-4 py-2 rounded-xl text-slate-600 font-bold hover:bg-slate-100 transition"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={isSubmittingPayment}
                                    className="bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white px-6 py-2 rounded-xl font-bold transition shadow-md shadow-indigo-100 flex items-center gap-1.5"
                                >
                                    <Check size={14} /> {isSubmittingPayment ? 'Recording...' : 'Confirm Payment'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default BookkeepingDashboardTab;
