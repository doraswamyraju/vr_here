import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    IndianRupee, TrendingUp, ArrowUpRight, Clock, 
    CheckCircle2, AlertCircle, RefreshCw, Send,
    FileText, X, Loader2, CreditCard, Building, ShieldCheck
} from 'lucide-react';

const PartnerEarningsView = ({ userInfo }) => {
    const [earningsData, setEarningsData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [activeSubTab, setActiveSubTab] = useState('ledger'); // 'ledger' | 'payouts'
    const [showPayoutModal, setShowPayoutModal] = useState(false);
    const [submittingPayout, setSubmittingPayout] = useState(false);
    const [payoutFeedback, setPayoutFeedback] = useState(null);

    const [payoutForm, setPayoutForm] = useState({
        amount: '',
        payoutMethod: 'UPI',
        upiId: userInfo?.upiId || '',
        bankDetails: {
            accountName: userInfo?.bankDetails?.accountName || userInfo?.name || '',
            accountNumber: userInfo?.bankDetails?.accountNumber || '',
            ifscCode: userInfo?.bankDetails?.ifscCode || '',
            bankName: userInfo?.bankDetails?.bankName || ''
        }
    });

    useEffect(() => {
        fetchEarnings();
    }, []);

    const fetchEarnings = async () => {
        setLoading(true);
        setError('');
        try {
            const config = {
                headers: { Authorization: `Bearer ${userInfo.token}` }
            };
            const { data } = await axios.get('/api/partner/earnings', config);
            setEarningsData(data);
            if (data.availableWithdrawBalance >= 500 && !payoutForm.amount) {
                setPayoutForm(prev => ({
                    ...prev,
                    amount: Math.floor(data.availableWithdrawBalance)
                }));
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to fetch earnings ledger');
        } finally {
            setLoading(false);
        }
    };

    const handlePayoutSubmit = async (e) => {
        e.preventDefault();
        setSubmittingPayout(true);
        setPayoutFeedback(null);

        const amt = Number(payoutForm.amount);
        if (amt < 500) {
            setPayoutFeedback({ type: 'error', message: 'Minimum withdrawal amount is ₹500.' });
            setSubmittingPayout(false);
            return;
        }

        if (amt > (earningsData?.availableWithdrawBalance || 0)) {
            setPayoutFeedback({ 
                type: 'error', 
                message: `Withdrawal amount cannot exceed available balance (₹${earningsData?.availableWithdrawBalance?.toLocaleString('en-IN')}).` 
            });
            setSubmittingPayout(false);
            return;
        }

        try {
            const config = {
                headers: { Authorization: `Bearer ${userInfo.token}` }
            };
            const payload = {
                amount: amt,
                payoutMethod: payoutForm.payoutMethod,
                upiId: payoutForm.payoutMethod === 'UPI' ? payoutForm.upiId : undefined,
                bankDetails: payoutForm.payoutMethod === 'Bank Transfer' ? payoutForm.bankDetails : undefined
            };

            const { data } = await axios.post('/api/partner/payout-request', payload, config);

            setPayoutFeedback({
                type: 'success',
                message: data.message || 'Payout request submitted successfully.'
            });

            // Refresh data
            fetchEarnings();

            setTimeout(() => {
                setShowPayoutModal(false);
                setPayoutFeedback(null);
                setActiveSubTab('payouts');
            }, 2500);
        } catch (err) {
            setPayoutFeedback({
                type: 'error',
                message: err.response?.data?.message || 'Failed to submit payout request.'
            });
        } finally {
            setSubmittingPayout(false);
        }
    };

    const formatCurrency = (amount) => {
        return new Intl.NumberFormat('en-IN', {
            style: 'currency',
            currency: 'INR',
            maximumFractionDigits: 0
        }).format(amount || 0);
    };

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center p-16">
                <div className="w-12 h-12 border-4 border-slate-200 border-t-red-600 rounded-full animate-spin mb-4"></div>
                <p className="text-slate-500 font-bold">Loading earnings & payout data...</p>
            </div>
        );
    }

    const {
        lifetimeRevenue = 0,
        totalCommissionEarned = 0,
        pendingOrdersCommission = 0,
        paidPayouts = 0,
        pendingPayouts = 0,
        availableWithdrawBalance = 0,
        orders = [],
        payouts = []
    } = earningsData || {};

    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Header Section */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Earnings & Commission Ledger</h1>
                    <p className="text-slate-500 text-sm mt-1">
                        Track verified commissions generated from your partner referrals and request instant payouts.
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <button 
                        onClick={fetchEarnings}
                        className="p-2.5 rounded-xl bg-white border border-slate-200 text-slate-500 hover:text-red-600 hover:border-red-100 transition-all shadow-sm"
                        title="Refresh Earnings"
                    >
                        <RefreshCw className="w-5 h-5" />
                    </button>
                    <button
                        onClick={() => { setShowPayoutModal(true); setPayoutFeedback(null); }}
                        disabled={availableWithdrawBalance < 500}
                        className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-black shadow-lg transition-all ${
                            availableWithdrawBalance >= 500
                                ? 'bg-red-600 text-white hover:bg-red-700 shadow-red-200'
                                : 'bg-slate-200 text-slate-400 cursor-not-allowed shadow-none'
                        }`}
                    >
                        <Send className="w-4 h-4" />
                        Request Payout
                    </button>
                </div>
            </div>

            {/* KPI Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Total Referred Revenue</span>
                        <div className="w-10 h-10 rounded-xl bg-slate-50 text-slate-700 flex items-center justify-center">
                            <TrendingUp className="w-5 h-5" />
                        </div>
                    </div>
                    <h3 className="text-2xl font-black text-slate-900">{formatCurrency(lifetimeRevenue)}</h3>
                    <p className="text-[11px] text-slate-400 font-semibold mt-1">Gross client order volume</p>
                </div>

                <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Total Commission Earned</span>
                        <div className="w-10 h-10 rounded-xl bg-green-50 text-green-600 flex items-center justify-center">
                            <CheckCircle2 className="w-5 h-5" />
                        </div>
                    </div>
                    <h3 className="text-2xl font-black text-green-600">{formatCurrency(totalCommissionEarned)}</h3>
                    <p className="text-[11px] text-slate-400 font-semibold mt-1">From settled & paid orders</p>
                </div>

                <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Pending Orders Comm.</span>
                        <div className="w-10 h-10 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center">
                            <Clock className="w-5 h-5" />
                        </div>
                    </div>
                    <h3 className="text-2xl font-black text-amber-600">{formatCurrency(pendingOrdersCommission)}</h3>
                    <p className="text-[11px] text-slate-400 font-semibold mt-1">Awaiting client payment</p>
                </div>

                <div className="bg-slate-950 text-white rounded-3xl p-6 shadow-xl relative overflow-hidden">
                    <div className="absolute right-0 top-0 translate-x-4 -translate-y-4 w-28 h-28 bg-red-600/20 rounded-full blur-2xl"></div>
                    <div className="flex items-center justify-between mb-3 relative z-10">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Available For Payout</span>
                        <div className="w-10 h-10 rounded-xl bg-red-500/20 text-red-400 flex items-center justify-center">
                            <IndianRupee className="w-5 h-5" />
                        </div>
                    </div>
                    <h3 className="text-2xl font-black text-white relative z-10">{formatCurrency(availableWithdrawBalance)}</h3>
                    <p className="text-[11px] text-slate-400 font-semibold mt-1 relative z-10">
                        {availableWithdrawBalance >= 500 ? 'Ready for withdrawal' : 'Min ₹500 required'}
                    </p>
                </div>
            </div>

            {/* Sub-tab Navigation */}
            <div className="flex items-center gap-3 border-b border-slate-200">
                <button
                    onClick={() => setActiveSubTab('ledger')}
                    className={`pb-4 px-3 text-sm font-black transition-all border-b-2 ${
                        activeSubTab === 'ledger'
                            ? 'border-red-600 text-slate-900'
                            : 'border-transparent text-slate-400 hover:text-slate-700'
                    }`}
                >
                    Commission Ledger ({orders.length})
                </button>
                <button
                    onClick={() => setActiveSubTab('payouts')}
                    className={`pb-4 px-3 text-sm font-black transition-all border-b-2 ${
                        activeSubTab === 'payouts'
                            ? 'border-red-600 text-slate-900'
                            : 'border-transparent text-slate-400 hover:text-slate-700'
                    }`}
                >
                    Payout History ({payouts.length})
                </button>
            </div>

            {/* Sub-tab Content: Commission Ledger */}
            {activeSubTab === 'ledger' && (
                <div className="bg-white rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                    <div className="p-6 md:p-8 border-b border-slate-100 bg-slate-50/30">
                        <h3 className="text-lg font-black text-slate-900 tracking-tight">Referral Commissions Breakdown</h3>
                        <p className="text-slate-500 text-xs mt-0.5">Showing orders tied to your partner code or booked by you.</p>
                    </div>

                    {orders.length > 0 ? (
                        <div className="overflow-x-auto">
                            <table className="w-full text-left border-collapse">
                                <thead>
                                    <tr className="bg-slate-50/50">
                                        <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Date & Order ID</th>
                                        <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Customer</th>
                                        <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Service</th>
                                        <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Order Value</th>
                                        <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Your Commission</th>
                                        <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Payment Status</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100 text-xs">
                                    {orders.map((o) => (
                                        <tr key={o._id} className="hover:bg-slate-50/50 transition-colors">
                                            <td className="px-8 py-5">
                                                <div className="font-bold text-slate-900">#{o._id.slice(-6).toUpperCase()}</div>
                                                <div className="text-[10px] text-slate-400 font-semibold mt-0.5">
                                                    {o.createdAt ? new Date(o.createdAt).toLocaleDateString('en-IN', { dateStyle: 'medium' }) : 'N/A'}
                                                </div>
                                            </td>
                                            <td className="px-8 py-5">
                                                <div className="font-black text-slate-900">{o.clientName || o.user?.name || 'Client'}</div>
                                                <div className="text-[10px] text-slate-400 font-semibold">{o.email || o.user?.email || ''}</div>
                                            </td>
                                            <td className="px-8 py-5 font-bold text-slate-700">
                                                {o.serviceName}
                                            </td>
                                            <td className="px-8 py-5 text-right font-bold text-slate-900">
                                                {formatCurrency(o.price)}
                                            </td>
                                            <td className="px-8 py-5 text-right font-black text-green-600">
                                                {formatCurrency(o.partnerCommissionAmount)}
                                            </td>
                                            <td className="px-8 py-5 text-center">
                                                <span className={`inline-block px-2.5 py-1 rounded-full text-[9px] font-black uppercase tracking-wider ${
                                                    o.paymentStatus === 'Paid'
                                                        ? 'bg-green-50 text-green-600 border border-green-200'
                                                        : 'bg-amber-50 text-amber-600 border border-amber-200'
                                                }`}>
                                                    {o.paymentStatus || 'Pending'}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="p-16 text-center">
                            <div className="w-14 h-14 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3">
                                <FileText className="w-7 h-7 text-slate-300" />
                            </div>
                            <h4 className="font-bold text-slate-800 text-base">No Commission Entries Yet</h4>
                            <p className="text-slate-400 text-xs max-w-sm mx-auto mt-1">
                                When clients book services with your referral code or master orders, commission entries will appear here.
                            </p>
                        </div>
                    )}
                </div>
            )}

            {/* Sub-tab Content: Payout History */}
            {activeSubTab === 'payouts' && (
                <div className="bg-white rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                    <div className="p-6 md:p-8 border-b border-slate-100 bg-slate-50/30 flex items-center justify-between">
                        <div>
                            <h3 className="text-lg font-black text-slate-900 tracking-tight">Withdrawal Requests</h3>
                            <p className="text-slate-500 text-xs mt-0.5">Status of your commission payout settlements.</p>
                        </div>
                        <div className="text-right">
                            <span className="text-xs font-bold text-slate-400">Total Settled: </span>
                            <span className="text-xs font-black text-green-600">{formatCurrency(paidPayouts)}</span>
                        </div>
                    </div>

                    {payouts.length > 0 ? (
                        <div className="overflow-x-auto">
                            <table className="w-full text-left border-collapse">
                                <thead>
                                    <tr className="bg-slate-50/50">
                                        <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Request Date</th>
                                        <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Amount</th>
                                        <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Method & Destination</th>
                                        <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Status</th>
                                        <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Reference / UTR</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100 text-xs">
                                    {payouts.map((p) => (
                                        <tr key={p._id} className="hover:bg-slate-50/50 transition-colors">
                                            <td className="px-8 py-5">
                                                <div className="font-bold text-slate-900">
                                                    {new Date(p.createdAt).toLocaleDateString('en-IN', { dateStyle: 'medium' })}
                                                </div>
                                                <div className="text-[10px] text-slate-400 font-semibold mt-0.5">
                                                    #{p._id.slice(-6).toUpperCase()}
                                                </div>
                                            </td>
                                            <td className="px-8 py-5 text-right font-black text-slate-900 text-sm">
                                                {formatCurrency(p.amount)}
                                            </td>
                                            <td className="px-8 py-5">
                                                <div className="font-bold text-slate-800">{p.payoutMethod}</div>
                                                <div className="text-[10px] text-slate-500 font-semibold">
                                                    {p.payoutMethod === 'UPI' ? p.upiId : `${p.bankDetails?.bankName || 'Bank'} (A/C: ${p.bankDetails?.accountNumber || 'N/A'})`}
                                                </div>
                                            </td>
                                            <td className="px-8 py-5 text-center">
                                                <span className={`inline-block px-3 py-1 rounded-full text-[9px] font-black uppercase tracking-wider ${
                                                    p.status === 'Paid' 
                                                        ? 'bg-green-50 text-green-700 border border-green-200'
                                                        : p.status === 'Rejected'
                                                        ? 'bg-red-50 text-red-700 border border-red-200'
                                                        : 'bg-amber-50 text-amber-700 border border-amber-200'
                                                }`}>
                                                    {p.status}
                                                </span>
                                            </td>
                                            <td className="px-8 py-5">
                                                <div className="font-bold text-slate-700">{p.transactionRef || 'Processing...'}</div>
                                                {p.adminNotes && (
                                                    <div className="text-[10px] text-slate-400 mt-0.5 italic">{p.adminNotes}</div>
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="p-16 text-center">
                            <div className="w-14 h-14 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3">
                                <Send className="w-7 h-7 text-slate-300" />
                            </div>
                            <h4 className="font-bold text-slate-800 text-base">No Payout Requests Yet</h4>
                            <p className="text-slate-400 text-xs max-w-sm mx-auto mt-1">
                                When your available balance reaches ₹500, you can request commission withdrawals here.
                            </p>
                        </div>
                    )}
                </div>
            )}

            {/* Request Payout Modal */}
            {showPayoutModal && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-fade-in">
                    <div className="bg-white rounded-[32px] shadow-2xl max-w-lg w-full overflow-hidden border border-slate-100 animate-in zoom-in-95 duration-200">
                        <div className="bg-slate-950 p-6 sm:p-8 flex items-center justify-between border-b-4 border-red-600">
                            <div>
                                <h3 className="text-white text-lg font-black tracking-tight">Request Commission Payout</h3>
                                <p className="text-slate-400 text-xs font-semibold mt-1">
                                    Available balance: {formatCurrency(availableWithdrawBalance)}
                                </p>
                            </div>
                            <button 
                                onClick={() => setShowPayoutModal(false)}
                                className="p-2 text-slate-400 hover:text-white transition rounded-xl"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        <form onSubmit={handlePayoutSubmit} className="p-6 sm:p-8 space-y-4">
                            {payoutFeedback && (
                                <div className={`p-4 rounded-2xl text-xs font-bold flex items-start gap-3 ${
                                    payoutFeedback.type === 'success' 
                                        ? 'bg-green-50 text-green-700 border border-green-200' 
                                        : 'bg-red-50 text-red-600 border border-red-200'
                                }`}>
                                    {payoutFeedback.type === 'success' ? (
                                        <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-green-600" />
                                    ) : (
                                        <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
                                    )}
                                    <span>{payoutFeedback.message}</span>
                                </div>
                            )}

                            {/* Withdrawal Amount */}
                            <div className="space-y-1.5">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                    Withdrawal Amount (₹) * (Min ₹500)
                                </label>
                                <input 
                                    type="number" 
                                    required
                                    min="500"
                                    max={availableWithdrawBalance}
                                    value={payoutForm.amount}
                                    onChange={(e) => setPayoutForm({ ...payoutForm, amount: e.target.value })}
                                    className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
                                />
                            </div>

                            {/* Payout Method */}
                            <div className="space-y-1.5">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                    Payout Method *
                                </label>
                                <div className="grid grid-cols-2 gap-3">
                                    <button
                                        type="button"
                                        onClick={() => setPayoutForm({ ...payoutForm, payoutMethod: 'UPI' })}
                                        className={`py-3 px-4 rounded-xl border text-xs font-black flex items-center justify-center gap-2 transition ${
                                            payoutForm.payoutMethod === 'UPI'
                                                ? 'bg-red-50 border-red-500 text-red-600 shadow-sm'
                                                : 'bg-slate-50 border-slate-200 text-slate-600 hover:bg-slate-100'
                                        }`}
                                    >
                                        <CreditCard className="w-4 h-4" /> UPI Transfer
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setPayoutForm({ ...payoutForm, payoutMethod: 'Bank Transfer' })}
                                        className={`py-3 px-4 rounded-xl border text-xs font-black flex items-center justify-center gap-2 transition ${
                                            payoutForm.payoutMethod === 'Bank Transfer'
                                                ? 'bg-red-50 border-red-500 text-red-600 shadow-sm'
                                                : 'bg-slate-50 border-slate-200 text-slate-600 hover:bg-slate-100'
                                        }`}
                                    >
                                        <Building className="w-4 h-4" /> Bank Account
                                    </button>
                                </div>
                            </div>

                            {/* UPI ID Field */}
                            {payoutForm.payoutMethod === 'UPI' && (
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                        UPI ID / VPA *
                                    </label>
                                    <input 
                                        type="text" 
                                        required
                                        placeholder="username@okhdfcbank"
                                        value={payoutForm.upiId}
                                        onChange={(e) => setPayoutForm({ ...payoutForm, upiId: e.target.value })}
                                        className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
                                    />
                                </div>
                            )}

                            {/* Bank Details Fields */}
                            {payoutForm.payoutMethod === 'Bank Transfer' && (
                                <div className="space-y-3 p-4 bg-slate-50 rounded-2xl border border-slate-100">
                                    <div className="space-y-1">
                                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Account Beneficiary Name</label>
                                        <input 
                                            type="text" 
                                            required
                                            value={payoutForm.bankDetails.accountName}
                                            onChange={(e) => setPayoutForm({
                                                ...payoutForm,
                                                bankDetails: { ...payoutForm.bankDetails, accountName: e.target.value }
                                            })}
                                            className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 text-xs font-bold outline-none focus:border-red-500"
                                        />
                                    </div>
                                    <div className="grid grid-cols-2 gap-3">
                                        <div className="space-y-1">
                                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Bank Name</label>
                                            <input 
                                                type="text" 
                                                required
                                                placeholder="HDFC Bank"
                                                value={payoutForm.bankDetails.bankName}
                                                onChange={(e) => setPayoutForm({
                                                    ...payoutForm,
                                                    bankDetails: { ...payoutForm.bankDetails, bankName: e.target.value }
                                                })}
                                                className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 text-xs font-bold outline-none focus:border-red-500"
                                            />
                                        </div>
                                        <div className="space-y-1">
                                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">IFSC Code</label>
                                            <input 
                                                type="text" 
                                                required
                                                placeholder="HDFC0001234"
                                                value={payoutForm.bankDetails.ifscCode}
                                                onChange={(e) => setPayoutForm({
                                                    ...payoutForm,
                                                    bankDetails: { ...payoutForm.bankDetails, ifscCode: e.target.value.toUpperCase() }
                                                })}
                                                className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 text-xs font-bold uppercase outline-none focus:border-red-500"
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-1">
                                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Account Number</label>
                                        <input 
                                            type="text" 
                                            required
                                            value={payoutForm.bankDetails.accountNumber}
                                            onChange={(e) => setPayoutForm({
                                                ...payoutForm,
                                                bankDetails: { ...payoutForm.bankDetails, accountNumber: e.target.value }
                                            })}
                                            className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 text-xs font-bold outline-none focus:border-red-500"
                                        />
                                    </div>
                                </div>
                            )}

                            <div className="flex items-center gap-3 pt-4 border-t border-slate-100">
                                <button
                                    type="button"
                                    onClick={() => setShowPayoutModal(false)}
                                    className="flex-1 py-3 rounded-xl bg-slate-100 text-slate-600 font-bold hover:bg-slate-200 text-xs transition"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={submittingPayout}
                                    className="flex-1 py-3 rounded-xl bg-slate-900 text-white font-bold hover:bg-slate-800 shadow-xl shadow-slate-200 text-xs transition flex items-center justify-center gap-2"
                                >
                                    {submittingPayout ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Confirm Request'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default PartnerEarningsView;
