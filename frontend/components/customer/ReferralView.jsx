import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    Gift, Share2, Copy, Check, Users, IndianRupee, ArrowUpRight,
    Send, Plus, ShieldCheck, Sparkles, CheckCircle2, Clock, Phone,
    Building2, ExternalLink, RefreshCw, AlertCircle
} from 'lucide-react';

const ReferralView = ({ userInfo }) => {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [copied, setCopied] = useState(false);
    
    // Add lead modal state
    const [showAddModal, setShowAddModal] = useState(false);
    const [leadForm, setLeadForm] = useState({
        name: '',
        phone: '',
        email: '',
        interestedService: 'Private Limited Company Registration'
    });
    const [submittingLead, setSubmittingLead] = useState(false);
    const [leadMessage, setLeadMessage] = useState(null);

    // UPI Payout state
    const [showPayoutModal, setShowPayoutModal] = useState(false);
    const [upiId, setUpiId] = useState('');
    const [payoutAmount, setPayoutAmount] = useState('');
    const [submittingPayout, setSubmittingPayout] = useState(false);
    const [payoutMessage, setPayoutMessage] = useState(null);

    const fetchStats = async () => {
        try {
            setLoading(true);
            const { data } = await axios.get('/api/customer/referrals/stats', {
                headers: { Authorization: `Bearer ${userInfo.token}` }
            });
            setStats(data);
            if (data.savedUpiId) {
                setUpiId(data.savedUpiId);
            }
        } catch (err) {
            console.error('Error fetching referral stats:', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (userInfo?.token) {
            fetchStats();
        }
    }, [userInfo]);

    const handleCopyLink = () => {
        if (!stats?.referralLink) return;
        navigator.clipboard.writeText(stats.referralLink);
        setCopied(true);
        setTimeout(() => setCopied(false), 2500);
    };

    const handleWhatsAppShare = () => {
        if (!stats?.referralCode) return;
        const text = encodeURIComponent(
            `Hey! I use VR Here for company registrations, GST, and CA compliances. You can get your business registered or file taxes with their expert CA team.\n\nUse my referral link for priority onboarding: ${stats.referralLink} (or referral code: ${stats.referralCode})`
        );
        window.open(`https://api.whatsapp.com/send?text=${text}`, '_blank');
    };

    const handleAddLeadSubmit = async (e) => {
        e.preventDefault();
        setSubmittingLead(true);
        setLeadMessage(null);
        try {
            const { data } = await axios.post('/api/customer/referrals/lead', leadForm, {
                headers: { Authorization: `Bearer ${userInfo.token}` }
            });
            setLeadMessage({ type: 'success', text: data.message });
            setLeadForm({
                name: '',
                phone: '',
                email: '',
                interestedService: 'Private Limited Company Registration'
            });
            setTimeout(() => {
                setShowAddModal(false);
                setLeadMessage(null);
                fetchStats();
            }, 1800);
        } catch (err) {
            setLeadMessage({
                type: 'error',
                text: err.response?.data?.message || 'Failed to submit referral. Please check details.'
            });
        } finally {
            setSubmittingLead(false);
        }
    };

    const handlePayoutSubmit = async (e) => {
        e.preventDefault();
        setSubmittingPayout(true);
        setPayoutMessage(null);
        try {
            const { data } = await axios.post('/api/customer/referrals/payout-request', {
                upiId,
                amount: Number(payoutAmount) || stats.walletBalance
            }, {
                headers: { Authorization: `Bearer ${userInfo.token}` }
            });
            setPayoutMessage({ type: 'success', text: data.message });
            setTimeout(() => {
                setShowPayoutModal(false);
                setPayoutMessage(null);
                fetchStats();
            }, 2000);
        } catch (err) {
            setPayoutMessage({
                type: 'error',
                text: err.response?.data?.message || 'Failed to request payout.'
            });
        } finally {
            setSubmittingPayout(false);
        }
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-[400px]">
                <div className="flex flex-col items-center gap-3">
                    <RefreshCw className="animate-spin text-red-600" size={32} />
                    <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">Loading Refer & Earn Hub...</p>
                </div>
            </div>
        );
    }

    const referralCode = stats?.referralCode || `VR-${(userInfo?.phone || '').slice(-6)}`;
    const referralLink = stats?.referralLink || `https://vrhere.in/ref?code=${referralCode}`;
    const walletBalance = stats?.walletBalance || 0;
    const referralsList = stats?.referrals || [];

    return (
        <div className="pb-28 lg:pb-12 animate-in fade-in slide-in-from-bottom-3 duration-500 space-y-8">
            
            {/* 1. HERO BANNER */}
            <div className="bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 rounded-3xl p-6 sm:p-8 text-white relative overflow-hidden shadow-xl border border-slate-800">
                <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-red-600/20 via-rose-500/10 to-amber-500/20 rounded-full blur-3xl pointer-events-none"></div>
                <div className="relative z-10 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
                    <div className="max-w-xl space-y-3">
                        <div className="inline-flex items-center gap-2 px-3 py-1 bg-gradient-to-r from-red-600/30 to-amber-500/20 border border-red-500/40 rounded-full text-[11px] font-black tracking-wider uppercase text-amber-300">
                            <Sparkles size={13} className="text-amber-400" />
                            <span>Refer & Earn ₹500 Flat</span>
                        </div>
                        <h1 className="text-2xl sm:text-3xl lg:text-4xl font-black tracking-tight leading-tight">
                            Earn <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-amber-300">₹500 Cash</span> for Every Business Referral
                        </h1>
                        <p className="text-slate-300 text-xs sm:text-sm font-medium leading-relaxed">
                            Introduce friends, clients, or founders to VR Here. When they complete their first registration or tax filing, you receive ₹500 in your VR Wallet instantly!
                        </p>
                    </div>

                    {/* Quick CTA Actions */}
                    <div className="flex flex-wrap sm:flex-nowrap items-center gap-3">
                        <button
                            onClick={() => setShowAddModal(true)}
                            className="w-full sm:w-auto px-5 py-3.5 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 text-white rounded-2xl text-xs font-black uppercase tracking-wider shadow-lg shadow-red-600/30 flex items-center justify-center gap-2 transition-all"
                        >
                            <Plus size={16} />
                            <span>Refer a Contact</span>
                        </button>
                        <button
                            onClick={handleWhatsAppShare}
                            className="w-full sm:w-auto px-5 py-3.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-2xl text-xs font-black uppercase tracking-wider shadow-lg shadow-emerald-600/30 flex items-center justify-center gap-2 transition-all"
                        >
                            <Share2 size={16} />
                            <span>Share on WhatsApp</span>
                        </button>
                    </div>
                </div>
            </div>

            {/* 2. 4-KPI STAT CARDS */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-2xs">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Total Invited</span>
                        <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center">
                            <Users size={16} />
                        </div>
                    </div>
                    <h3 className="text-2xl font-black text-slate-900">{stats?.totalInvited || 0}</h3>
                    <p className="text-[11px] text-slate-500 mt-1 font-medium">Referred contacts</p>
                </div>

                <div className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-2xs">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Successful Orders</span>
                        <div className="w-8 h-8 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center">
                            <CheckCircle2 size={16} />
                        </div>
                    </div>
                    <h3 className="text-2xl font-black text-emerald-600">{stats?.successfulConversions || 0}</h3>
                    <p className="text-[11px] text-slate-500 mt-1 font-medium">Completed filings</p>
                </div>

                <div className="bg-white rounded-2xl p-5 border border-slate-200/90 shadow-2xs">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-slate-400">Total Earned</span>
                        <div className="w-8 h-8 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center">
                            <Gift size={16} />
                        </div>
                    </div>
                    <h3 className="text-2xl font-black text-slate-900">₹{stats?.totalEarned || 0}</h3>
                    <p className="text-[11px] text-slate-500 mt-1 font-medium">All-time bonus</p>
                </div>

                <div className="bg-gradient-to-br from-red-50 to-rose-50 rounded-2xl p-5 border border-red-200/80 shadow-2xs">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] font-black uppercase tracking-wider text-red-600">Available Balance</span>
                        <div className="w-8 h-8 rounded-xl bg-red-100 text-red-700 flex items-center justify-center">
                            <IndianRupee size={16} />
                        </div>
                    </div>
                    <div className="flex items-baseline justify-between">
                        <h3 className="text-2xl font-black text-red-700">₹{walletBalance}</h3>
                        {walletBalance >= 500 && (
                            <button
                                onClick={() => {
                                    setPayoutAmount(String(walletBalance));
                                    setShowPayoutModal(true);
                                }}
                                className="text-[11px] font-black text-red-700 hover:underline flex items-center gap-0.5"
                            >
                                <span>Withdraw</span>
                                <ArrowUpRight size={13} />
                            </button>
                        )}
                    </div>
                    <p className="text-[10px] text-slate-600 mt-1 font-semibold">Usable at checkout or UPI</p>
                </div>
            </div>

            {/* 3. SHARING & CODE BAR */}
            <div className="bg-white rounded-3xl p-6 border border-slate-200/90 shadow-2xs space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                    <div>
                        <h3 className="text-base font-black text-slate-900">Your Exclusive Referral Link & Code</h3>
                        <p className="text-xs text-slate-500 font-medium">Share via WhatsApp, Email, or SMS</p>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-500 font-bold">Code:</span>
                        <span className="px-3.5 py-1.5 bg-slate-900 text-white font-mono font-black text-xs rounded-xl tracking-wider">
                            {referralCode}
                        </span>
                    </div>
                </div>

                <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
                    <div className="w-full flex-1 bg-slate-50 border border-slate-200 rounded-2xl px-4 py-3 flex items-center justify-between text-xs font-mono text-slate-700 select-all overflow-hidden">
                        <span className="truncate">{referralLink}</span>
                    </div>
                    <button
                        onClick={handleCopyLink}
                        className="w-full sm:w-auto px-5 py-3 bg-slate-900 hover:bg-slate-800 text-white rounded-2xl text-xs font-black uppercase tracking-wider transition-all flex items-center justify-center gap-2 shrink-0 shadow-sm"
                    >
                        {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                        <span>{copied ? 'Copied!' : 'Copy Link'}</span>
                    </button>
                </div>
            </div>

            {/* 4. REFERRED CONTACTS TABLE */}
            <div className="bg-white rounded-3xl p-6 border border-slate-200/90 shadow-2xs space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                    <div>
                        <h3 className="text-base font-black text-slate-900">Referred Friends & Leads</h3>
                        <p className="text-xs text-slate-500 font-medium">Track your referrals in real-time as they place orders</p>
                    </div>
                    <button
                        onClick={() => setShowAddModal(true)}
                        className="self-start sm:self-auto flex items-center gap-1.5 px-3.5 py-2 bg-red-50 hover:bg-red-100 text-red-700 text-xs font-bold rounded-xl border border-red-200 transition-colors"
                    >
                        <Plus size={14} />
                        <span>Add New Contact</span>
                    </button>
                </div>

                {referralsList.length === 0 ? (
                    <div className="p-10 text-center border-2 border-dashed border-slate-200 rounded-2xl space-y-3">
                        <div className="w-14 h-14 bg-red-50 text-red-600 rounded-2xl flex items-center justify-center mx-auto">
                            <Gift size={24} />
                        </div>
                        <h4 className="text-sm font-black text-slate-800">No Referrals Yet</h4>
                        <p className="text-xs text-slate-500 max-w-sm mx-auto">
                            Click "Refer a Contact" or share your link on WhatsApp to start earning ₹500 for each friend who files with VR Here!
                        </p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs">
                            <thead>
                                <tr className="border-b border-slate-100 text-[10px] font-black uppercase tracking-wider text-slate-400">
                                    <th className="pb-3 px-3">Contact Name</th>
                                    <th className="pb-3 px-3">Mobile Number</th>
                                    <th className="pb-3 px-3">Interested Service</th>
                                    <th className="pb-3 px-3">Status</th>
                                    <th className="pb-3 px-3 text-right">Your Reward</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {referralsList.map((ref) => (
                                    <tr key={ref._id} className="hover:bg-slate-50/80 transition-colors">
                                        <td className="py-3.5 px-3 font-bold text-slate-900">
                                            {ref.refereeName}
                                        </td>
                                        <td className="py-3.5 px-3 font-mono text-slate-600">
                                            {ref.refereePhone}
                                        </td>
                                        <td className="py-3.5 px-3 text-slate-700">
                                            {ref.interestedService}
                                        </td>
                                        <td className="py-3.5 px-3">
                                            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider border ${
                                                ref.status === 'Rewarded'
                                                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                                    : ref.status === 'Order_Placed'
                                                    ? 'bg-blue-50 text-blue-700 border-blue-200'
                                                    : 'bg-amber-50 text-amber-700 border-amber-200'
                                            }`}>
                                                {ref.status === 'Rewarded' ? '₹500 Rewarded' : ref.status === 'Order_Placed' ? 'Order Processing' : 'Invite Sent'}
                                            </span>
                                        </td>
                                        <td className="py-3.5 px-3 text-right font-black">
                                            {ref.status === 'Rewarded' ? (
                                                <span className="text-emerald-600">+₹500</span>
                                            ) : (
                                                <span className="text-slate-400 font-normal">Pending Order</span>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* 5. ADD REFERRAL LEAD MODAL */}
            {showAddModal && (
                <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50 animate-in fade-in">
                    <div className="bg-white rounded-3xl p-6 sm:p-8 max-w-md w-full shadow-2xl border border-slate-100 space-y-5">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2.5">
                                <div className="w-9 h-9 rounded-xl bg-red-50 text-red-600 flex items-center justify-center font-bold">
                                    <Plus size={18} />
                                </div>
                                <div>
                                    <h3 className="text-base font-black text-slate-900">Refer a Friend / Client</h3>
                                    <p className="text-[11px] text-slate-500">We'll reach out and reward you ₹500</p>
                                </div>
                            </div>
                            <button
                                onClick={() => setShowAddModal(false)}
                                className="text-slate-400 hover:text-slate-600 text-lg font-bold"
                            >
                                &times;
                            </button>
                        </div>

                        {leadMessage && (
                            <div className={`p-3 rounded-xl text-xs font-semibold ${leadMessage.type === 'success' ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' : 'bg-red-50 text-red-800 border border-red-200'}`}>
                                {leadMessage.text}
                            </div>
                        )}

                        <form onSubmit={handleAddLeadSubmit} className="space-y-4">
                            <div>
                                <label className="block text-xs font-bold text-slate-700 mb-1">Friend's Full Name *</label>
                                <input
                                    type="text"
                                    required
                                    placeholder="e.g. Ramesh Kumar"
                                    value={leadForm.name}
                                    onChange={(e) => setLeadForm({ ...leadForm, name: e.target.value })}
                                    className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold focus:bg-white focus:outline-red-500"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-bold text-slate-700 mb-1">Mobile Number (10 Digits) *</label>
                                <input
                                    type="tel"
                                    required
                                    maxLength={10}
                                    placeholder="e.g. 9876543210"
                                    value={leadForm.phone}
                                    onChange={(e) => setLeadForm({ ...leadForm, phone: e.target.value.replace(/\D/g, '') })}
                                    className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold font-mono focus:bg-white focus:outline-red-500"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-bold text-slate-700 mb-1">Email Address (Optional)</label>
                                <input
                                    type="email"
                                    placeholder="e.g. ramesh@example.com"
                                    value={leadForm.email}
                                    onChange={(e) => setLeadForm({ ...leadForm, email: e.target.value })}
                                    className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold focus:bg-white focus:outline-red-500"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-bold text-slate-700 mb-1">Interested Service</label>
                                <select
                                    value={leadForm.interestedService}
                                    onChange={(e) => setLeadForm({ ...leadForm, interestedService: e.target.value })}
                                    className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold focus:bg-white focus:outline-red-500"
                                >
                                    <option value="Private Limited Company Registration">Private Limited Company Registration</option>
                                    <option value="GST Registration & Filing">GST Registration & Filing</option>
                                    <option value="Income Tax Return (ITR)">Income Tax Return (ITR)</option>
                                    <option value="Limited Liability Partnership (LLP)">Limited Liability Partnership (LLP)</option>
                                    <option value="Trademark Registration">Trademark Registration</option>
                                    <option value="ISO 9001 / 27001 Certification">ISO 9001 / 27001 Certification</option>
                                    <option value="Accounting & Bookkeeping">Accounting & Bookkeeping</option>
                                </select>
                            </div>

                            <div className="flex items-center justify-end gap-3 pt-2">
                                <button
                                    type="button"
                                    onClick={() => setShowAddModal(false)}
                                    className="px-4 py-2.5 text-xs font-bold text-slate-600 hover:text-slate-800"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={submittingLead}
                                    className="px-5 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-xl text-xs font-black uppercase tracking-wider transition-all disabled:opacity-50 shadow-md"
                                >
                                    {submittingLead ? 'Submitting...' : 'Send Referral Invite'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* 6. UPI PAYOUT WITHDRAWAL MODAL */}
            {showPayoutModal && (
                <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50 animate-in fade-in">
                    <div className="bg-white rounded-3xl p-6 sm:p-8 max-w-md w-full shadow-2xl border border-slate-100 space-y-5">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2.5">
                                <div className="w-9 h-9 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center font-bold">
                                    <IndianRupee size={18} />
                                </div>
                                <div>
                                    <h3 className="text-base font-black text-slate-900">Withdraw to UPI ID</h3>
                                    <p className="text-[11px] text-slate-500">Available Balance: ₹{walletBalance}</p>
                                </div>
                            </div>
                            <button
                                onClick={() => setShowPayoutModal(false)}
                                className="text-slate-400 hover:text-slate-600 text-lg font-bold"
                            >
                                &times;
                            </button>
                        </div>

                        {payoutMessage && (
                            <div className={`p-3 rounded-xl text-xs font-semibold ${payoutMessage.type === 'success' ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' : 'bg-red-50 text-red-800 border border-red-200'}`}>
                                {payoutMessage.text}
                            </div>
                        )}

                        <form onSubmit={handlePayoutSubmit} className="space-y-4">
                            <div>
                                <label className="block text-xs font-bold text-slate-700 mb-1">Your UPI ID (VPA) *</label>
                                <input
                                    type="text"
                                    required
                                    placeholder="e.g. yourname@okhdfcbank or 9876543210@paytm"
                                    value={upiId}
                                    onChange={(e) => setUpiId(e.target.value)}
                                    className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold font-mono focus:bg-white focus:outline-emerald-500"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-bold text-slate-700 mb-1">Withdrawal Amount (₹) *</label>
                                <input
                                    type="number"
                                    required
                                    min={500}
                                    max={walletBalance}
                                    value={payoutAmount}
                                    onChange={(e) => setPayoutAmount(e.target.value)}
                                    className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold font-mono focus:bg-white focus:outline-emerald-500"
                                />
                                <p className="text-[10px] text-slate-400 mt-1">Min withdrawal: ₹500 (Increments of ₹500)</p>
                            </div>

                            <div className="flex items-center justify-end gap-3 pt-2">
                                <button
                                    type="button"
                                    onClick={() => setShowPayoutModal(false)}
                                    className="px-4 py-2.5 text-xs font-bold text-slate-600 hover:text-slate-800"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={submittingPayout || walletBalance < 500}
                                    className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-black uppercase tracking-wider transition-all disabled:opacity-50 shadow-md"
                                >
                                    {submittingPayout ? 'Processing...' : 'Transfer to UPI'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

        </div>
    );
};

export default ReferralView;
