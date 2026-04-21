import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Users, Briefcase, TrendingUp, Search, 
    Filter, RefreshCw, ChevronRight, CheckCircle2,
    Clock, AlertCircle, IndianRupee, ExternalLink
} from 'lucide-react';

const PartnerOverviewView = ({ userInfo }) => {
    const [orders, setOrders] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        fetchPartnerOrders();
    }, []);

    const fetchPartnerOrders = async () => {
        setLoading(true);
        try {
            const config = {
                headers: { Authorization: `Bearer ${userInfo.token}` }
            };
            const { data } = await axios.get('/api/partner/orders', config);
            setOrders(data);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to fetch referral orders');
        } finally {
            setLoading(false);
        }
    };

    const stats = [
        { 
            label: 'Total Referrals', 
            value: orders.length, 
            icon: Users, 
            color: 'bg-indigo-50 text-indigo-600',
            trend: 'Direct Reach'
        },
        { 
            label: 'Active Cases', 
            value: orders.filter(o => o.status !== 'Completed').length, 
            icon: Briefcase, 
            color: 'bg-red-50 text-red-600',
            trend: 'In Progress'
        },
        { 
            label: 'Total Commission', 
            value: orders.reduce((acc, curr) => acc + (curr.partnerCommissionAmount || 0), 0), 
            icon: IndianRupee, 
            color: 'bg-green-50 text-green-600',
            isCurrency: true,
            trend: 'Lifetime Earnings'
        },
        { 
            label: 'Conversion Rate', 
            value: orders.length > 0 ? '100%' : '0%', 
            icon: TrendingUp, 
            color: 'bg-amber-50 text-amber-600',
            trend: 'Paid Referrals'
        }
    ];

    const filteredOrders = orders.filter(order => 
        order.clientName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        order.serviceName?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const getStatusColor = (status) => {
        switch (status) {
            case 'Completed': return 'bg-green-50 text-green-600 border-green-100';
            case 'Pending Documents': return 'bg-amber-50 text-amber-600 border-amber-100';
            case 'Waiting for Clarification': return 'bg-red-50 text-red-600 border-red-100';
            default: return 'bg-indigo-50 text-indigo-600 border-indigo-100';
        }
    };

    const formatCurrency = (amount) => {
        return new Intl.NumberFormat('en-IN', {
            style: 'currency',
            currency: 'INR',
            maximumFractionDigits: 0
        }).format(amount);
    };

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center p-12">
                <div className="w-12 h-12 border-4 border-slate-200 border-t-red-600 rounded-full animate-spin mb-4"></div>
                <p className="text-slate-500 font-bold animate-pulse">Loading dashboard data...</p>
            </div>
        );
    }

    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            
            {/* Header Section */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Partner Overview</h1>
                    <p className="text-slate-500 text-sm mt-1">Monitor your referrals and track your commission earnings.</p>
                </div>
                <div className="flex items-center gap-3">
                    <button 
                        onClick={fetchPartnerOrders}
                        className="p-2.5 rounded-xl bg-white border border-slate-200 text-slate-500 hover:text-red-600 hover:border-red-100 transition-all shadow-sm"
                    >
                        <RefreshCw className="w-5 h-5" />
                    </button>
                    <div className="flex items-center gap-2 px-4 py-2.5 bg-slate-900 text-white rounded-xl shadow-lg shadow-slate-200 text-sm font-bold">
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                        Active Partner
                    </div>
                </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {stats.map((stat, idx) => (
                    <div key={idx} className="bg-white p-6 rounded-[24px] shadow-sm border border-slate-100 hover:shadow-md transition-shadow">
                        <div className="flex items-start justify-between mb-4">
                            <div className={`p-3 rounded-2xl ${stat.color}`}>
                                <stat.icon className="w-6 h-6" />
                            </div>
                            <div className="text-[10px] font-black uppercase tracking-widest text-slate-400">
                                {stat.trend}
                            </div>
                        </div>
                        <h3 className="text-slate-500 text-xs font-bold uppercase tracking-wider">{stat.label}</h3>
                        <div className="text-2xl font-black text-slate-900 mt-1">
                            {stat.isCurrency ? formatCurrency(stat.value) : stat.value}
                        </div>
                    </div>
                ))}
            </div>

            {/* Orders Table Section */}
            <div className="bg-white rounded-[32px] shadow-sm border border-slate-100 overflow-hidden">
                <div className="p-8 border-b border-slate-100 bg-slate-50/50">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                        <h3 className="text-lg font-black text-slate-800">Referral Orders</h3>
                        
                        <div className="flex flex-wrap items-center gap-4">
                            <div className="relative group">
                                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                <input 
                                    type="text" 
                                    placeholder="Search client or service..."
                                    value={searchTerm}
                                    onChange={(e) => setSearchTerm(e.target.value)}
                                    className="pl-11 pr-4 py-2.5 rounded-xl bg-white border border-slate-200 text-sm focus:ring-4 focus:ring-red-500/10 focus:border-red-500 outline-none w-full md:w-64 transition-all"
                                />
                            </div>
                            <button className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-slate-200 text-sm font-bold text-slate-600 hover:bg-slate-50 transition-colors">
                                <Filter className="w-4 h-4" />
                                Filters
                            </button>
                        </div>
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-50/30">
                                <th className="px-8 py-4 text-xs font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Client / Service</th>
                                <th className="px-8 py-4 text-xs font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Order Date</th>
                                <th className="px-8 py-4 text-xs font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Status</th>
                                <th className="px-8 py-4 text-xs font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Commission</th>
                                <th className="px-8 py-4 text-xs font-black text-slate-400 uppercase tracking-widest border-b border-slate-100"></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-50">
                            {filteredOrders.length > 0 ? filteredOrders.map((order) => (
                                <tr key={order._id} className="hover:bg-slate-50/50 transition-colors group">
                                    <td className="px-8 py-5">
                                        <div className="font-bold text-slate-900">{order.clientName}</div>
                                        <div className="text-xs text-slate-500 font-medium mt-0.5">{order.serviceName}</div>
                                    </td>
                                    <td className="px-8 py-5">
                                        <div className="text-sm text-slate-600 font-semibold">{new Date(order.createdAt).toLocaleDateString()}</div>
                                        <div className="text-[10px] text-slate-400 font-bold uppercase tracking-tighter mt-0.5">
                                            {new Date(order.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                        </div>
                                    </td>
                                    <td className="px-8 py-5 text-center">
                                        <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest border ${getStatusColor(order.status)}`}>
                                            {order.status}
                                        </span>
                                    </td>
                                    <td className="px-8 py-5 text-right">
                                        <div className="font-black text-green-600">{formatCurrency(order.partnerCommissionAmount)}</div>
                                        <div className="text-[10px] text-slate-400 font-bold uppercase mt-0.5">Earned</div>
                                    </td>
                                    <td className="px-8 py-5 text-right">
                                        <button className="p-2 rounded-lg text-slate-400 hover:bg-slate-200 hover:text-slate-600 transition-colors">
                                            <ChevronRight className="w-5 h-5" />
                                        </button>
                                    </td>
                                </tr>
                            )) : (
                                <tr>
                                    <td colSpan="5" className="px-8 py-20 text-center">
                                        <div className="bg-slate-50 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                                            <AlertCircle className="w-8 h-8 text-slate-300" />
                                        </div>
                                        <h4 className="font-bold text-slate-900">No referrals found</h4>
                                        <p className="text-slate-500 text-sm mt-1 max-w-xs mx-auto">
                                            When customers use your mobile number as a referral code, their orders will appear here.
                                        </p>
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>

                {filteredOrders.length > 0 && (
                    <div className="p-6 bg-slate-50/30 border-t border-slate-100 text-center">
                        <button className="text-xs font-black text-slate-400 uppercase tracking-widest hover:text-red-600 transition-colors flex items-center gap-2 mx-auto disabled:opacity-50">
                            Load More Referrals <RefreshCw className="w-3 h-3" />
                        </button>
                    </div>
                )}
            </div>

            {/* Payout Info Section */}
            <div className="grid lg:grid-cols-2 gap-8">
                <div className="bg-gradient-to-br from-indigo-600 to-indigo-800 p-8 rounded-[32px] text-white shadow-xl shadow-indigo-200 relative overflow-hidden group">
                    <div className="absolute top-0 right-0 w-48 h-48 bg-white/10 rounded-full -mr-24 -mt-24 blur-3xl group-hover:bg-white/20 transition-all"></div>
                    <div className="relative z-10 flex flex-col h-full justify-between gap-6">
                        <div>
                            <div className="p-3 bg-white/10 rounded-2xl w-fit mb-6">
                                <Clock className="w-6 h-6 text-indigo-100" />
                            </div>
                            <h3 className="text-2xl font-black tracking-tight leading-tight">Payment Cycle Info</h3>
                            <p className="text-indigo-100 text-sm mt-2 font-medium">Commissions are processed on the 10th of every month for all completed orders of the previous month.</p>
                        </div>
                        <button className="bg-white/10 hover:bg-white/20 text-white font-bold py-3 rounded-2xl transition flex items-center justify-center gap-2 border border-white/20">
                            Download Payout Policy <ExternalLink className="w-4 h-4" />
                        </button>
                    </div>
                </div>

                <div className="bg-white p-8 rounded-[32px] border border-slate-100 shadow-sm">
                    <h3 className="text-lg font-black text-slate-900 mb-6">Bank Details</h3>
                    <div className="space-y-4">
                        <div className="p-4 bg-slate-50 rounded-2xl">
                            <div className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Account Holder</div>
                            <div className="font-bold text-slate-800">{userInfo.name}</div>
                        </div>
                        <div className="p-4 bg-slate-50 rounded-2xl">
                            <div className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Status</div>
                            <div className="flex items-center gap-2 text-green-600 font-bold text-sm">
                                <CheckCircle2 className="w-4 h-4" /> KYC Verified (PAN: {userInfo.panCard})
                            </div>
                        </div>
                        <p className="text-xs text-slate-400 font-medium pt-2">
                           Note: If you need to update your bank details, please contact our support team.
                        </p>
                    </div>
                </div>
            </div>

        </div>
    );
};

export default PartnerOverviewView;
