import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Users, IndianRupee, TrendingUp, Search, 
    Filter, RefreshCcw, Edit, ExternalLink,
    CheckCircle2, AlertCircle, Loader2, ArrowUpRight,
    Briefcase, ShieldCheck, Phone, Mail, X
} from 'lucide-react';

const ReferralPartnersModule = ({ config, orders }) => {
    const [partners, setPartners] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [searchTerm, setSearchTerm] = useState('');
    const [editingPartner, setEditingPartner] = useState(null);
    const [updateLoading, setUpdateLoading] = useState(false);

    useEffect(() => {
        fetchPartners();
    }, []);

    const fetchPartners = async () => {
        setLoading(true);
        try {
            const { data } = await axios.get('/api/auth/users?role=partner', config);
            setPartners(data);
        } catch (err) {
            setError('Failed to fetch referral partners');
        } finally {
            setLoading(false);
        }
    };

    const handleUpdateCommission = async (e) => {
        e.preventDefault();
        setUpdateLoading(true);
        try {
            await axios.put(`/api/auth/users/${editingPartner._id}`, {
                commissionPercentage: editingPartner.commissionPercentage
            }, config);
            
            setPartners(partners.map(p => p._id === editingPartner._id ? editingPartner : p));
            setEditingPartner(null);
        } catch (err) {
            alert('Failed to update commission');
        } finally {
            setUpdateLoading(false);
        }
    };

    const handleToggleActive = async (partnerId) => {
        try {
            const { data } = await axios.patch(`/api/auth/users/${partnerId}/toggle-active`, {}, config);
            setPartners(partners.map(p => p._id === partnerId ? { ...p, isActive: data.user.isActive } : p));
        } catch (err) {
            alert('Failed to update partner status');
        }
    };

    // Helper to calculate partner-specific stats from orders
    const getPartnerStats = (partnerId) => {
        const partnerOrders = orders.filter(o => o.referralPartner && (o.referralPartner._id === partnerId || o.referralPartner === partnerId));
        const totalRevenue = partnerOrders.reduce((sum, o) => sum + (o.price || 0), 0);
        const totalCommission = partnerOrders.reduce((sum, o) => sum + (o.partnerCommissionAmount || 0), 0);
        return { count: partnerOrders.length, revenue: totalRevenue, commission: totalCommission };
    };

    const filteredPartners = partners.filter(p => 
        p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        p.phone?.includes(searchTerm) ||
        p.panCard?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const formatCurrency = (amount) => {
        return new Intl.NumberFormat('en-IN', {
            style: 'currency',
            currency: 'INR',
            maximumFractionDigits: 0
        }).format(amount);
    };

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center p-20">
                <div className="w-12 h-12 border-4 border-slate-200 border-t-red-600 rounded-full animate-spin mb-4"></div>
                <p className="text-slate-500 font-bold">Loading partners...</p>
            </div>
        );
    }

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            
            {/* Header Section */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div>
                    <h2 className="text-3xl font-black text-slate-800 tracking-tight">Referral Partner Management</h2>
                    <p className="text-slate-500 font-medium mt-1">Control commission rates and monitor partner performance.</p>
                </div>
                <div className="flex items-center gap-3">
                    <button 
                        onClick={fetchPartners}
                        className="p-3 rounded-2xl bg-white border border-slate-200 text-slate-500 hover:text-red-500 transition-all shadow-sm"
                    >
                        <RefreshCcw className="w-5 h-5" />
                    </button>
                    <div className="px-5 py-3 bg-slate-900 text-white rounded-2xl shadow-xl shadow-slate-200 text-sm font-black flex items-center gap-2">
                        <Users className="w-4 h-4 text-red-500" />
                        {partners.filter(p => p.isActive).length} Active Partners
                        {partners.filter(p => !p.isActive).length > 0 && (
                            <span className="ml-2 px-2 py-0.5 bg-red-600 rounded-full text-[10px]">
                                {partners.filter(p => !p.isActive).length} Pending
                            </span>
                        )}
                    </div>
                </div>
            </div>

            {/* Main Content Area */}
            <div className="bg-white rounded-[32px] shadow-sm border border-slate-100 overflow-hidden">
                <div className="p-8 border-b border-slate-100 bg-slate-50/30">
                    <div className="flex flex-col md:flex-row items-center justify-between gap-6">
                        <div className="relative group w-full md:w-96">
                            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                            <input 
                                type="text" 
                                placeholder="Search by name, phone or PAN..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                className="w-full pl-11 pr-4 py-3 rounded-2xl bg-white border border-slate-200 text-sm font-semibold focus:ring-4 focus:ring-red-500/10 focus:border-red-500 outline-none transition-all shadow-sm"
                            />
                        </div>
                        <div className="flex items-center gap-4">
                             <button className="flex items-center gap-2 px-5 py-3 rounded-2xl border border-slate-200 text-sm font-bold text-slate-600 hover:bg-slate-50 transition-colors">
                                <Filter className="w-4 h-4" />
                                Custom Filter
                            </button>
                        </div>
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-50/50">
                                <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Partner Details</th>
                                <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Status</th>
                                <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Commission %</th>
                                <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Referrals</th>
                                <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Revenue Brought</th>
                                <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Owed Commission</th>
                                <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100"></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                            {filteredPartners.length > 0 ? filteredPartners.map((partner) => {
                                const partnerStats = getPartnerStats(partner._id);
                                return (
                                    <tr key={partner._id} className="hover:bg-slate-50/50 transition-colors group">
                                        <td className="px-8 py-6">
                                            <div className="flex items-center gap-4">
                                                <div className={`w-12 h-12 rounded-2xl flex items-center justify-center font-bold text-lg shrink-0 ${partner.isActive ? 'bg-indigo-50 text-indigo-600' : 'bg-slate-100 text-slate-400'}`}>
                                                    {partner.name.charAt(0)}
                                                </div>
                                                <div>
                                                    <div className={`font-black transition-colors ${partner.isActive ? 'text-slate-900 group-hover:text-red-600' : 'text-slate-400'}`}>
                                                        {partner.name}
                                                        {!partner.isActive && <span className="ml-2 text-[9px] bg-red-100 text-red-600 px-2 py-0.5 rounded-full uppercase tracking-widest">Pending Validation</span>}
                                                    </div>
                                                    <div className="flex items-center gap-3 mt-1 text-[11px] font-bold text-slate-400">
                                                        <span className="flex items-center gap-1"><Phone className="w-3 h-3" /> {partner.phone}</span>
                                                        <span className="flex items-center gap-1 uppercase"><ShieldCheck className="w-3 h-3" /> {partner.panCard || 'NO-KYC'}</span>
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-8 py-6 text-center">
                                            <button 
                                                onClick={() => handleToggleActive(partner._id)}
                                                className={`px-4 py-1.5 rounded-full text-[10px] font-black uppercase tracking-widest transition-all border ${
                                                    partner.isActive 
                                                    ? 'bg-green-50 text-green-600 border-green-100 hover:bg-green-100' 
                                                    : 'bg-red-600 text-white border-red-700 hover:bg-red-700 shadow-lg shadow-red-200'
                                                }`}
                                            >
                                                {partner.isActive ? 'Active' : 'Validate Account'}
                                            </button>
                                        </td>
                                        <td className="px-8 py-6 text-center">
                                            <div className="inline-flex items-center gap-2 px-3 py-1 bg-red-50 text-red-600 rounded-full text-xs font-black border border-red-100">
                                                {partner.commissionPercentage || 10}%
                                            </div>
                                        </td>
                                        <td className="px-8 py-6 text-center text-sm font-black text-slate-600">
                                            {partnerStats.count}
                                        </td>
                                        <td className="px-8 py-6 text-right">
                                            <div className="font-bold text-slate-900">{formatCurrency(partnerStats.revenue)}</div>
                                            <div className="text-[10px] font-black text-slate-400 uppercase tracking-tighter">Total OrdersValue</div>
                                        </td>
                                        <td className="px-8 py-6 text-right">
                                            <div className="font-black text-green-600">{formatCurrency(partnerStats.commission)}</div>
                                            <div className="text-[10px] font-black text-slate-400 uppercase tracking-tighter">Accrued Commission</div>
                                        </td>
                                        <td className="px-8 py-6 text-right">
                                            <button 
                                                onClick={() => setEditingPartner(partner)}
                                                className="p-2.5 rounded-xl text-slate-400 hover:bg-white hover:text-red-500 hover:shadow-sm border border-transparent hover:border-slate-100 transition-all"
                                            >
                                                <Edit className="w-5 h-5" />
                                            </button>
                                        </td>
                                    </tr>
                                );
                            }) : (
                                <tr>
                                    <td colSpan="6" className="p-20 text-center">
                                        <div className="w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
                                            <Users className="w-8 h-8 text-slate-300" />
                                        </div>
                                        <h4 className="font-black text-slate-900">No Partners Found</h4>
                                        <p className="text-slate-500 mt-1 max-w-xs mx-auto">Try a different search term or check if partners have registered.</p>
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Edit Modal */}
            {editingPartner && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-slate-900/40 backdrop-blur-md animate-fade-in">
                    <div className="bg-white rounded-[40px] shadow-2xl max-w-md w-full overflow-hidden animate-scale-in border border-white/50">
                        <div className="bg-slate-950 p-8 flex items-center justify-between border-b-4 border-red-600">
                            <div>
                                <h3 className="text-white text-xl font-black tracking-tight">Edit Partner Rates</h3>
                                <p className="text-slate-500 text-xs font-bold uppercase tracking-widest mt-1">{editingPartner.name}</p>
                            </div>
                            <button onClick={() => setEditingPartner(null)} className="p-2 text-slate-400 hover:text-white transition">
                                <X className="w-6 h-6" />
                            </button>
                        </div>
                        <div className="p-8 lg:p-10">
                            <form onSubmit={handleUpdateCommission} className="space-y-8">
                                <div className="space-y-2">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Commission Percentage (%)</label>
                                    <div className="relative group">
                                        <TrendingUp className="absolute left-5 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                        <input 
                                            type="number" 
                                            required
                                            value={editingPartner.commissionPercentage}
                                            onChange={(e) => setEditingPartner({...editingPartner, commissionPercentage: e.target.value})}
                                            className="w-full pl-14 pr-6 py-5 rounded-3xl bg-slate-50 border-2 border-transparent focus:border-red-500 focus:bg-white focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-black text-lg"
                                            placeholder="e.g. 10"
                                        />
                                    </div>
                                    <p className="text-[11px] text-slate-400 font-medium px-2 pt-1 uppercase">
                                        Changes will apply to all orders placed after this update.
                                    </p>
                                </div>

                                <div className="flex gap-4">
                                    <button 
                                        type="button"
                                        onClick={() => setEditingPartner(null)}
                                        className="flex-1 py-5 rounded-3xl bg-slate-100 text-slate-600 font-black hover:bg-slate-200 transition active:scale-95"
                                    >
                                        Cancel
                                    </button>
                                    <button 
                                        disabled={updateLoading}
                                        type="submit"
                                        className="flex-1 py-5 rounded-3xl bg-slate-900 text-white font-black hover:bg-slate-800 shadow-xl shadow-slate-200 transition active:scale-95 flex items-center justify-center gap-2"
                                    >
                                        {updateLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Save Changes'}
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            )}

        </div>
    );
};

export default ReferralPartnersModule;
