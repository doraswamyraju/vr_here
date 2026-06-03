import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Users, IndianRupee, TrendingUp, Search, 
    Filter, RefreshCcw, Edit, ExternalLink,
    CheckCircle2, AlertCircle, Loader2, ArrowUpRight,
    Briefcase, ShieldCheck, Phone, Mail, X, Trash2,
    Eye, ArrowLeft, Calendar, FileText, Pause, Play
} from 'lucide-react';

const ReferralPartnersModule = ({ config, orders }) => {
    const [partners, setPartners] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [searchTerm, setSearchTerm] = useState('');
    const [editingPartner, setEditingPartner] = useState(null);
    const [selectedPartner, setSelectedPartner] = useState(null);
    const [updateLoading, setUpdateLoading] = useState(false);
    const [orderSearchText, setOrderSearchText] = useState('');

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

    const handleUpdatePartner = async (e) => {
        e.preventDefault();
        setUpdateLoading(true);
        try {
            const { data } = await axios.put(`/api/auth/users/${editingPartner._id}`, {
                name: editingPartner.name,
                email: editingPartner.email,
                phone: editingPartner.phone,
                panCard: editingPartner.panCard,
                commissionPercentage: editingPartner.commissionPercentage
            }, config);
            
            const updated = data.user || editingPartner;
            setPartners(partners.map(p => p._id === updated._id ? { ...p, ...updated } : p));
            if (selectedPartner && selectedPartner._id === updated._id) {
                setSelectedPartner({ ...selectedPartner, ...updated });
            }
            setEditingPartner(null);
        } catch (err) {
            alert(err?.response?.data?.message || 'Failed to update partner details');
        } finally {
            setUpdateLoading(false);
        }
    };

    const handleToggleActive = async (partnerId) => {
        try {
            const { data } = await axios.patch(`/api/auth/users/${partnerId}/toggle-active`, {}, config);
            const updatedPartners = partners.map(p => p._id === partnerId ? { ...p, isActive: data.user.isActive } : p);
            setPartners(updatedPartners);
            if (selectedPartner && selectedPartner._id === partnerId) {
                setSelectedPartner({ ...selectedPartner, isActive: data.user.isActive });
            }
        } catch (err) {
            alert('Failed to update partner status');
        }
    };

    const handleDeletePartner = async (partner) => {
        if (!window.confirm(`Are you sure you want to permanently delete partner "${partner.name}"? This will revoke all dashboard access.`)) {
            return;
        }
        try {
            await axios.delete(`/api/auth/users/${partner._id}`, config);
            setPartners(partners.filter(p => p._id !== partner._id));
            if (selectedPartner && selectedPartner._id === partner._id) {
                setSelectedPartner(null);
            }
            alert('Partner successfully deleted');
        } catch (err) {
            alert(err?.response?.data?.message || 'Failed to delete partner');
        }
    };

    const getPartnerStats = (partnerId) => {
        const partnerOrders = orders.filter(o => o.referralPartner && (o.referralPartner._id === partnerId || o.referralPartner === partnerId || (o.referralPartner.phone && partners.find(p => p._id === partnerId)?.phone === o.referralPartner.phone)));
        const totalRevenue = partnerOrders.reduce((sum, o) => sum + (o.price || 0), 0);
        const totalCommission = partnerOrders.reduce((sum, o) => sum + (o.partnerCommissionAmount || 0), 0);
        return { 
            count: partnerOrders.length, 
            revenue: totalRevenue, 
            commission: totalCommission,
            orders: partnerOrders
        };
    };

    const filteredPartners = partners.filter(p => 
        p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        p.phone?.includes(searchTerm) ||
        p.email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
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

    if (selectedPartner) {
        const stats = getPartnerStats(selectedPartner._id);
        const filteredOrders = stats.orders.filter(o => 
            o.clientName?.toLowerCase().includes(orderSearchText.toLowerCase()) ||
            o.serviceName?.toLowerCase().includes(orderSearchText.toLowerCase()) ||
            o._id?.includes(orderSearchText)
        );

        return (
            <div className="space-y-8 animate-in fade-in duration-300">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <button 
                        onClick={() => { setSelectedPartner(null); setOrderSearchText(''); }}
                        className="inline-flex items-center gap-2 text-slate-500 hover:text-slate-900 font-bold text-sm transition-colors self-start"
                    >
                        <ArrowLeft className="w-4 h-4" />
                        Back to Partner List
                    </button>

                    <div className="flex items-center gap-3">
                        <button 
                            onClick={() => setEditingPartner(selectedPartner)}
                            className="flex items-center gap-2 px-4 py-2 border border-slate-200 hover:bg-slate-50 rounded-xl text-xs font-bold text-slate-700 transition"
                        >
                            <Edit className="w-4 h-4" />
                            Edit Details
                        </button>
                        <button 
                            onClick={() => handleToggleActive(selectedPartner._id)}
                            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold text-white transition ${
                                selectedPartner.isActive 
                                ? 'bg-amber-600 hover:bg-amber-700' 
                                : 'bg-green-600 hover:bg-green-700'
                            }`}
                        >
                            {selectedPartner.isActive ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                            {selectedPartner.isActive ? 'Pause Access' : 'Resume Access'}
                        </button>
                        <button 
                            onClick={() => handleDeletePartner(selectedPartner)}
                            className="flex items-center gap-2 px-4 py-2 bg-red-50 text-red-600 hover:bg-red-100 rounded-xl text-xs font-bold transition"
                        >
                            <Trash2 className="w-4 h-4" />
                            Delete Partner
                        </button>
                    </div>
                </div>

                <div className="bg-slate-950 text-white rounded-[32px] p-8 md:p-10 relative overflow-hidden shadow-xl">
                    <div className="absolute right-0 top-0 translate-x-12 -translate-y-12 w-64 h-64 bg-red-600/10 rounded-full blur-3xl"></div>
                    <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 relative z-10">
                        <div>
                            <span className={`inline-block px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider mb-3 ${
                                selectedPartner.isActive ? 'bg-green-500/20 text-green-400 border border-green-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'
                            }`}>
                                {selectedPartner.isActive ? 'Active Channel' : 'Inactive / Paused'}
                            </span>
                            <h2 className="text-3xl font-black tracking-tight">{selectedPartner.name}</h2>
                            <div className="flex flex-wrap gap-4 mt-3 text-slate-400 text-xs font-semibold">
                                <span className="flex items-center gap-1.5"><Phone className="w-4 h-4 text-red-500" /> {selectedPartner.phone}</span>
                                <span className="flex items-center gap-1.5"><Mail className="w-4 h-4 text-red-500" /> {selectedPartner.email}</span>
                                <span className="flex items-center gap-1.5 uppercase"><ShieldCheck className="w-4 h-4 text-red-500" /> PAN: {selectedPartner.panCard || 'N/A'}</span>
                            </div>
                        </div>
                        <div className="text-left md:text-right bg-white/5 border border-white/10 rounded-2xl p-5 shrink-0">
                            <p className="text-slate-400 text-[10px] font-black uppercase tracking-widest">Commission Settings</p>
                            <p className="text-3xl font-black text-red-500 mt-1">{selectedPartner.commissionPercentage || 10}%</p>
                            <p className="text-slate-400 text-[10px] font-medium mt-1">Default rate on business fees</p>
                        </div>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm flex items-center gap-5">
                        <div className="w-14 h-14 bg-indigo-50 rounded-2xl flex items-center justify-center text-indigo-600">
                            <TrendingUp className="w-7 h-7" />
                        </div>
                        <div>
                            <p className="text-slate-400 text-xs font-black uppercase tracking-wider">Total Referred Orders</p>
                            <h4 className="text-2xl font-black text-slate-800 mt-1">{stats.count}</h4>
                        </div>
                    </div>

                    <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm flex items-center gap-5">
                        <div className="w-14 h-14 bg-emerald-50 rounded-2xl flex items-center justify-center text-emerald-600">
                            <IndianRupee className="w-7 h-7" />
                        </div>
                        <div>
                            <p className="text-slate-400 text-xs font-black uppercase tracking-wider">Total Sales Volume</p>
                            <h4 className="text-2xl font-black text-slate-800 mt-1">{formatCurrency(stats.revenue)}</h4>
                        </div>
                    </div>

                    <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm flex items-center gap-5">
                        <div className="w-14 h-14 bg-red-50 rounded-2xl flex items-center justify-center text-red-600">
                            <ArrowUpRight className="w-7 h-7" />
                        </div>
                        <div>
                            <p className="text-slate-400 text-xs font-black uppercase tracking-wider">Accrued Commission</p>
                            <h4 className="text-2xl font-black text-green-600 mt-1">{formatCurrency(stats.commission)}</h4>
                        </div>
                    </div>
                </div>

                <div className="bg-white rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                    <div className="p-8 border-b border-slate-100 flex flex-col md:flex-row items-center justify-between gap-6 bg-slate-50/20">
                        <div>
                            <h3 className="text-xl font-black text-slate-800 tracking-tight">Referred Business Ledger</h3>
                            <p className="text-slate-500 text-xs font-medium mt-1">Live order tracking and commissions earned.</p>
                        </div>
                        <div className="relative w-full md:w-80">
                            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                            <input 
                                type="text" 
                                placeholder="Search orders, clients..."
                                value={orderSearchText}
                                onChange={(e) => setOrderSearchText(e.target.value)}
                                className="w-full pl-11 pr-4 py-2.5 rounded-xl bg-white border border-slate-200 text-xs font-semibold outline-none focus:border-red-500 transition shadow-sm"
                            />
                        </div>
                    </div>

                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-50/50">
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Order ID & Date</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Client details</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Service Page</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Order Value</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Commission</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Status</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100 text-xs">
                                {filteredOrders.length > 0 ? filteredOrders.map((o) => (
                                    <tr key={o._id} className="hover:bg-slate-50/40 transition-colors">
                                        <td className="px-8 py-5">
                                            <div className="font-bold text-slate-900 flex items-center gap-1">
                                                #{o._id ? o._id.slice(-6).toUpperCase() : 'N/A'}
                                            </div>
                                            <div className="text-[10px] text-slate-400 font-semibold mt-0.5">
                                                {o.createdAt ? new Date(o.createdAt).toLocaleDateString('en-IN', { dateStyle: 'medium' }) : 'N/A'}
                                            </div>
                                        </td>
                                        <td className="px-8 py-5">
                                            <div className="font-bold text-slate-900">{o.clientName || 'N/A'}</div>
                                            <div className="text-[10px] text-slate-400 font-semibold mt-0.5">{o.clientPhone || o.clientEmail || ''}</div>
                                        </td>
                                        <td className="px-8 py-5 font-bold text-slate-600">
                                            {o.serviceName || 'Standard Consult'}
                                        </td>
                                        <td className="px-8 py-5 text-right font-bold text-slate-900">
                                            {formatCurrency(o.price || 0)}
                                        </td>
                                        <td className="px-8 py-5 text-right font-black text-green-600">
                                            {formatCurrency(o.partnerCommissionAmount || 0)}
                                        </td>
                                        <td className="px-8 py-5 text-center">
                                            <span className={`inline-block px-2.5 py-1 rounded-full text-[9px] font-black uppercase tracking-wider ${
                                                o.status === 'completed' ? 'bg-green-50 text-green-600 border border-green-100' :
                                                o.status === 'cancelled' ? 'bg-red-50 text-red-600 border border-red-100' :
                                                'bg-amber-50 text-amber-600 border border-amber-100'
                                            }`}>
                                                {o.status || 'pending'}
                                            </span>
                                        </td>
                                    </tr>
                                )) : (
                                    <tr>
                                        <td colSpan="6" className="p-16 text-center">
                                            <div className="w-12 h-12 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3">
                                                <FileText className="w-6 h-6 text-slate-300" />
                                            </div>
                                            <h5 className="font-bold text-slate-700">No Orders Found</h5>
                                            <p className="text-slate-400 text-xs mt-1">This partner hasn't brought in any matched referrals matching filters.</p>
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            
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

            <div className="bg-white rounded-[32px] shadow-sm border border-slate-100 overflow-hidden">
                <div className="p-8 border-b border-slate-100 bg-slate-50/30">
                    <div className="flex flex-col md:flex-row items-center justify-between gap-6">
                        <div className="relative group w-full md:w-96">
                            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                            <input 
                                type="text" 
                                placeholder="Search by name, phone, email or PAN..."
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
                                <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Actions</th>
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
                                                        {!partner.isActive && <span className="ml-2 text-[9px] bg-red-100 text-red-600 px-2 py-0.5 rounded-full uppercase tracking-widest font-black">Paused/Pending</span>}
                                                    </div>
                                                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1 text-[11px] font-bold text-slate-400">
                                                        <span className="flex items-center gap-1"><Phone className="w-3 h-3" /> {partner.phone}</span>
                                                        {partner.email && <span className="flex items-center gap-1"><Mail className="w-3 h-3" /> {partner.email}</span>}
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
                                                {partner.isActive ? 'Active' : 'Validate / Resume'}
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
                                            <div className="flex items-center justify-end gap-2">
                                                <button 
                                                    onClick={() => setSelectedPartner(partner)}
                                                    className="p-2.5 rounded-xl text-slate-400 hover:bg-slate-50 hover:text-slate-700 transition"
                                                    title="View Partner Dashboard"
                                                >
                                                    <Eye className="w-4 h-4" />
                                                </button>
                                                <button 
                                                    onClick={() => setEditingPartner(partner)}
                                                    className="p-2.5 rounded-xl text-slate-400 hover:bg-slate-50 hover:text-slate-700 transition"
                                                    title="Edit Partner"
                                                >
                                                    <Edit className="w-4 h-4" />
                                                </button>
                                                <button 
                                                    onClick={() => handleDeletePartner(partner)}
                                                    className="p-2.5 rounded-xl text-slate-400 hover:bg-red-50 hover:text-red-600 transition"
                                                    title="Delete Partner"
                                                >
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                );
                            }) : (
                                <tr>
                                    <td colSpan="7" className="p-20 text-center">
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

            {editingPartner && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-slate-900/40 backdrop-blur-md animate-fade-in">
                    <div className="bg-white rounded-[40px] shadow-2xl max-w-lg w-full overflow-hidden border border-white/50">
                        <div className="bg-slate-950 p-8 flex items-center justify-between border-b-4 border-red-600">
                            <div>
                                <h3 className="text-white text-xl font-black tracking-tight font-sans">Edit Referral Partner</h3>
                                <p className="text-slate-400 text-xs font-bold uppercase tracking-widest mt-1">Update details & commission rates</p>
                            </div>
                            <button onClick={() => setEditingPartner(null)} className="p-2 text-slate-400 hover:text-white transition">
                                <X className="w-6 h-6" />
                            </button>
                        </div>
                        <div className="p-8 space-y-6 max-h-[70vh] overflow-y-auto">
                            <form onSubmit={handleUpdatePartner} className="space-y-6">
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Full Name</label>
                                    <input 
                                        type="text" 
                                        required
                                        value={editingPartner.name}
                                        onChange={(e) => setEditingPartner({...editingPartner, name: e.target.value})}
                                        className="w-full px-5 py-3 rounded-2xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-sm transition"
                                    />
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div className="space-y-1.5">
                                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Email address</label>
                                        <input 
                                            type="email" 
                                            required
                                            value={editingPartner.email}
                                            onChange={(e) => setEditingPartner({...editingPartner, email: e.target.value})}
                                            className="w-full px-5 py-3 rounded-2xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-sm transition"
                                        />
                                    </div>
                                    <div className="space-y-1.5">
                                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Phone Number</label>
                                        <input 
                                            type="text" 
                                            required
                                            value={editingPartner.phone}
                                            onChange={(e) => setEditingPartner({...editingPartner, phone: e.target.value})}
                                            className="w-full px-5 py-3 rounded-2xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-sm transition"
                                        />
                                    </div>
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div className="space-y-1.5">
                                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">PAN Card Number</label>
                                        <input 
                                            type="text" 
                                            required
                                            value={editingPartner.panCard || ''}
                                            onChange={(e) => setEditingPartner({...editingPartner, panCard: e.target.value.toUpperCase()})}
                                            className="w-full px-5 py-3 rounded-2xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-sm uppercase transition"
                                        />
                                    </div>
                                    <div className="space-y-1.5">
                                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Commission Rate (%)</label>
                                        <input 
                                            type="number" 
                                            required
                                            value={editingPartner.commissionPercentage}
                                            onChange={(e) => setEditingPartner({...editingPartner, commissionPercentage: e.target.value})}
                                            className="w-full px-5 py-3 rounded-2xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-sm transition"
                                        />
                                    </div>
                                </div>

                                <div className="flex gap-4 pt-4 border-t border-slate-100">
                                    <button 
                                        type="button"
                                        onClick={() => setEditingPartner(null)}
                                        className="flex-1 py-3.5 rounded-2xl bg-slate-100 text-slate-600 font-bold hover:bg-slate-200 transition active:scale-98"
                                    >
                                        Cancel
                                    </button>
                                    <button 
                                        disabled={updateLoading}
                                        type="submit"
                                        className="flex-1 py-3.5 rounded-2xl bg-slate-900 text-white font-bold hover:bg-slate-800 shadow-xl shadow-slate-200 transition active:scale-98 flex items-center justify-center gap-2"
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
