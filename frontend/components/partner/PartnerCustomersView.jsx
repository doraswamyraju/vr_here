import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Users, UserPlus, Search, RefreshCw, Phone, Mail, 
    Building2, FileText, CheckCircle2, AlertCircle, 
    ArrowUpRight, ShoppingBag, IndianRupee, X, Loader2 
} from 'lucide-react';

const PartnerCustomersView = ({ userInfo, onSelectCustomerForOrder }) => {
    const [customers, setCustomers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [searchTerm, setSearchTerm] = useState('');
    const [showAddModal, setShowAddModal] = useState(false);
    const [submitting, setSubmitting] = useState(false);
    const [statusFeedback, setStatusFeedback] = useState(null);

    const [formData, setFormData] = useState({
        name: '',
        email: '',
        phone: '',
        companyName: '',
        gstin: ''
    });

    useEffect(() => {
        fetchCustomers();
    }, []);

    const fetchCustomers = async () => {
        setLoading(true);
        setError('');
        try {
            const config = {
                headers: { Authorization: `Bearer ${userInfo.token}` }
            };
            const { data } = await axios.get('/api/partner/customers', config);
            setCustomers(data);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to fetch customer portfolio');
        } finally {
            setLoading(false);
        }
    };

    const handleAddCustomer = async (e) => {
        e.preventDefault();
        setSubmitting(true);
        setStatusFeedback(null);
        try {
            const config = {
                headers: { Authorization: `Bearer ${userInfo.token}` }
            };
            const { data } = await axios.post('/api/partner/customers', formData, config);
            
            setStatusFeedback({
                type: 'success',
                message: data.message || 'Customer saved successfully'
            });

            // Reset form
            setFormData({
                name: '',
                email: '',
                phone: '',
                companyName: '',
                gstin: ''
            });

            // Refresh customer list
            fetchCustomers();
            setTimeout(() => {
                setShowAddModal(false);
                setStatusFeedback(null);
            }, 2500);
        } catch (err) {
            setStatusFeedback({
                type: 'error',
                message: err.response?.data?.message || 'Failed to add customer.'
            });
        } finally {
            setSubmitting(false);
        }
    };

    const filteredCustomers = customers.filter(c => 
        c.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        c.email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        c.phone?.includes(searchTerm) ||
        c.companyName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        c.gstin?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const formatCurrency = (amount) => {
        return new Intl.NumberFormat('en-IN', {
            style: 'currency',
            currency: 'INR',
            maximumFractionDigits: 0
        }).format(amount || 0);
    };

    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Header Section */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Customer Portfolio</h1>
                    <p className="text-slate-500 text-sm mt-1">
                        Manage your linked clients, view engagement metrics, and onboard new businesses.
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <button 
                        onClick={fetchCustomers}
                        className="p-2.5 rounded-xl bg-white border border-slate-200 text-slate-500 hover:text-red-600 hover:border-red-100 transition-all shadow-sm"
                        title="Refresh Customers"
                    >
                        <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin text-red-600' : ''}`} />
                    </button>
                    <button
                        onClick={() => { setShowAddModal(true); setStatusFeedback(null); }}
                        className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-slate-900 text-white hover:bg-slate-800 text-sm font-black shadow-lg shadow-slate-200 transition-all"
                    >
                        <UserPlus className="w-4 h-4 text-red-500" />
                        Add Customer
                    </button>
                </div>
            </div>

            {/* Quick Metrics */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
                <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm flex items-center gap-5">
                    <div className="w-14 h-14 bg-indigo-50 rounded-2xl flex items-center justify-center text-indigo-600">
                        <Users className="w-7 h-7" />
                    </div>
                    <div>
                        <p className="text-slate-400 text-xs font-black uppercase tracking-wider">Total Customers</p>
                        <h4 className="text-2xl font-black text-slate-800 mt-1">{customers.length}</h4>
                    </div>
                </div>

                <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm flex items-center gap-5">
                    <div className="w-14 h-14 bg-emerald-50 rounded-2xl flex items-center justify-center text-emerald-600">
                        <ShoppingBag className="w-7 h-7" />
                    </div>
                    <div>
                        <p className="text-slate-400 text-xs font-black uppercase tracking-wider">Total Orders Placed</p>
                        <h4 className="text-2xl font-black text-slate-800 mt-1">
                            {customers.reduce((acc, c) => acc + (c.totalOrders || 0), 0)}
                        </h4>
                    </div>
                </div>

                <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm flex items-center gap-5">
                    <div className="w-14 h-14 bg-red-50 rounded-2xl flex items-center justify-center text-red-600">
                        <IndianRupee className="w-7 h-7" />
                    </div>
                    <div>
                        <p className="text-slate-400 text-xs font-black uppercase tracking-wider">Commission Generated</p>
                        <h4 className="text-2xl font-black text-green-600 mt-1">
                            {formatCurrency(customers.reduce((acc, c) => acc + (c.totalCommission || 0), 0))}
                        </h4>
                    </div>
                </div>
            </div>

            {/* Customer Table Container */}
            <div className="bg-white rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                <div className="p-6 md:p-8 border-b border-slate-100 flex flex-col md:flex-row items-center justify-between gap-4 bg-slate-50/30">
                    <div className="relative w-full md:w-96">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                        <input 
                            type="text" 
                            placeholder="Search by name, email, phone, company..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full pl-11 pr-4 py-2.5 rounded-xl bg-white border border-slate-200 text-xs font-semibold outline-none focus:border-red-500 transition shadow-sm"
                        />
                    </div>
                    <span className="text-xs font-bold text-slate-400">
                        Showing {filteredCustomers.length} of {customers.length} clients
                    </span>
                </div>

                {loading ? (
                    <div className="p-16 text-center">
                        <div className="w-10 h-10 border-4 border-slate-200 border-t-red-600 rounded-full animate-spin mx-auto mb-3"></div>
                        <p className="text-slate-500 text-sm font-bold">Loading customers...</p>
                    </div>
                ) : filteredCustomers.length > 0 ? (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-50/50">
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Customer Info</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Company & GSTIN</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Orders</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Total Spend</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Commission</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Action</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100 text-xs">
                                {filteredCustomers.map((c) => (
                                    <tr key={c._id} className="hover:bg-slate-50/50 transition-colors">
                                        <td className="px-8 py-5">
                                            <div className="flex items-center gap-3">
                                                <div className="w-10 h-10 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center font-bold text-sm shrink-0">
                                                    {(c.name || 'C').charAt(0).toUpperCase()}
                                                </div>
                                                <div>
                                                    <div className="font-black text-slate-900">{c.name}</div>
                                                    <div className="flex items-center gap-2 mt-0.5 text-[11px] text-slate-400 font-semibold">
                                                        <span className="flex items-center gap-1"><Mail className="w-3 h-3 text-slate-400" /> {c.email}</span>
                                                        {c.phone && <span className="flex items-center gap-1"><Phone className="w-3 h-3 text-slate-400" /> {c.phone}</span>}
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-8 py-5">
                                            <div className="font-bold text-slate-700">{c.companyName || 'Individual Client'}</div>
                                            {c.gstin && (
                                                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wide mt-0.5">
                                                    GST: {c.gstin}
                                                </div>
                                            )}
                                        </td>
                                        <td className="px-8 py-5 text-center font-bold text-slate-700">
                                            <span className="px-2.5 py-1 rounded-full bg-slate-100 text-slate-800 text-xs font-black">
                                                {c.totalOrders || 0}
                                            </span>
                                        </td>
                                        <td className="px-8 py-5 text-right font-bold text-slate-900">
                                            {formatCurrency(c.totalSpend)}
                                        </td>
                                        <td className="px-8 py-5 text-right font-black text-green-600">
                                            {formatCurrency(c.totalCommission)}
                                        </td>
                                        <td className="px-8 py-5 text-center">
                                            <button
                                                onClick={() => onSelectCustomerForOrder && onSelectCustomerForOrder(c)}
                                                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 text-white hover:bg-red-600 text-xs font-bold transition shadow-sm"
                                            >
                                                <ShoppingBag className="w-3.5 h-3.5" />
                                                Book Order
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <div className="p-16 text-center">
                        <div className="w-14 h-14 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3">
                            <Users className="w-7 h-7 text-slate-300" />
                        </div>
                        <h4 className="font-bold text-slate-800 text-base">No Customers Found</h4>
                        <p className="text-slate-400 text-xs max-w-sm mx-auto mt-1">
                            {searchTerm ? 'No customers match your search query.' : 'Click "Add Customer" above to onboard your first business client.'}
                        </p>
                    </div>
                )}
            </div>

            {/* Add Customer Modal */}
            {showAddModal && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-fade-in">
                    <div className="bg-white rounded-[32px] shadow-2xl max-w-lg w-full overflow-hidden border border-slate-100 animate-in zoom-in-95 duration-200">
                        <div className="bg-slate-950 p-6 sm:p-8 flex items-center justify-between border-b-4 border-red-600">
                            <div>
                                <h3 className="text-white text-lg font-black tracking-tight">Onboard New Customer</h3>
                                <p className="text-slate-400 text-xs font-semibold mt-1">
                                    Adds client to your portfolio & sends customer dashboard login access.
                                </p>
                            </div>
                            <button 
                                onClick={() => setShowAddModal(false)}
                                className="p-2 text-slate-400 hover:text-white transition rounded-xl"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        <form onSubmit={handleAddCustomer} className="p-6 sm:p-8 space-y-4">
                            {statusFeedback && (
                                <div className={`p-4 rounded-2xl text-xs font-bold flex items-start gap-3 ${
                                    statusFeedback.type === 'success' 
                                        ? 'bg-green-50 text-green-700 border border-green-200' 
                                        : 'bg-red-50 text-red-600 border border-red-200'
                                }`}>
                                    {statusFeedback.type === 'success' ? (
                                        <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-green-600" />
                                    ) : (
                                        <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
                                    )}
                                    <span>{statusFeedback.message}</span>
                                </div>
                            )}

                            <div className="space-y-1.5">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                    Full Name *
                                </label>
                                <input 
                                    type="text" 
                                    required
                                    placeholder="e.g. Ramesh Kumar"
                                    value={formData.name}
                                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                    className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
                                />
                            </div>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                        Email Address *
                                    </label>
                                    <input 
                                        type="email" 
                                        required
                                        placeholder="ramesh@company.com"
                                        value={formData.email}
                                        onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                                        className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
                                    />
                                </div>

                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                        Phone Number *
                                    </label>
                                    <input 
                                        type="tel" 
                                        required
                                        placeholder="10 digit phone number"
                                        value={formData.phone}
                                        onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                                        className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
                                    />
                                </div>
                            </div>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                        Company Name (Optional)
                                    </label>
                                    <input 
                                        type="text" 
                                        placeholder="ABC Technologies Pvt Ltd"
                                        value={formData.companyName}
                                        onChange={(e) => setFormData({ ...formData, companyName: e.target.value })}
                                        className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
                                    />
                                </div>

                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                        GSTIN (Optional)
                                    </label>
                                    <input 
                                        type="text" 
                                        placeholder="36AAAAA0000A1Z5"
                                        value={formData.gstin}
                                        onChange={(e) => setFormData({ ...formData, gstin: e.target.value.toUpperCase() })}
                                        className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs uppercase transition"
                                    />
                                </div>
                            </div>

                            <div className="p-3 bg-slate-50 rounded-xl border border-slate-100 text-[11px] text-slate-500 font-medium">
                                ℹ️ Dual Check: If client already exists on VR HERE without a partner, they will be securely mapped to you. If brand new, a customer dashboard access setup email will be automatically sent.
                            </div>

                            <div className="flex items-center gap-3 pt-4 border-t border-slate-100">
                                <button
                                    type="button"
                                    onClick={() => setShowAddModal(false)}
                                    className="flex-1 py-3 rounded-xl bg-slate-100 text-slate-600 font-bold hover:bg-slate-200 text-xs transition"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={submitting}
                                    className="flex-1 py-3 rounded-xl bg-slate-900 text-white font-bold hover:bg-slate-800 shadow-xl shadow-slate-200 text-xs transition flex items-center justify-center gap-2"
                                >
                                    {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Register Client'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default PartnerCustomersView;
