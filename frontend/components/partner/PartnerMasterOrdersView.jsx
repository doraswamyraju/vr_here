import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    ShoppingBag, Plus, Search, RefreshCw, CheckCircle2, 
    AlertCircle, FileText, IndianRupee, Loader2, ArrowUpRight, 
    Calendar, User, Layers, ShieldCheck, X
} from 'lucide-react';

const COMMON_SERVICES = [
    { name: 'Private Limited Company Incorporation', defaultPrice: 6999 },
    { name: 'Limited Liability Partnership (LLP) Registration', defaultPrice: 4999 },
    { name: 'One Person Company (OPC) Registration', defaultPrice: 5499 },
    { name: 'GST Registration', defaultPrice: 1499 },
    { name: 'GST Monthly / Quarterly Return Filing (Annual)', defaultPrice: 9999 },
    { name: 'Income Tax Return (ITR) Filing - Business', defaultPrice: 3499 },
    { name: 'Trademark Registration & Filing', defaultPrice: 4500 },
    { name: 'Startup India & MSME / Udyam Registration', defaultPrice: 1999 },
    { name: 'Annual Company Secretarial Compliance (ROC)', defaultPrice: 11999 },
    { name: 'Bookkeeping & Monthly Accounting Retainer', defaultPrice: 14999 },
    { name: 'Custom Legal / Financial Advisory Retainer', defaultPrice: 8000 }
];

const PartnerMasterOrdersView = ({ userInfo, initialSelectedCustomer, onClearInitialCustomer }) => {
    const [orders, setOrders] = useState([]);
    const [customers, setCustomers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [showBookingModal, setShowBookingModal] = useState(false);
    const [submitting, setSubmitting] = useState(false);
    const [feedback, setFeedback] = useState(null);

    const [bookingForm, setBookingForm] = useState({
        customerId: '',
        serviceName: COMMON_SERVICES[0].name,
        packageName: 'Partner Professional',
        price: COMMON_SERVICES[0].defaultPrice
    });

    const commissionRate = userInfo?.commissionPercentage || 10;

    useEffect(() => {
        fetchInitialData();
    }, []);

    useEffect(() => {
        if (initialSelectedCustomer) {
            setBookingForm(prev => ({
                ...prev,
                customerId: initialSelectedCustomer._id
            }));
            setShowBookingModal(true);
        }
    }, [initialSelectedCustomer]);

    const fetchInitialData = async () => {
        setLoading(true);
        try {
            const config = {
                headers: { Authorization: `Bearer ${userInfo.token}` }
            };
            const [ordersRes, customersRes] = await Promise.all([
                axios.get('/api/partner/orders', config),
                axios.get('/api/partner/customers', config)
            ]);
            setOrders(ordersRes.data || []);
            setCustomers(customersRes.data || []);

            if (customersRes.data?.length > 0 && !bookingForm.customerId) {
                setBookingForm(prev => ({
                    ...prev,
                    customerId: customersRes.data[0]._id
                }));
            }
        } catch (err) {
            console.error('Error fetching partner data:', err);
        } finally {
            setLoading(false);
        }
    };

    const handleServiceChange = (e) => {
        const selectedServiceName = e.target.value;
        const matched = COMMON_SERVICES.find(s => s.name === selectedServiceName);
        setBookingForm({
            ...bookingForm,
            serviceName: selectedServiceName,
            price: matched ? matched.defaultPrice : bookingForm.price
        });
    };

    const handleCreateOrder = async (e) => {
        e.preventDefault();
        setSubmitting(true);
        setFeedback(null);

        if (!bookingForm.customerId) {
            setFeedback({ type: 'error', message: 'Please select or onboard a customer first.' });
            setSubmitting(false);
            return;
        }

        try {
            const config = {
                headers: { Authorization: `Bearer ${userInfo.token}` }
            };
            await axios.post('/api/partner/orders', bookingForm, config);

            setFeedback({
                type: 'success',
                message: 'Master Order booked successfully! Invoice & payment link emailed to client.'
            });

            // Refresh orders list
            const ordersRes = await axios.get('/api/partner/orders', config);
            setOrders(ordersRes.data || []);

            setTimeout(() => {
                setShowBookingModal(false);
                setFeedback(null);
                if (onClearInitialCustomer) onClearInitialCustomer();
            }, 2500);
        } catch (err) {
            setFeedback({
                type: 'error',
                message: err.response?.data?.message || 'Failed to book master order.'
            });
        } finally {
            setSubmitting(false);
        }
    };

    const filteredOrders = orders.filter(o => 
        o.clientName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        o.serviceName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        o.paymentStatus?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        o.status?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const formatCurrency = (amount) => {
        return new Intl.NumberFormat('en-IN', {
            style: 'currency',
            currency: 'INR',
            maximumFractionDigits: 0
        }).format(amount || 0);
    };

    const calculatedCommission = Math.round((Number(bookingForm.price) || 0) * (commissionRate / 100));

    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Top Bar */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Master Orders</h1>
                    <p className="text-slate-500 text-sm mt-1">
                        Book service orders directly for your clients. Invoices & payment links are dispatched automatically.
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <button 
                        onClick={fetchInitialData}
                        className="p-2.5 rounded-xl bg-white border border-slate-200 text-slate-500 hover:text-red-600 hover:border-red-100 transition-all shadow-sm"
                        title="Refresh Orders"
                    >
                        <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin text-red-600' : ''}`} />
                    </button>
                    <button
                        onClick={() => { setShowBookingModal(true); setFeedback(null); }}
                        className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-slate-900 text-white hover:bg-slate-800 text-sm font-black shadow-lg shadow-slate-200 transition-all"
                    >
                        <Plus className="w-4 h-4 text-red-500" />
                        Place Master Order
                    </button>
                </div>
            </div>

            {/* Orders Ledger */}
            <div className="bg-white rounded-[32px] border border-slate-100 shadow-sm overflow-hidden">
                <div className="p-6 md:p-8 border-b border-slate-100 flex flex-col md:flex-row items-center justify-between gap-4 bg-slate-50/30">
                    <div className="relative w-full md:w-96">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                        <input 
                            type="text" 
                            placeholder="Search orders, clients, status..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full pl-11 pr-4 py-2.5 rounded-xl bg-white border border-slate-200 text-xs font-semibold outline-none focus:border-red-500 transition shadow-sm"
                        />
                    </div>
                    <span className="text-xs font-bold text-slate-400">
                        {filteredOrders.length} orders booked
                    </span>
                </div>

                {loading ? (
                    <div className="p-16 text-center">
                        <div className="w-10 h-10 border-4 border-slate-200 border-t-red-600 rounded-full animate-spin mx-auto mb-3"></div>
                        <p className="text-slate-500 text-sm font-bold">Loading master orders...</p>
                    </div>
                ) : filteredOrders.length > 0 ? (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-slate-50/50">
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Order ID & Date</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Customer</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100">Service Engaged</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Order Value</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-right">Your Commission</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Payment</th>
                                    <th className="px-8 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-100 text-center">Filing Status</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100 text-xs">
                                {filteredOrders.map((ord) => (
                                    <tr key={ord._id} className="hover:bg-slate-50/50 transition-colors">
                                        <td className="px-8 py-5">
                                            <div className="font-bold text-slate-900">
                                                #{ord._id.slice(-6).toUpperCase()}
                                            </div>
                                            <div className="text-[10px] text-slate-400 font-semibold mt-0.5">
                                                {ord.createdAt ? new Date(ord.createdAt).toLocaleDateString('en-IN', { dateStyle: 'medium' }) : 'N/A'}
                                            </div>
                                        </td>
                                        <td className="px-8 py-5">
                                            <div className="font-black text-slate-900">{ord.clientName || ord.user?.name || 'Customer'}</div>
                                            <div className="text-[10px] text-slate-400 font-semibold mt-0.5">
                                                {ord.email || ord.user?.email || ''}
                                            </div>
                                        </td>
                                        <td className="px-8 py-5">
                                            <div className="font-bold text-slate-800">{ord.serviceName}</div>
                                            <div className="text-[10px] text-slate-400 font-semibold">{ord.packageName || 'Standard'}</div>
                                        </td>
                                        <td className="px-8 py-5 text-right font-bold text-slate-900">
                                            {formatCurrency(ord.price)}
                                        </td>
                                        <td className="px-8 py-5 text-right font-black text-green-600">
                                            {formatCurrency(ord.partnerCommissionAmount)}
                                        </td>
                                        <td className="px-8 py-5 text-center">
                                            <span className={`inline-block px-2.5 py-1 rounded-full text-[9px] font-black uppercase tracking-wider ${
                                                ord.paymentStatus === 'Paid' 
                                                    ? 'bg-green-50 text-green-600 border border-green-200' 
                                                    : 'bg-amber-50 text-amber-600 border border-amber-200'
                                            }`}>
                                                {ord.paymentStatus || 'Pending'}
                                            </span>
                                        </td>
                                        <td className="px-8 py-5 text-center">
                                            <span className="inline-block px-2.5 py-1 rounded-full text-[9px] font-bold bg-slate-100 text-slate-700">
                                                {ord.status || 'In Progress'}
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
                            <ShoppingBag className="w-7 h-7 text-slate-300" />
                        </div>
                        <h4 className="font-bold text-slate-800 text-base">No Master Orders Found</h4>
                        <p className="text-slate-400 text-xs max-w-sm mx-auto mt-1">
                            Click "Place Master Order" to select a customer and book compliance or registration services.
                        </p>
                    </div>
                )}
            </div>

            {/* Place Master Order Modal */}
            {showBookingModal && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-fade-in">
                    <div className="bg-white rounded-[32px] shadow-2xl max-w-lg w-full overflow-hidden border border-slate-100 animate-in zoom-in-95 duration-200">
                        <div className="bg-slate-950 p-6 sm:p-8 flex items-center justify-between border-b-4 border-red-600">
                            <div>
                                <h3 className="text-white text-lg font-black tracking-tight">Place Master Order</h3>
                                <p className="text-slate-400 text-xs font-semibold mt-1">
                                    Create a service order on behalf of your client.
                                </p>
                            </div>
                            <button 
                                onClick={() => {
                                    setShowBookingModal(false);
                                    if (onClearInitialCustomer) onClearInitialCustomer();
                                }}
                                className="p-2 text-slate-400 hover:text-white transition rounded-xl"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        <form onSubmit={handleCreateOrder} className="p-6 sm:p-8 space-y-4">
                            {feedback && (
                                <div className={`p-4 rounded-2xl text-xs font-bold flex items-start gap-3 ${
                                    feedback.type === 'success' 
                                        ? 'bg-green-50 text-green-700 border border-green-200' 
                                        : 'bg-red-50 text-red-600 border border-red-200'
                                }`}>
                                    {feedback.type === 'success' ? (
                                        <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-green-600" />
                                    ) : (
                                        <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
                                    )}
                                    <span>{feedback.message}</span>
                                </div>
                            )}

                            {/* Customer Selector */}
                            <div className="space-y-1.5">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                    Select Customer *
                                </label>
                                {customers.length > 0 ? (
                                    <select
                                        required
                                        value={bookingForm.customerId}
                                        onChange={(e) => setBookingForm({ ...bookingForm, customerId: e.target.value })}
                                        className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
                                    >
                                        <option value="">-- Select Linked Customer --</option>
                                        {customers.map(c => (
                                            <option key={c._id} value={c._id}>
                                                {c.name} ({c.email}) {c.companyName ? `- ${c.companyName}` : ''}
                                            </option>
                                        ))}
                                    </select>
                                ) : (
                                    <div className="p-3 bg-amber-50 border border-amber-200 text-amber-700 rounded-xl text-xs font-bold">
                                        No linked customers found. Please go to Customers tab to onboard your client first.
                                    </div>
                                )}
                            </div>

                            {/* Service Picker */}
                            <div className="space-y-1.5">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                    Service Required *
                                </label>
                                <select
                                    required
                                    value={bookingForm.serviceName}
                                    onChange={handleServiceChange}
                                    className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
                                >
                                    {COMMON_SERVICES.map(s => (
                                        <option key={s.name} value={s.name}>
                                            {s.name} (Std: ₹{s.defaultPrice.toLocaleString('en-IN')})
                                        </option>
                                    ))}
                                </select>
                            </div>

                            {/* Package & Price */}
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                        Package Plan
                                    </label>
                                    <input 
                                        type="text" 
                                        required
                                        placeholder="e.g. Standard / Fast-Track"
                                        value={bookingForm.packageName}
                                        onChange={(e) => setBookingForm({ ...bookingForm, packageName: e.target.value })}
                                        className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
                                    />
                                </div>

                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">
                                        Order Price (INR) *
                                    </label>
                                    <input 
                                        type="number" 
                                        required
                                        min="1"
                                        value={bookingForm.price}
                                        onChange={(e) => setBookingForm({ ...bookingForm, price: e.target.value })}
                                        className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
                                    />
                                </div>
                            </div>

                            {/* Commission Calculation Preview */}
                            <div className="p-4 bg-indigo-50/70 rounded-2xl border border-indigo-100 flex items-center justify-between">
                                <div>
                                    <p className="text-[10px] font-black uppercase tracking-wider text-indigo-700">
                                        Estimated Partner Commission ({commissionRate}%)
                                    </p>
                                    <p className="text-xs text-indigo-900/80 font-medium mt-0.5">
                                        Credited directly to your wallet upon customer payment settlement.
                                    </p>
                                </div>
                                <div className="text-right">
                                    <span className="text-lg font-black text-indigo-700">
                                        {formatCurrency(calculatedCommission)}
                                    </span>
                                </div>
                            </div>

                            <div className="flex items-center gap-3 pt-4 border-t border-slate-100">
                                <button
                                    type="button"
                                    onClick={() => {
                                        setShowBookingModal(false);
                                        if (onClearInitialCustomer) onClearInitialCustomer();
                                    }}
                                    className="flex-1 py-3 rounded-xl bg-slate-100 text-slate-600 font-bold hover:bg-slate-200 text-xs transition"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={submitting || !bookingForm.customerId}
                                    className="flex-1 py-3 rounded-xl bg-slate-900 text-white font-bold hover:bg-slate-800 shadow-xl shadow-slate-200 text-xs transition flex items-center justify-center gap-2"
                                >
                                    {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Confirm & Send Invoice'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default PartnerMasterOrdersView;
