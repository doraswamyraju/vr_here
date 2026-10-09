import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { 
    ShoppingBag, Plus, Search, RefreshCw, CheckCircle2, 
    AlertCircle, FileText, IndianRupee, Loader2, ArrowUpRight, 
    Calendar, User, Layers, ShieldCheck, X, UserPlus, Filter, 
    Sparkles, ArrowLeft, Check, Star, Info, ChevronRight, HelpCircle
} from 'lucide-react';
import { MENU_DATA, getServiceLink } from '../SharedComponents';
import { SERVICE_CATALOG } from '../../data/serviceCatalog';
import { fetchServicePageConfig } from '../../modules/service-editor/v1.1/services/serviceConfigApi';

const formatCurrency = (amount) => {
    if (typeof amount === 'string' && (amount.includes('₹') || isNaN(Number(amount.replace(/[^0-9]/g, ''))))) {
        return amount;
    }
    const num = Number(String(amount).replace(/[^0-9]/g, '')) || 0;
    return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(num);
};

const PartnerMasterOrdersView = ({ userInfo, initialSelectedCustomer, onClearInitialCustomer }) => {
    const [orders, setOrders] = useState([]);
    const [customers, setCustomers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeViewTab, setActiveViewTab] = useState('catalog'); // 'catalog' | 'orders'
    const [searchTerm, setSearchTerm] = useState('');
    const [searchCatalogQuery, setSearchCatalogQuery] = useState('');
    const [selectedCategory, setSelectedCategory] = useState('All');

    // Selected service for booking with packages
    const [selectedService, setSelectedService] = useState(null);
    const [serviceConfig, setServiceConfig] = useState(null);
    const [loadingConfig, setLoadingConfig] = useState(false);

    // Order booking form state
    const [selectedCustomer, setSelectedCustomer] = useState(initialSelectedCustomer?._id || '');
    const [selectedPackage, setSelectedPackage] = useState(null);
    const [customPrice, setCustomPrice] = useState('');
    const [customPackageName, setCustomPackageName] = useState('');
    const [submittingOrder, setSubmittingOrder] = useState(false);
    const [bookingFeedback, setBookingFeedback] = useState(null);

    // Quick inline client onboarding
    const [showInlineAddClient, setShowInlineAddClient] = useState(false);
    const [inlineClientForm, setInlineClientForm] = useState({ name: '', email: '', phone: '', companyName: '', gstin: '' });
    const [inlineClientSubmitting, setInlineClientSubmitting] = useState(false);
    const [inlineClientFeedback, setInlineClientFeedback] = useState(null);

    const commissionRate = userInfo?.commissionPercentage || 10;

    useEffect(() => {
        fetchInitialData();
    }, []);

    useEffect(() => {
        if (initialSelectedCustomer) {
            setSelectedCustomer(initialSelectedCustomer._id);
            setActiveViewTab('catalog');
        }
    }, [initialSelectedCustomer]);

    const fetchInitialData = async () => {
        setLoading(true);
        try {
            const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
            const [ordersRes, customersRes] = await Promise.all([
                axios.get('/api/partner/orders', config),
                axios.get('/api/partner/customers', config)
            ]);
            setOrders(ordersRes.data || []);
            setCustomers(customersRes.data || []);

            if (customersRes.data?.length > 0 && !selectedCustomer) {
                setSelectedCustomer(customersRes.data[0]._id);
            }
        } catch (err) {
            console.error('Error fetching partner data:', err);
        } finally {
            setLoading(false);
        }
    };

    // Load package configuration whenever a service is picked
    useEffect(() => {
        if (!selectedService) {
            setServiceConfig(null);
            setSelectedPackage(null);
            return;
        }

        let isMounted = true;
        const loadServiceConfig = async () => {
            setLoadingConfig(true);
            const slug = selectedService.slug || getServiceLink(selectedService.title).replace(/^\//, '');
            try {
                let resolvedConfig = null;
                try {
                    const apiData = await fetchServicePageConfig(slug);
                    if (apiData && apiData.packages && apiData.packages.length > 0) {
                        resolvedConfig = apiData;
                    }
                } catch (e) {
                    // fallback to local catalog
                }

                if (!resolvedConfig && SERVICE_CATALOG[slug]) {
                    resolvedConfig = SERVICE_CATALOG[slug];
                }

                if (!resolvedConfig) {
                    const basePrice = 4999;
                    const defaultPackages = [
                        {
                            id: 'consultation',
                            name: 'Expert CA/CS Consultation',
                            price: 499,
                            isAdjustable: true,
                            description: `30 Mins direct consultation call & document eligibility assessment for ${selectedService.title}.`,
                            features: ['30 Mins Expert Call', 'Document Checklist Review', 'Filing Strategy & Roadmap', 'Fee 100% Adjusted in Final Order']
                        },
                        {
                            id: 'standard',
                            name: 'Standard Package',
                            price: basePrice,
                            isPopular: true,
                            description: `Complete standard registration, filing & certificate delivery for ${selectedService.title}.`,
                            features: [
                                'Complete Application Preparation & Drafting',
                                'Government Portal Filing & Document Submission',
                                'Dedicated CA Review & Compliance Check',
                                'Official Government Certificate Delivery',
                                'Standard Email & Call Support'
                            ]
                        },
                        {
                            id: 'premium',
                            name: 'Premium Fast-Track Enterprise',
                            price: basePrice * 2 + 1000,
                            description: 'All-inclusive VIP fast-track processing with allied licenses and priority support.',
                            features: [
                                'Fast-Track Priority Processing (24-48 Hrs)',
                                'Dedicated Senior CA & CS Manager',
                                'Allied License & MSME Registration Included',
                                'Permanent Digital Document Vault Storage',
                                '1-Year Free Annual Compliance Roadmap'
                            ]
                        }
                    ];
                    resolvedConfig = { packages: defaultPackages, title: selectedService.title };
                }

                if (isMounted && resolvedConfig) {
                    setServiceConfig(resolvedConfig);
                    const defaultPkg = (resolvedConfig.packages || []).find(p => p.isPopular) || (resolvedConfig.packages || [])[0];
                    if (defaultPkg) {
                        setSelectedPackage(defaultPkg);
                        setCustomPrice(String(defaultPkg.price || ''));
                        setCustomPackageName(defaultPkg.name || 'Standard');
                    }
                }
            } catch (err) {
                console.error('Failed to load service packages:', err);
            } finally {
                if (isMounted) {
                    setLoadingConfig(false);
                }
            }
        };

        loadServiceConfig();
        return () => { isMounted = false; };
    }, [selectedService]);


    const handleSelectPackageTier = (pkg) => {
        setSelectedPackage(pkg);
        setCustomPrice(String(pkg.price));
        setCustomPackageName(pkg.name);
    };

    const handleInlineAddCustomer = async (e) => {
        e.preventDefault();
        setInlineClientSubmitting(true);
        setInlineClientFeedback(null);
        try {
            const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
            const { data } = await axios.post('/api/partner/customers', inlineClientForm, config);
            
            const custRes = await axios.get('/api/partner/customers', config);
            setCustomers(custRes.data || []);
            
            if (data.customer?._id) {
                setSelectedCustomer(data.customer._id);
            }

            setInlineClientFeedback({ type: 'success', message: data.message || 'Client added successfully!' });
            setTimeout(() => {
                setShowInlineAddClient(false);
                setInlineClientFeedback(null);
                setInlineClientForm({ name: '', email: '', phone: '', companyName: '', gstin: '' });
            }, 1800);
        } catch (err) {
            setInlineClientFeedback({ type: 'error', message: err.response?.data?.message || 'Failed to add client' });
        } finally {
            setInlineClientSubmitting(false);
        }
    };

    const handleConfirmOrderBooking = async (e) => {
        e.preventDefault();
        setSubmittingOrder(true);
        setBookingFeedback(null);

        if (!selectedCustomer) {
            setBookingFeedback({ type: 'error', message: 'Please select or onboard a customer first.' });
            setSubmittingOrder(false);
            return;
        }

        const priceNum = Number(customPrice);
        if (!priceNum || priceNum < 1) {
            setBookingFeedback({ type: 'error', message: 'Please specify a valid order price.' });
            setSubmittingOrder(false);
            return;
        }

        try {
            const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
            const payload = {
                customerId: selectedCustomer,
                serviceName: selectedService.title,
                packageName: customPackageName || selectedPackage?.name || 'Standard',
                price: priceNum
            };

            await axios.post('/api/partner/orders', payload, config);

            setBookingFeedback({
                type: 'success',
                message: 'Master Order booked successfully! Invoice & payment link emailed to client.'
            });

            // Refresh orders list
            const ordersRes = await axios.get('/api/partner/orders', config);
            setOrders(ordersRes.data || []);

            setTimeout(() => {
                setSelectedService(null);
                setBookingFeedback(null);
                setActiveViewTab('orders');
                if (onClearInitialCustomer) onClearInitialCustomer();
            }, 2500);
        } catch (err) {
            setBookingFeedback({
                type: 'error',
                message: err.response?.data?.message || 'Failed to book master order.'
            });
        } finally {
            setSubmittingOrder(false);
        }
    };

    // Filter categories and items based on search
    const filteredMenuData = useMemo(() => {
        let list = MENU_DATA;
        if (selectedCategory !== 'All') {
            list = list.filter(cat => cat.title.toLowerCase().includes(selectedCategory.toLowerCase()) || cat.id === selectedCategory);
        }
        if (!searchCatalogQuery.trim()) return list;

        const q = searchCatalogQuery.toLowerCase();
        return list
            .map((category) => ({
                ...category,
                columns: category.columns
                    .map((col) => ({
                        ...col,
                        items: col.items.filter((item) =>
                            item.toLowerCase().includes(q) ||
                            col.title?.toLowerCase().includes(q) ||
                            category.title.toLowerCase().includes(q)
                        ),
                    }))
                    .filter((col) => col.items.length > 0),
            }))
            .filter((cat) => cat.columns.length > 0);
    }, [searchCatalogQuery, selectedCategory]);

    const filteredOrders = orders.filter(o => 
        o.clientName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        o.serviceName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        o.paymentStatus?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        o.status?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const calculatedCommission = Math.round((Number(customPrice) || 0) * (commissionRate / 100));

    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            
            {/* Top Bar Navigation */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h1 className="text-2xl lg:text-3xl font-black text-slate-800 tracking-tight">
                        {selectedService ? 'Select Service Package' : 'Master Orders & Services'}
                    </h1>
                    <p className="text-slate-500 text-sm mt-1">
                        {selectedService 
                            ? `Choose the appropriate package level for ${selectedService.title} to book for your client.`
                            : 'Browse our full service catalogue with all multi-tier packages to book on behalf of your clients.'}
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <button 
                        onClick={fetchInitialData}
                        className="p-2.5 rounded-xl bg-white border border-slate-200 text-slate-500 hover:text-red-600 hover:border-red-100 transition-all shadow-sm"
                        title="Refresh Data"
                    >
                        <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin text-red-600' : ''}`} />
                    </button>
                    {!selectedService && (
                        <div className="flex items-center p-1 bg-slate-200/70 rounded-2xl">
                            <button
                                onClick={() => setActiveViewTab('catalog')}
                                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
                                    activeViewTab === 'catalog'
                                        ? 'bg-slate-900 text-white shadow-sm'
                                        : 'text-slate-600 hover:text-slate-900'
                                }`}
                            >
                                <Layers className="w-4 h-4" />
                                Browse Catalog
                            </button>
                            <button
                                onClick={() => setActiveViewTab('orders')}
                                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
                                    activeViewTab === 'orders'
                                        ? 'bg-slate-900 text-white shadow-sm'
                                        : 'text-slate-600 hover:text-slate-900'
                                }`}
                            >
                                <ShoppingBag className="w-4 h-4" />
                                Booked Orders ({orders.length})
                            </button>
                        </div>
                    )}
                </div>
            </div>

            {/* VIEW 1: PACKAGE SELECTION & BOOKING FOR SELECTED SERVICE */}
            {selectedService ? (
                <div className="space-y-6 animate-in fade-in zoom-in-95 duration-200">
                    <button
                        onClick={() => setSelectedService(null)}
                        className="inline-flex items-center gap-2 text-slate-500 hover:text-slate-900 font-bold text-xs transition"
                    >
                        <ArrowLeft className="w-4 h-4" /> Back to Services Catalogue
                    </button>

                    {/* Service Header Banner */}
                    <div className="bg-slate-950 text-white rounded-[32px] p-8 md:p-10 relative overflow-hidden shadow-xl border border-slate-800">
                        <div className="absolute right-0 top-0 translate-x-12 -translate-y-12 w-64 h-64 bg-red-600/15 rounded-full blur-3xl"></div>
                        <div className="relative z-10 max-w-2xl">
                            <div className="inline-flex items-center gap-2 px-3 py-1 bg-white/10 border border-white/20 rounded-full text-[10px] font-black uppercase tracking-wider text-red-400 mb-3">
                                <Sparkles className="w-3.5 h-3.5" />
                                Official CA / CS & Ministry Filing
                            </div>
                            <h2 className="text-2xl md:text-3xl font-black tracking-tight">{selectedService.title}</h2>
                            <p className="text-slate-400 text-xs md:text-sm mt-2 leading-relaxed">
                                Select package plan below to generate an automated invoice with payment gateway link sent directly to your client.
                            </p>
                        </div>
                    </div>

                    {/* Booking Form Card */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        {/* Left 2 Cols: Package Selection Cards */}
                        <div className="lg:col-span-2 space-y-6">
                            <div className="flex items-center justify-between">
                                <h3 className="text-lg font-black text-slate-900 tracking-tight">Available Package Plans</h3>
                                <span className="text-xs font-bold text-slate-400">
                                    {serviceConfig?.packages?.length || 3} options available
                                </span>
                            </div>

                            {loadingConfig ? (
                                <div className="p-16 text-center bg-white rounded-3xl border border-slate-100">
                                    <div className="w-10 h-10 border-4 border-slate-200 border-t-red-600 rounded-full animate-spin mx-auto mb-3"></div>
                                    <p className="text-slate-500 text-xs font-bold">Loading live package tiers...</p>
                                </div>
                            ) : (
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {(serviceConfig?.packages || []).map((pkg) => {
                                        const isSelected = selectedPackage?.id === pkg.id || selectedPackage?.name === pkg.name;
                                        return (
                                            <div
                                                key={pkg.id || pkg.name}
                                                onClick={() => handleSelectPackageTier(pkg)}
                                                className={`p-6 rounded-[28px] border-2 transition-all cursor-pointer flex flex-col justify-between relative ${
                                                    isSelected
                                                        ? 'bg-slate-900 text-white border-slate-900 shadow-xl shadow-slate-300 scale-[1.02]'
                                                        : 'bg-white text-slate-800 border-slate-200 hover:border-slate-300'
                                                }`}
                                            >
                                                {pkg.isPopular && (
                                                    <span className="absolute -top-3 right-6 px-3 py-1 bg-red-600 text-white rounded-full text-[9px] font-black uppercase tracking-wider shadow-sm">
                                                        Popular Choice
                                                    </span>
                                                )}

                                                <div>
                                                    <div className="flex items-center justify-between gap-2 mb-2">
                                                        <h4 className="text-base font-black tracking-tight">{pkg.name}</h4>
                                                        <div className={`w-5 h-5 rounded-full flex items-center justify-center ${isSelected ? 'bg-red-500 text-white' : 'border border-slate-300'}`}>
                                                            {isSelected && <Check className="w-3 h-3" />}
                                                        </div>
                                                    </div>

                                                    <p className={`text-xs mb-4 ${isSelected ? 'text-slate-400' : 'text-slate-500'}`}>
                                                        {pkg.description}
                                                    </p>

                                                    <div className="mb-4">
                                                        <span className="text-2xl font-black">
                                                            {formatCurrency(pkg.price)}
                                                        </span>
                                                        <span className={`text-[11px] ml-1.5 font-semibold ${isSelected ? 'text-slate-400' : 'text-slate-400'}`}>
                                                            + Govt fee at actuals
                                                        </span>
                                                    </div>

                                                    {pkg.features && pkg.features.length > 0 && (
                                                        <ul className="space-y-2 border-t pt-4 text-xs font-semibold border-slate-200/20">
                                                            {pkg.features.map((feat, idx) => (
                                                                <li key={idx} className="flex items-start gap-2">
                                                                    <CheckCircle2 className={`w-4 h-4 shrink-0 mt-0.5 ${isSelected ? 'text-red-400' : 'text-green-600'}`} />
                                                                    <span>{feat}</span>
                                                                </li>
                                                            ))}
                                                        </ul>
                                                    )}
                                                </div>

                                                <button
                                                    type="button"
                                                    className={`w-full mt-6 py-2.5 rounded-xl text-xs font-black transition ${
                                                        isSelected
                                                            ? 'bg-red-600 text-white hover:bg-red-700'
                                                            : 'bg-slate-100 text-slate-800 hover:bg-slate-200'
                                                    }`}
                                                >
                                                    {isSelected ? '✓ Selected' : 'Select Plan'}
                                                </button>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </div>

                        {/* Right Col: Client Selector, Price Tuning & Submit */}
                        <div className="bg-white rounded-[32px] p-6 md:p-8 border border-slate-100 shadow-sm space-y-5 self-start sticky top-6">
                            <h3 className="text-base font-black text-slate-900 tracking-tight">Order Booking Summary</h3>

                            {bookingFeedback && (
                                <div className={`p-4 rounded-2xl text-xs font-bold flex items-start gap-3 ${
                                    bookingFeedback.type === 'success' ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-600'
                                }`}>
                                    {bookingFeedback.type === 'success' ? <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-green-600" /> : <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />}
                                    <span>{bookingFeedback.message}</span>
                                </div>
                            )}

                            <form onSubmit={handleConfirmOrderBooking} className="space-y-4">
                                {/* Customer Picker */}
                                <div className="space-y-1.5">
                                    <div className="flex items-center justify-between">
                                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">
                                            Select Client *
                                        </label>
                                        <button
                                            type="button"
                                            onClick={() => setShowInlineAddClient(!showInlineAddClient)}
                                            className="text-xs font-bold text-red-600 hover:text-red-700 inline-flex items-center gap-1"
                                        >
                                            <UserPlus className="w-3.5 h-3.5" />
                                            {showInlineAddClient ? 'Hide Form' : '+ New Client'}
                                        </button>
                                    </div>

                                    {/* Inline Add Client Form */}
                                    {showInlineAddClient ? (
                                        <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-2">
                                            <p className="text-xs font-bold text-slate-800">Quick Client Onboard</p>
                                            {inlineClientFeedback && (
                                                <div className={`p-2 rounded-xl text-xs font-bold ${inlineClientFeedback.type === 'success' ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-600'}`}>
                                                    {inlineClientFeedback.message}
                                                </div>
                                            )}
                                            <input
                                                type="text"
                                                required
                                                placeholder="Client Name *"
                                                value={inlineClientForm.name}
                                                onChange={(e) => setInlineClientForm({ ...inlineClientForm, name: e.target.value })}
                                                className="w-full p-2 border rounded-xl text-xs bg-white"
                                            />
                                            <input
                                                type="email"
                                                required
                                                placeholder="Email Address *"
                                                value={inlineClientForm.email}
                                                onChange={(e) => setInlineClientForm({ ...inlineClientForm, email: e.target.value })}
                                                className="w-full p-2 border rounded-xl text-xs bg-white"
                                            />
                                            <input
                                                type="tel"
                                                required
                                                placeholder="Phone Number *"
                                                value={inlineClientForm.phone}
                                                onChange={(e) => setInlineClientForm({ ...inlineClientForm, phone: e.target.value })}
                                                className="w-full p-2 border rounded-xl text-xs bg-white"
                                            />
                                            <div className="flex justify-end gap-2 pt-1">
                                                <button
                                                    type="button"
                                                    onClick={() => setShowInlineAddClient(false)}
                                                    className="px-3 py-1 text-xs font-bold text-slate-600"
                                                >
                                                    Cancel
                                                </button>
                                                <button
                                                    type="button"
                                                    onClick={handleInlineAddCustomer}
                                                    disabled={inlineClientSubmitting}
                                                    className="px-3 py-1 bg-red-600 text-white rounded-lg text-xs font-bold"
                                                >
                                                    {inlineClientSubmitting ? 'Saving...' : 'Save Client'}
                                                </button>
                                            </div>
                                        </div>
                                    ) : customers.length > 0 ? (
                                        <select
                                            required
                                            value={selectedCustomer}
                                            onChange={(e) => setSelectedCustomer(e.target.value)}
                                            className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 border border-slate-200 text-xs font-bold outline-none focus:border-red-500"
                                        >
                                            <option value="">-- Choose Client --</option>
                                            {customers.map(c => (
                                                <option key={c._id} value={c._id}>
                                                    {c.name} ({c.email}) {c.companyName ? `- ${c.companyName}` : ''}
                                                </option>
                                            ))}
                                        </select>
                                    ) : (
                                        <button
                                            type="button"
                                            onClick={() => setShowInlineAddClient(true)}
                                            className="w-full py-3 bg-amber-50 border border-amber-200 text-amber-800 rounded-xl text-xs font-bold"
                                        >
                                            + Onboard First Client
                                        </button>
                                    )}
                                </div>

                                {/* Custom Package Name & Price Tuning */}
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">
                                        Package Tier Label
                                    </label>
                                    <input
                                        type="text"
                                        required
                                        value={customPackageName}
                                        onChange={(e) => setCustomPackageName(e.target.value)}
                                        className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-slate-200 text-xs font-bold outline-none focus:border-red-500"
                                    />
                                </div>

                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">
                                        Order Price (₹) *
                                    </label>
                                    <input
                                        type="number"
                                        required
                                        min="1"
                                        value={customPrice}
                                        onChange={(e) => setCustomPrice(e.target.value)}
                                        className="w-full px-3.5 py-2 rounded-xl bg-slate-50 border border-slate-200 text-xs font-bold outline-none focus:border-red-500"
                                    />
                                </div>

                                {/* Commission Preview */}
                                <div className="p-4 bg-indigo-50/70 rounded-2xl border border-indigo-100 flex items-center justify-between">
                                    <div>
                                        <p className="text-[10px] font-black uppercase text-indigo-700">
                                            Partner Commission ({commissionRate}%)
                                        </p>
                                        <p className="text-[11px] text-indigo-900/80 font-medium">Credited upon client payment</p>
                                    </div>
                                    <span className="text-lg font-black text-indigo-700">
                                        {formatCurrency(calculatedCommission)}
                                    </span>
                                </div>

                                <button
                                    type="submit"
                                    disabled={submittingOrder || !selectedCustomer}
                                    className="w-full py-3.5 rounded-2xl bg-slate-900 hover:bg-slate-800 text-white font-black text-xs shadow-xl shadow-slate-200 transition flex items-center justify-center gap-2 disabled:opacity-50"
                                >
                                    {submittingOrder ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Confirm Booking & Send Invoice'}
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            ) : activeViewTab === 'catalog' ? (
                /* VIEW 2: FULL SERVICES CATALOGUE GRID (SIMILAR TO CUSTOMER PANEL) */
                <div className="space-y-6">
                    {/* Search Bar & Categories */}
                    <div className="bg-white rounded-[32px] p-6 md:p-8 border border-slate-100 shadow-sm space-y-4">
                        <div className="relative">
                            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                            <input
                                type="text"
                                placeholder="Search for legal, registration, tax, certification, MSME or industrial services..."
                                value={searchCatalogQuery}
                                onChange={(e) => setSearchCatalogQuery(e.target.value)}
                                className="w-full pl-12 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl text-sm font-semibold outline-none focus:border-red-500 focus:bg-white transition"
                            />
                            {searchCatalogQuery && (
                                <button onClick={() => setSearchCatalogQuery('')} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600">
                                    <X className="w-4 h-4" />
                                </button>
                            )}
                        </div>

                        {/* Category filter pills */}
                        <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-100">
                            {['All', ...MENU_DATA.map(m => m.title.split(' ')[0])].map((cat) => (
                                <button
                                    key={cat}
                                    onClick={() => setSelectedCategory(cat)}
                                    className={`px-4 py-1.5 rounded-full text-xs font-bold transition-all ${
                                        selectedCategory === cat
                                            ? 'bg-slate-900 text-white shadow-sm'
                                            : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                                    }`}
                                >
                                    {cat}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Categorized Service Columns */}
                    <div className="space-y-8">
                        {filteredMenuData.map((category) => (
                            <div key={category.id} className="bg-white rounded-[32px] p-6 md:p-8 border border-slate-100 shadow-sm space-y-6">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-xl bg-red-50 text-red-600 flex items-center justify-center font-bold">
                                        <Layers className="w-5 h-5" />
                                    </div>
                                    <div>
                                        <h3 className="text-lg font-black text-slate-900 tracking-tight">{category.title}</h3>
                                        <p className="text-slate-400 text-xs font-medium">Click any service to configure package tier and book</p>
                                    </div>
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                    {category.columns.map((col, idx) => (
                                        <div key={idx} className="bg-slate-50/70 p-5 rounded-2xl border border-slate-100 space-y-3">
                                            <h4 className="text-xs font-black uppercase text-slate-500 tracking-wider pb-2 border-b border-slate-200/60">
                                                {col.title}
                                            </h4>
                                            <div className="space-y-1.5">
                                                {col.items.map((item) => (
                                                    <div
                                                        key={item}
                                                        onClick={() => {
                                                            const computedLink = getServiceLink(item);
                                                            const slug = computedLink ? computedLink.replace(/^\//, '') : item.toLowerCase().replace(/[^a-z0-9]+/g, '-');
                                                            setSelectedService({ title: item, slug });
                                                        }}
                                                        className="p-2.5 rounded-xl bg-white border border-slate-200/80 hover:border-red-500 hover:bg-red-50/40 transition cursor-pointer flex items-center justify-between group"
                                                    >
                                                        <span className="text-xs font-bold text-slate-800 group-hover:text-red-700 transition line-clamp-1">
                                                            {item}
                                                        </span>
                                                        <ChevronRight className="w-4 h-4 text-slate-300 group-hover:text-red-600 shrink-0 transition-transform group-hover:translate-x-0.5" />
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            ) : (
                /* VIEW 3: BOOKED ORDERS TABLE */
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
                            {filteredOrders.length} orders recorded
                        </span>
                    </div>

                    {filteredOrders.length > 0 ? (
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
                                Select a service from the catalogue tab to place your first booking.
                            </p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default PartnerMasterOrdersView;
