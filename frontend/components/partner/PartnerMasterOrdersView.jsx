import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    ShoppingBag, Plus, Search, RefreshCw, CheckCircle2, 
    AlertCircle, FileText, IndianRupee, Loader2, ArrowUpRight, 
    Calendar, User, Layers, ShieldCheck, X, UserPlus, Filter, Sparkles
} from 'lucide-react';

export const COMPREHENSIVE_CATALOG = [
    {
        category: 'Accounting, Tax & Compliance',
        services: [
            { name: 'Cloud Accounting & Bookkeeping Retainer', defaultPrice: 14999, description: 'Monthly book closing, ledger audit, Zoho/Tally' },
            { name: 'GST Return Filing (Monthly / Annual)', defaultPrice: 1499, description: 'GSTR-1, GSTR-3B monthly & annual reconciliation' },
            { name: 'Income Tax Return (ITR 1-7) Business Filing', defaultPrice: 2499, description: 'CA computation, filing & notice protection' },
            { name: 'Companies Compliance Scheme 2026 (CCFS)', defaultPrice: 7999, description: 'ROC amnesty regularisation & filings' },
            { name: 'Payroll Management & Payslips Support', defaultPrice: 4999, description: 'Monthly payroll, Form 16 & PT processing' },
            { name: 'Professional Tax (PT) Returns', defaultPrice: 1999, description: 'State-wise monthly / annual PT filing' },
            { name: 'EPFO & ESIC Monthly Returns', defaultPrice: 2999, description: 'PF/ESI monthly challans and returns' },
            { name: 'TDS / TCS Quarterly Return Filing', defaultPrice: 2499, description: 'Form 24Q, 26Q, 27Q filing & Form 16A' },
            { name: '12AA & 80G Tax Exemption Certificates', defaultPrice: 8999, description: 'NGO & Trust tax exemption certification' },
            { name: '15CA / 15CB Foreign Remittance Certification', defaultPrice: 3999, description: 'CA certificate for international remittances' },
            { name: 'Statutory / Internal Financial Audit', defaultPrice: 19999, description: 'Independent books audit & compliance report' },
            { name: 'GST Audit & Annual Reconciliation', defaultPrice: 14999, description: 'Comprehensive GSTR-9/9C audit' }
        ]
    },
    {
        category: 'Company Registration & Legal',
        services: [
            { name: 'Private Limited Company Incorporation', defaultPrice: 6999, description: 'COI, PAN, TAN, MOA, AOA, 2 DIN & DSCs' },
            { name: 'Limited Liability Partnership (LLP) Registration', defaultPrice: 4999, description: 'LLP agreement, DPIN, PAN & certificate' },
            { name: 'One Person Company (OPC) Registration', defaultPrice: 5499, description: 'Single promoter corporate incorporation' },
            { name: 'Partnership Firm Registration & Deed Drafting', defaultPrice: 4899, description: 'Partnership deed, ROF filing & PAN' },
            { name: 'Proprietorship Business Setup', defaultPrice: 1999, description: 'MSME, GST, Current account & Trade setup' },
            { name: 'Section 8 Non-Profit Company (NGO)', defaultPrice: 11999, description: 'Central Govt license & non-profit incorporation' },
            { name: 'Public Limited Company Incorporation', defaultPrice: 18999, description: '3+ Directors, 7+ Shareholders incorporation' },
            { name: 'Society & Trust Registration', defaultPrice: 14999, description: 'Trust deed drafting & Sub-Registrar registration' },
            { name: 'GST Registration', defaultPrice: 1499, description: 'New GSTIN generation within 3-7 working days' },
            { name: 'Udyam Registration (MSME)', defaultPrice: 999, description: 'Govt MSME classification certificate' },
            { name: 'Startup India Recognition & DPIIT', defaultPrice: 3999, description: 'Tax holiday & seed funding eligibility certificate' },
            { name: 'Import Export Code (IEC)', defaultPrice: 1999, description: 'DGFT lifetime export-import license' },
            { name: 'FSSAI Food License / Registration', defaultPrice: 2999, description: 'Basic, State or Central FSSAI food license' },
            { name: 'Shops & Establishment License (Gumasta)', defaultPrice: 2499, description: 'State municipal commercial license' },
            { name: 'Trade License & Municipal Clearances', defaultPrice: 3499, description: 'City municipal trade operation certificate' },
            { name: 'Pollution Control Board NOC (CFE / CFO)', defaultPrice: 14999, description: 'State PCB consent for industrial operations' },
            { name: 'Contract Labour & Factory License', defaultPrice: 14999, description: 'Factory inspectorate compliance & labour permit' },
            { name: 'ROC Annual Filings (AOC-4, MGT-7)', defaultPrice: 8999, description: 'Annual ROC compliance and return filing' },
            { name: 'Director KYC (DIR-3 KYC)', defaultPrice: 999, description: 'Mandatory annual MCA director KYC filing' },
            { name: 'Digital Signature Certificate (DSC Class 3)', defaultPrice: 1499, description: '2-Year validity Class 3 digital signature token' }
        ]
    },
    {
        category: 'Certifications & ISO Standards',
        services: [
            { name: 'ISO 9001:2015 - Quality Management System', defaultPrice: 6999, description: 'Internationally recognized quality standard' },
            { name: 'ISO 14001:2015 - Environmental Management', defaultPrice: 7499, description: 'Eco & environmental sustainability standard' },
            { name: 'ISO 45001:2018 - Occupational Health & Safety', defaultPrice: 7999, description: 'Workplace safety & hazard risk prevention' },
            { name: 'ISO 22000:2018 - Food Safety Management', defaultPrice: 8999, description: 'HACCP & food chain safety compliance' },
            { name: 'ISO 27001:2022 - Information Security (ISMS)', defaultPrice: 14999, description: 'Data protection & cybersecurity accreditation' },
            { name: 'ISO 13485:2016 - Medical Devices Standard', defaultPrice: 12999, description: 'Medical equipment manufacturing certification' },
            { name: 'ISO 50001:2018 - Energy Management System', defaultPrice: 8999, description: 'Energy performance & optimization standard' },
            { name: 'GMP / HACCP Certification', defaultPrice: 9999, description: 'Good Manufacturing Practices audit & certificate' },
            { name: 'CE Marking Certification', defaultPrice: 18999, description: 'European Union health & safety conformity mark' },
            { name: 'ISI / BIS Mark Certification Support', defaultPrice: 24999, description: 'Bureau of Indian Standards product testing' },
            { name: 'FDA Compliance & Registration Support', defaultPrice: 29999, description: 'US FDA facility & product listing compliance' },
            { name: 'Halal & Kosher Certification', defaultPrice: 14999, description: 'Global export religious dietary certification' }
        ]
    },
    {
        category: 'Government, GeM & MSME Subsidies',
        services: [
            { name: 'GeM Seller & Service Provider Registration', defaultPrice: 2999, description: 'Govt e-Marketplace primary seller onboarding' },
            { name: 'GeM OEM Panel & Brand Approval', defaultPrice: 6999, description: 'Manufacturer catalog, OEM panel & brand listing' },
            { name: 'GeM Tender Management & Bid Participation', defaultPrice: 9999, description: 'Govt tender bidding, technical evaluation support' },
            { name: 'Detailed Project Report (DPR) Preparation', defaultPrice: 14999, description: 'Bankable DPR for industrial plant & machinery' },
            { name: 'CMA Data Preparation for Bank Loans', defaultPrice: 7999, description: 'Credit Monitoring Arrangement data for CC/OD' },
            { name: 'Bank Loan File Support (Term Loan & Working Capital)', defaultPrice: 19999, description: 'End-to-end bank loan proposal structuring' },
            { name: 'CGTMSE Collateral-Free Loan Scheme', defaultPrice: 14999, description: 'MSME credit guarantee scheme documentation' },
            { name: 'PMEGP Govt Subsidy Loan Scheme (Up to 35%)', defaultPrice: 11999, description: 'KVIC / DIC subsidy project loan documentation' },
            { name: 'MUDRA Business Loan Support (Shishu/Kishor/Tarun)', defaultPrice: 4999, description: 'Govt micro-enterprise credit loan scheme' },
            { name: 'MSME ZED Scheme Certification (Bronze/Silver/Gold)', defaultPrice: 8999, description: 'Zero Defect Zero Effect subsidy scheme' },
            { name: 'PMFME Food Processing Subsidy Support', defaultPrice: 14999, description: '35% credit-linked capital subsidy for food units' },
            { name: 'TReDS Bill Discounting Portal Setup', defaultPrice: 3499, description: 'Invoice financing onboarding on RXIL/M1xchange' }
        ]
    },
    {
        category: 'Branding, Advisory & Plant Setup',
        services: [
            { name: 'Trademark Registration & Filing (Per Class)', defaultPrice: 4500, description: 'Brand name & logo protection with Govt registry' },
            { name: 'Investor Pitch Deck Preparation', defaultPrice: 12499, description: 'Fundraising ready presentation & financials' },
            { name: 'Institutional Business Plan Preparation', defaultPrice: 9999, description: 'Market research, projections & operational roadmap' },
            { name: 'Corporate HR Policy & SOP Documentation', defaultPrice: 9999, description: 'Standard Operating Procedures & employee manual' },
            { name: 'Commercial Business & Factory Insurance', defaultPrice: 4999, description: 'Asset, stock, fire & liability policy consulting' },
            { name: 'Industrial Machinery Sourcing & Vendor Audit', defaultPrice: 24999, description: 'Machine specifications, supplier verification' },
            { name: 'Turnkey Plant Engineering & Feasibility Analysis', defaultPrice: 49999, description: 'Complete industrial plant setup consulting' }
        ]
    }
];

const PartnerMasterOrdersView = ({ userInfo, initialSelectedCustomer, onClearInitialCustomer }) => {
    const [orders, setOrders] = useState([]);
    const [customers, setCustomers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [showBookingModal, setShowBookingModal] = useState(false);
    const [submitting, setSubmitting] = useState(false);
    const [feedback, setFeedback] = useState(null);

    // Quick inline customer adding state within modal
    const [showInlineCustomerAdd, setShowInlineCustomerAdd] = useState(false);
    const [inlineCustomer, setInlineCustomer] = useState({ name: '', email: '', phone: '', companyName: '', gstin: '' });
    const [inlineSubmitting, setInlineSubmitting] = useState(false);
    const [inlineFeedback, setInlineFeedback] = useState(null);

    // Catalog filtering state inside booking modal
    const [catalogCategory, setCatalogCategory] = useState('All');
    const [catalogSearch, setCatalogSearch] = useState('');

    const [bookingForm, setBookingForm] = useState({
        customerId: '',
        serviceName: COMPREHENSIVE_CATALOG[0].services[0].name,
        packageName: 'Standard Professional',
        price: COMPREHENSIVE_CATALOG[0].services[0].defaultPrice
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

    const handleSelectCatalogService = (service) => {
        setBookingForm({
            ...bookingForm,
            serviceName: service.name,
            price: service.defaultPrice
        });
    };

    const handleInlineAddCustomer = async (e) => {
        e.preventDefault();
        setInlineSubmitting(true);
        setInlineFeedback(null);
        try {
            const config = { headers: { Authorization: `Bearer ${userInfo.token}` } };
            const { data } = await axios.post('/api/partner/customers', inlineCustomer, config);
            
            // Refresh customer list
            const custRes = await axios.get('/api/partner/customers', config);
            setCustomers(custRes.data || []);
            
            const newlyCreated = data.customer;
            if (newlyCreated) {
                setBookingForm(prev => ({ ...prev, customerId: newlyCreated._id }));
            }

            setInlineFeedback({ type: 'success', message: data.message || 'Customer onboarded!' });
            setTimeout(() => {
                setShowInlineCustomerAdd(false);
                setInlineFeedback(null);
                setInlineCustomer({ name: '', email: '', phone: '', companyName: '', gstin: '' });
            }, 1800);
        } catch (err) {
            setInlineFeedback({ type: 'error', message: err.response?.data?.message || 'Failed to onboard customer' });
        } finally {
            setInlineSubmitting(false);
        }
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

    const allServicesFlattened = COMPREHENSIVE_CATALOG.flatMap(cat => 
        cat.services.map(s => ({ ...s, category: cat.category }))
    );

    const filteredCatalogServices = allServicesFlattened.filter(s => {
        const matchesCategory = catalogCategory === 'All' || s.category === catalogCategory;
        const matchesSearch = !catalogSearch || 
            s.name.toLowerCase().includes(catalogSearch.toLowerCase()) || 
            s.description?.toLowerCase().includes(catalogSearch.toLowerCase());
        return matchesCategory && matchesSearch;
    });

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
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Master Orders Booking</h1>
                    <p className="text-slate-500 text-sm mt-1">
                        Select any service from our complete catalogue to book on behalf of your clients with automated invoice generation.
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
                            Click "Place Master Order" to select a customer and choose from the complete VR HERE service catalogue.
                        </p>
                    </div>
                )}
            </div>

            {/* Place Master Order Modal */}
            {showBookingModal && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-fade-in">
                    <div className="bg-white rounded-[32px] shadow-2xl max-w-2xl w-full overflow-hidden border border-slate-100 animate-in zoom-in-95 duration-200 max-h-[90vh] flex flex-col">
                        <div className="bg-slate-950 p-6 flex items-center justify-between border-b-4 border-red-600 shrink-0">
                            <div>
                                <h3 className="text-white text-lg font-black tracking-tight flex items-center gap-2">
                                    <Sparkles className="w-4 h-4 text-red-500" />
                                    Book Master Order
                                </h3>
                                <p className="text-slate-400 text-xs font-semibold mt-0.5">
                                    Full service catalog with instant invoice generation & dispatch.
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

                        <div className="p-6 overflow-y-auto space-y-5 flex-1">
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

                            {/* Customer Selector Section */}
                            <div className="space-y-2">
                                <div className="flex items-center justify-between">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">
                                        Select Customer *
                                    </label>
                                    <button
                                        type="button"
                                        onClick={() => setShowInlineCustomerAdd(!showInlineCustomerAdd)}
                                        className="text-xs font-bold text-red-600 hover:text-red-700 inline-flex items-center gap-1"
                                    >
                                        <UserPlus className="w-3.5 h-3.5" />
                                        {showInlineCustomerAdd ? 'Hide Onboarding Form' : '+ Onboard New Client'}
                                    </button>
                                </div>

                                {/* Inline Customer Onboarding Sub-Form */}
                                {showInlineCustomerAdd ? (
                                    <form onSubmit={handleInlineAddCustomer} className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-3 animate-in fade-in duration-200">
                                        <p className="text-xs font-bold text-slate-800">Quick Client Onboarding</p>
                                        {inlineFeedback && (
                                            <div className={`p-2.5 rounded-xl text-xs font-bold ${inlineFeedback.type === 'success' ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-600'}`}>
                                                {inlineFeedback.message}
                                            </div>
                                        )}
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                            <input
                                                type="text"
                                                required
                                                placeholder="Client Name *"
                                                value={inlineCustomer.name}
                                                onChange={(e) => setInlineCustomer({ ...inlineCustomer, name: e.target.value })}
                                                className="p-2 border rounded-xl border-slate-200 text-xs bg-white font-semibold"
                                            />
                                            <input
                                                type="email"
                                                required
                                                placeholder="Email Address *"
                                                value={inlineCustomer.email}
                                                onChange={(e) => setInlineCustomer({ ...inlineCustomer, email: e.target.value })}
                                                className="p-2 border rounded-xl border-slate-200 text-xs bg-white font-semibold"
                                            />
                                        </div>
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                            <input
                                                type="tel"
                                                required
                                                placeholder="Phone Number *"
                                                value={inlineCustomer.phone}
                                                onChange={(e) => setInlineCustomer({ ...inlineCustomer, phone: e.target.value })}
                                                className="p-2 border rounded-xl border-slate-200 text-xs bg-white font-semibold"
                                            />
                                            <input
                                                type="text"
                                                placeholder="Company Name (Optional)"
                                                value={inlineCustomer.companyName}
                                                onChange={(e) => setInlineCustomer({ ...inlineCustomer, companyName: e.target.value })}
                                                className="p-2 border rounded-xl border-slate-200 text-xs bg-white font-semibold"
                                            />
                                        </div>
                                        <div className="flex justify-end gap-2">
                                            <button
                                                type="button"
                                                onClick={() => setShowInlineCustomerAdd(false)}
                                                className="px-3 py-1.5 rounded-lg bg-slate-200 text-slate-700 text-xs font-bold"
                                            >
                                                Cancel
                                            </button>
                                            <button
                                                type="submit"
                                                disabled={inlineSubmitting}
                                                className="px-4 py-1.5 rounded-lg bg-red-600 text-white text-xs font-bold hover:bg-red-700"
                                            >
                                                {inlineSubmitting ? 'Saving...' : 'Save & Select Client'}
                                            </button>
                                        </div>
                                    </form>
                                ) : customers.length > 0 ? (
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
                                    <div className="p-4 bg-amber-50 border border-amber-200 text-amber-800 rounded-2xl flex items-center justify-between gap-3">
                                        <div className="text-xs font-bold">
                                            No customers linked yet. Click to onboard your first client.
                                        </div>
                                        <button
                                            type="button"
                                            onClick={() => setShowInlineCustomerAdd(true)}
                                            className="px-3 py-1 bg-amber-600 text-white rounded-lg text-xs font-bold hover:bg-amber-700 shrink-0"
                                        >
                                            + Add Client
                                        </button>
                                    </div>
                                )}
                            </div>

                            {/* Complete Service Catalogue Selector */}
                            <div className="space-y-3 pt-2">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">
                                    Complete Service Catalogue ({allServicesFlattened.length} Services)
                                </label>

                                {/* Category Pills */}
                                <div className="flex flex-wrap gap-1.5">
                                    {['All', ...COMPREHENSIVE_CATALOG.map(c => c.category)].map(catName => (
                                        <button
                                            key={catName}
                                            type="button"
                                            onClick={() => setCatalogCategory(catName)}
                                            className={`px-3 py-1 rounded-full text-[11px] font-bold transition-all ${
                                                catalogCategory === catName
                                                    ? 'bg-slate-900 text-white shadow-sm'
                                                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                                            }`}
                                        >
                                            {catName}
                                        </button>
                                    ))}
                                </div>

                                {/* Instant Catalog Search */}
                                <div className="relative">
                                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
                                    <input
                                        type="text"
                                        placeholder="Search any service (e.g. GST, ISO, Private Limited, GeM, ITR, Loan, Trademark)..."
                                        value={catalogSearch}
                                        onChange={(e) => setCatalogSearch(e.target.value)}
                                        className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold outline-none focus:border-red-500"
                                    />
                                </div>

                                {/* Catalog Service Grid */}
                                <div className="max-h-48 overflow-y-auto space-y-1.5 p-2 bg-slate-50/50 rounded-2xl border border-slate-200/80 custom-scrollbar">
                                    {filteredCatalogServices.map(service => {
                                        const isSelected = bookingForm.serviceName === service.name;
                                        return (
                                            <div
                                                key={service.name}
                                                onClick={() => handleSelectCatalogService(service)}
                                                className={`p-2.5 rounded-xl cursor-pointer border transition-all flex items-center justify-between gap-3 ${
                                                    isSelected
                                                        ? 'bg-red-50/80 border-red-500 shadow-sm'
                                                        : 'bg-white border-slate-200/80 hover:border-slate-300'
                                                }`}
                                            >
                                                <div className="min-w-0">
                                                    <p className={`text-xs font-bold truncate ${isSelected ? 'text-red-700' : 'text-slate-800'}`}>
                                                        {service.name}
                                                    </p>
                                                    <p className="text-[10px] text-slate-400 font-medium truncate mt-0.5">
                                                        {service.category} • {service.description}
                                                    </p>
                                                </div>
                                                <div className="text-right shrink-0">
                                                    <span className="text-xs font-black text-slate-900">
                                                        ₹{service.defaultPrice.toLocaleString('en-IN')}
                                                    </span>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>

                            {/* Selected Service Details & Customization */}
                            <form onSubmit={handleCreateOrder} className="space-y-4 pt-2 border-t border-slate-100">
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                    <div className="space-y-1.5">
                                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">
                                            Package Tier / Custom Label
                                        </label>
                                        <input 
                                            type="text" 
                                            required
                                            placeholder="Standard / Fast-Track"
                                            value={bookingForm.packageName}
                                            onChange={(e) => setBookingForm({ ...bookingForm, packageName: e.target.value })}
                                            className="w-full px-3 py-2 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
                                        />
                                    </div>

                                    <div className="space-y-1.5">
                                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">
                                            Order Price (INR) *
                                        </label>
                                        <input 
                                            type="number" 
                                            required
                                            min="1"
                                            value={bookingForm.price}
                                            onChange={(e) => setBookingForm({ ...bookingForm, price: e.target.value })}
                                            className="w-full px-3 py-2 rounded-xl bg-slate-50 border border-slate-200 focus:border-red-500 focus:bg-white outline-none font-bold text-xs transition"
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

                                <div className="flex items-center gap-3 pt-2">
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
                                        {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Confirm & Dispatch Invoice'}
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

export default PartnerMasterOrdersView;
