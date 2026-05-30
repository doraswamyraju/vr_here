import React, { useState, useEffect } from 'react';
import {
    Calculator, CheckCircle2, ArrowRight, ShieldCheck, Mail, Phone, RefreshCw, Layers, LayoutDashboard
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { SharedHeader, SharedFooter } from './components/SharedComponents';
import ConsultationPaymentModal from './components/ConsultationPaymentModal';
import { launchRazorpayCheckout } from './utils/razorpayCheckout';
import { showPaymentSuccessPopup } from './utils/paymentSuccessPopup';

const ACCOUNTING_SERVICES = [
    { id: 'gst', name: 'GST', desc: 'Monthly/Quarterly GST Returns & Compliance.', icon: Calculator },
    { id: 'tds', name: 'TDS', desc: 'TDS returns calculation and filing.', icon: Layers },
    { id: 'payroll', name: 'Payroll (PF, ESI & PT)', desc: 'Complete payroll, EPF, ESI and PT management.', icon: ShieldCheck },
    { id: 'form16', name: 'Form-16', desc: 'Employee Form-16 generation and filing.', icon: Mail },
    { id: 'accounts_mis', name: 'Accounts maintenance & MIS Reporting', desc: 'Bookkeeping and monthly management reports.', icon: RefreshCw },
    { id: 'stock', name: 'Stock Maintenance', desc: 'Inventory tracking and valuation support.', icon: Layers }
];

const AccountingServices = () => {
    const navigate = useNavigate();

    // Staff Authorization Banner Setup
    const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
    const isAuthorized = userInfo && (userInfo.role === 'admin' || userInfo.role === 'employee');

    const [isScrolled, setIsScrolled] = useState(false);
    const [loading, setLoading] = useState(true);
    
    // Selection State
    const [selectedServices, setSelectedServices] = useState([]);

    // Modal State
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [formData, setFormData] = useState({ name: '', email: '', phone: '' });

    useEffect(() => {
        const timer = setTimeout(() => setLoading(false), 1000);
        const handleScroll = () => setIsScrolled(window.scrollY > 20);
        window.addEventListener('scroll', handleScroll);
        return () => {
            window.removeEventListener('scroll', handleScroll);
            clearTimeout(timer);
        };
    }, []);

    const toggleService = (id) => {
        setSelectedServices(prev => 
            prev.includes(id) ? prev.filter(serviceId => serviceId !== id) : [...prev, id]
        );
    };

    const handleProceed = () => {
        if (selectedServices.length === 0) {
            alert('Please select at least one service to proceed.');
            return;
        }
        setIsModalOpen(true);
    };

    const handleFormSubmit = ({ formData: submittedFormData, termsAccepted }) => {
        if (!termsAccepted) {
            alert('Please accept the Terms & Conditions before proceeding.');
            return;
        }

        // Generate dynamic service name based on selections
        const selectedNames = ACCOUNTING_SERVICES
            .filter(s => selectedServices.includes(s.id))
            .map(s => s.name)
            .join(', ');
            
        const dynamicServiceName = `Accounting Consultation: ${selectedNames}`;

        const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
        setFormData(submittedFormData);

        // Dummy Plan object for the util
        const consultationPlan = {
            id: 'accounting-consultation',
            name: dynamicServiceName,
            price: 499,
            buttonText: 'Pay 499 & Proceed'
        };

        launchRazorpayCheckout({
            serviceName: dynamicServiceName,
            selectedPlan: consultationPlan,
            formData: submittedFormData,
            token: userInfo?.token,
            onSubmittingChange: setIsSubmitting,
            onSuccess: async (data) => {
                const requiresEmailLogin = Boolean(data?.resetLinkSent);
                await showPaymentSuccessPopup({
                    serviceName: dynamicServiceName,
                    paymentId: data?.payment?.paymentId,
                    requiresEmailLogin
                });
                setIsModalOpen(false);
                setSelectedServices([]); // Reset tracking
                setFormData({ name: '', email: '', phone: '' });
                navigate(requiresEmailLogin ? '/login' : '/customer-dashboard');
            },
            onFailure: (error) => {
                console.error('Payment Flow Error:', error);
                alert(error?.response?.data?.message || error?.description || error?.message || 'Something went wrong while processing payment.');
            }
        });
    };

    const formatCurrency = (amount) => {
        return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(amount);
    };

    if (loading) {
        return (
            <div className="fixed inset-0 bg-white z-[100] flex flex-col items-center justify-center">
                <div className="w-20 h-20 bg-black rounded-2xl flex items-center justify-center mb-6 animate-pulse">
                    <span className="text-white font-black text-3xl">VR</span>
                </div>
                <div className="text-sm font-bold tracking-widest text-slate-400">LOADING SERVICES...</div>
            </div>
        );
    }

    return (
        <div className={`font-sans text-slate-800 bg-slate-50 min-h-screen ${isAuthorized ? 'pt-14' : ''}`}>
            
            {/* Staff Panel Navigation Header */}
            {isAuthorized && (
                <div className="fixed top-0 left-0 right-0 z-[100] h-14 bg-slate-900 border-b border-indigo-500/20 text-white px-6 flex items-center justify-between shadow-lg font-sans animate-fade-in">
                    <div className="flex items-center gap-3">
                        <div className="w-7 h-7 bg-gradient-to-br from-indigo-600 to-blue-500 rounded-lg flex items-center justify-center text-white font-bold text-sm shadow">
                            VR
                        </div>
                        <div className="flex flex-col">
                            <span className="text-xs font-black uppercase tracking-wider text-slate-100">VR Here Staff Panel</span>
                            <span className="text-[9px] font-bold uppercase tracking-widest text-emerald-400 flex items-center gap-1">
                                <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-ping"></span>
                                <span>Active Session ({userInfo?.role})</span>
                            </span>
                        </div>
                    </div>

                    <div className="flex items-center gap-3">
                        <button
                            onClick={() => navigate(userInfo?.role === 'admin' ? '/admin' : '/employee')}
                            className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-4 py-2 rounded-lg text-xs font-black uppercase tracking-wider transition flex items-center gap-1.5"
                        >
                            <LayoutDashboard className="w-3.5 h-3.5" />
                            <span>Back to Dashboard</span>
                        </button>
                    </div>
                </div>
            )}

            <SharedHeader isScrolled={isScrolled} />
            
            {/* Payment Modal */}
            <ConsultationPaymentModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                selectedPlan={{ price: 499, buttonText: 'Confirm Consultation' }}
                initialFormData={formData}
                onSubmit={handleFormSubmit}
                isSubmitting={isSubmitting}
                formatCurrency={formatCurrency}
                title="Book Service Consultation"
                nonAdjustableNote="Our expert will review your requirements on the call."
                initialTermsAccepted={false}
            />

            <div className="pt-24 pb-16 lg:pt-32 lg:pb-24 max-w-7xl mx-auto px-4 sm:px-6">
                
                {/* Hero Section */}
                <div className="text-center mb-16 animate-fade-in">
                    <h1 className="text-4xl lg:text-6xl font-black text-slate-900 tracking-tight leading-[1.1] mb-6">
                        Custom <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-600 to-orange-600">Accounting</span> Services
                    </h1>
                    <p className="text-lg text-slate-600 max-w-2xl mx-auto mb-8">
                        Select the exact accounting and compliance services you need. Pay a flat ₹499 consultation fee, and our experts will customize a package and roadmap specifically for your business.
                    </p>
                </div>

                {/* Selection Grid */}
                <div className="bg-white rounded-3xl shadow-xl border border-slate-200 p-6 sm:p-10 max-w-5xl mx-auto mb-12 animate-fade-in">
                    <div className="flex justify-between items-center border-b border-slate-100 pb-6 mb-8">
                        <h2 className="text-xl sm:text-2xl font-bold text-slate-900">Select Your Requirements</h2>
                        <span className="bg-slate-100 text-slate-600 px-3 py-1 rounded-full text-sm font-bold">
                            {selectedServices.length} Selected
                        </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
                        {ACCOUNTING_SERVICES.map((service) => {
                            const isSelected = selectedServices.includes(service.id);
                            return (
                                <button
                                    key={service.id}
                                    onClick={() => toggleService(service.id)}
                                    className={`relative flex flex-col items-start p-6 rounded-2xl border-2 transition-all duration-300 text-left overflow-hidden ${
                                        isSelected 
                                        ? 'border-red-600 bg-red-50/50 shadow-md transform -translate-y-1' 
                                        : 'border-slate-100 bg-white hover:border-red-200 hover:shadow-sm'
                                    }`}
                                >
                                    <div className="flex w-full justify-between items-start mb-4">
                                        <div className={`p-2 rounded-lg ${isSelected ? 'bg-red-600 text-white' : 'bg-slate-100 text-slate-600'}`}>
                                            <service.icon className="w-6 h-6" />
                                        </div>
                                        <div className={`w-6 h-6 rounded-full border-2 flex items-center justify-center ${isSelected ? 'border-red-600 bg-red-600' : 'border-slate-300'}`}>
                                            {isSelected && <CheckCircle2 className="w-4 h-4 text-white" />}
                                        </div>
                                    </div>
                                    <h3 className={`font-bold text-lg mb-2 line-clamp-2 ${isSelected ? 'text-red-700' : 'text-slate-900'}`}>{service.name}</h3>
                                    <p className="text-sm text-slate-500 line-clamp-3">{service.desc}</p>
                                    
                                    {/* Active border accent */}
                                    {isSelected && <div className="absolute bottom-0 left-0 h-1 bg-red-600 w-full animate-fade-in" />}
                                </button>
                            );
                        })}
                    </div>

                    {/* Action Footer */}
                    <div className="mt-10 bg-slate-50 rounded-2xl p-6 border border-slate-100 flex flex-col sm:flex-row items-center justify-between gap-6">
                        <div>
                            <div className="font-bold text-slate-900 text-lg mb-1">Consultation Fee</div>
                            <div className="text-3xl font-black text-red-600">₹499 <span className="text-sm font-medium text-slate-500 line-through ml-2">₹999</span></div>
                            <p className="text-sm text-slate-500 mt-1">Adjustable against final service fees.</p>
                        </div>
                        <button
                            onClick={handleProceed}
                            disabled={selectedServices.length === 0}
                            className={`w-full sm:w-auto px-8 py-4 rounded-xl font-bold flex items-center justify-center transition-all shadow-lg ${
                                selectedServices.length > 0
                                ? 'bg-gradient-to-r from-red-600 to-orange-500 text-white hover:shadow-red-600/30 transform hover:-translate-y-1'
                                : 'bg-slate-200 text-slate-400 cursor-not-allowed opacity-70'
                            }`}
                        >
                            Proceed to Book <ArrowRight className="ml-2 w-5 h-5" />
                        </button>
                    </div>
                </div>

            </div>
            <SharedFooter />
        </div>
    );
};

export default AccountingServices;
