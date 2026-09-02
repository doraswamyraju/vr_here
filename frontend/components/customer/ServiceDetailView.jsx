import React, { useState, useEffect } from 'react';
import { 
    CheckCircle2, ArrowRight, RefreshCw, Star, Info, 
    ChevronRight, ArrowLeft 
} from 'lucide-react';
import { SERVICE_CATALOG } from '../../data/serviceCatalog';
import ConsultationPaymentModal from '../ConsultationPaymentModal';
import { launchRazorpayCheckout } from '../../utils/razorpayCheckout';
import { showPaymentSuccessPopup } from '../../utils/paymentSuccessPopup';

const ServiceDetailView = ({ serviceKey, setActiveTab, userInfo }) => {
    const service = SERVICE_CATALOG[serviceKey];
    const [loading, setLoading] = useState(true);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [selectedPlan, setSelectedPlan] = useState(null);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [formData, setFormData] = useState({ 
        name: userInfo?.name || '', 
        email: userInfo?.email || '', 
        phone: userInfo?.phone || '' 
    });

    useEffect(() => {
        const timer = setTimeout(() => setLoading(false), 500);
        return () => clearTimeout(timer);
    }, [serviceKey]);

    if (!service) {
        return (
            <div className="p-12 text-center">
                <p className="text-slate-500 font-bold">Service data not found.</p>
                <button 
                    onClick={() => setActiveTab('Services')}
                    className="mt-4 text-indigo-600 font-black flex items-center gap-2 mx-auto hover:underline"
                >
                    <ArrowLeft size={16} /> Back to Catalog
                </button>
            </div>
        );
    }

    const handleSelectPlan = (plan) => {
        setSelectedPlan(plan);
        setIsModalOpen(true);
    };

    const handleFormSubmit = ({ formData: submittedFormData, termsAccepted }) => {
        if (!termsAccepted) {
            alert('Please accept the Terms & Conditions before proceeding.');
            return;
        }

        setFormData(submittedFormData);

        launchRazorpayCheckout({
            serviceName: service.title,
            selectedPlan,
            formData: submittedFormData,
            token: userInfo?.token,
            onSubmittingChange: setIsSubmitting,
            onSuccess: async (data) => {
                await showPaymentSuccessPopup({
                    serviceName: selectedPlan?.name || service.title,
                    paymentId: data?.payment?.paymentId,
                    requiresEmailLogin: false
                });
                setIsModalOpen(false);
                setActiveTab('Orders');
            },
            onFailure: (error) => {
                console.error('Payment Flow Error:', error);
                alert(error?.response?.data?.message || 'Something went wrong while processing payment.');
            }
        });
    };

    const formatCurrency = (amount) => {
        return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(amount);
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center p-12">
                <div className="w-12 h-12 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin"></div>
            </div>
        );
    }

    return (
        <div className="space-y-6 pb-20 md:pb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Header */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-2 px-1">
                <div>
                    <button 
                        onClick={() => setActiveTab('Services')}
                        className="text-slate-400 hover:text-indigo-600 text-[10px] font-black uppercase tracking-widest flex items-center gap-1 mb-2 transition-colors"
                    >
                        <ArrowLeft size={12} /> Master Catalog
                    </button>
                    <h1 className="text-2xl lg:text-3xl font-black text-slate-800 tracking-tight flex items-center gap-3">
                        {service.icon && <service.icon className="text-indigo-600" size={32} />}
                        {service.title}
                    </h1>
                    <p className="text-slate-500 text-sm max-w-2xl mt-1">{service.description}</p>
                </div>
            </div>

            <ConsultationPaymentModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                selectedPlan={selectedPlan}
                initialFormData={formData}
                onSubmit={handleFormSubmit}
                isSubmitting={isSubmitting}
                formatCurrency={formatCurrency}
                title={selectedPlan?.id === 'consultation' ? 'Book Consultation' : 'Get Started'}
                initialTermsAccepted={false}
            />

            {/* Packages Grid */}
            <div
                className={`grid gap-6 mt-8 justify-center ${
                    service.packages.length === 1
                        ? 'max-w-md mx-auto grid-cols-1'
                        : service.packages.length === 2
                        ? 'max-w-3xl mx-auto grid-cols-1 md:grid-cols-2'
                        : service.packages.length === 3
                        ? 'max-w-5xl mx-auto grid-cols-1 md:grid-cols-3'
                        : 'max-w-[1400px] mx-auto grid-cols-1 md:grid-cols-2 lg:grid-cols-4'
                }`}
            >
                {service.packages.map((pkg) => (
                    <div 
                        key={pkg.id} 
                        className={`bg-white rounded-2xl p-8 border transition-all duration-300 flex flex-col relative transform hover:-translate-y-4 hover:shadow-2xl ${
                            pkg.isPopular ? 'border-red-600 shadow-xl scale-105 z-10' : 'border-slate-200 hover:border-red-300 shadow-sm'
                        }`}
                    >
                        {pkg.isPopular && (
                            <div className="absolute top-0 right-0 bg-red-600 text-white text-xs font-bold px-3 py-1 rounded-bl-lg rounded-tr-lg shadow-md">
                                RECOMMENDED
                            </div>
                        )}

                        <h3 className="text-xl font-bold text-slate-900 mb-2">{pkg.name}</h3>
                        <div className="text-4xl font-black text-slate-900 mb-6">
                            {formatCurrency(pkg.price)}
                            <span className="text-[10px] font-bold text-slate-500 ml-1 block mt-1">
                                {pkg.isAdjustable ? '(Fully Adjustable)' : '+ Taxes'}
                            </span>
                        </div>

                        {pkg.isAdjustable && (
                            <div className="bg-green-50 text-green-700 text-xs font-bold p-2 rounded mb-4 flex items-center">
                                <RefreshCw className="w-3 h-3 mr-1" /> Fee Adjustable in Final Package
                            </div>
                        )}

                        <p className="text-sm text-slate-600 mb-6 font-medium leading-relaxed">{pkg.description}</p>

                        <div className="space-y-4 mb-8 flex-1">
                            {pkg.features.map((feat, i) => (
                                <div key={i} className="flex items-start text-sm text-slate-700 font-medium group">
                                    <CheckCircle2 size={16} className="text-green-500 mr-2 mt-0.5 shrink-0 group-hover:scale-125 transition-transform" />
                                    <span>{feat}</span>
                                </div>
                            ))}
                        </div>

                        <button 
                            onClick={() => handleSelectPlan(pkg)} 
                            className={`w-full py-4 rounded-xl font-bold transition transform active:scale-95 ${
                                pkg.isPopular || pkg.isAdjustable 
                                ? 'bg-red-600 text-white hover:bg-red-700 shadow-lg shadow-red-600/30' 
                                : 'bg-slate-100 text-slate-900 hover:bg-slate-200'
                            }`}
                        >
                            {pkg.buttonText}
                        </button>
                    </div>
                ))}
            </div>

            {/* Why VR HERE Section */}
            <div className="mt-12 bg-slate-900 rounded-[40px] p-8 md:p-12 text-white relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/10 rounded-full -mr-48 -mt-48 blur-3xl group-hover:bg-indigo-500/20 transition-all duration-1000"></div>
                <div className="relative z-10 grid md:grid-cols-2 gap-12 items-center">
                    <div>
                        <div className="inline-flex items-center px-4 py-1.5 rounded-full bg-indigo-600/30 border border-indigo-400/30 text-[10px] font-black uppercase tracking-widest text-indigo-300 mb-6">
                            The VR HERE Advantage
                        </div>
                        <h2 className="text-2xl lg:text-3xl font-black mb-6 tracking-tight">Expert-Led Compliance & Seamless Execution</h2>
                        <ul className="space-y-4">
                            {[
                                { t: 'CA/CS Expert Oversight', d: 'Every document is strictly reviewed for compliance.' },
                                { t: 'Real-time Tracking', d: 'Track every step of your registration in this portal.' },
                                { t: 'Post-Registration Support', d: 'We don\'t just register, we help you stay compliant.' }
                            ].map((item, i) => (
                                <li key={i} className="flex items-start gap-4">
                                    <div className="w-10 h-10 bg-white/10 rounded-xl flex items-center justify-center shrink-0 border border-white/5">
                                        <Star size={18} className="text-amber-400" />
                                    </div>
                                    <div>
                                        <div className="font-bold text-sm text-white mb-1">{item.t}</div>
                                        <p className="text-slate-400 text-xs leading-relaxed">{item.d}</p>
                                    </div>
                                </li>
                            ))}
                        </ul>
                    </div>
                    <div className="bg-white/5 backdrop-blur-xl border border-white/10 p-8 rounded-[32px] text-center">
                        <div className="w-16 h-16 bg-white rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-2xl">
                            <Info className="text-indigo-600" size={32} />
                        </div>
                        <h3 className="font-black text-xl mb-4">Confused? Free Assessment</h3>
                        <p className="text-slate-400 text-xs mb-8 leading-relaxed max-w-sm mx-auto">
                            Not sure which structure is right? Click the help button below to raise a quick inquiry.
                        </p>
                        <button 
                            onClick={() => setActiveTab('New')}
                            className="bg-white text-slate-900 px-10 py-4 rounded-2xl font-black text-[10px] uppercase tracking-widest hover:bg-slate-100 transition-colors"
                        >
                            Get Free Advice
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ServiceDetailView;
