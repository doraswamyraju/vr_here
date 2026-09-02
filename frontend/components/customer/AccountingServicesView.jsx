import React, { useState, useEffect } from 'react';
import {
    Calculator, CheckCircle2, ArrowRight, ShieldCheck, Mail, Phone, RefreshCw, Layers
} from 'lucide-react';
import { launchCustomerCheckout } from '../../utils/customerCheckout';
import CustomerOrderSuccessModal from './CustomerOrderSuccessModal';

const ACCOUNTING_SERVICES = [
    { id: 'gst', name: 'GST', desc: 'Monthly/Quarterly GST Returns & Compliance.', icon: Calculator },
    { id: 'tds', name: 'TDS', desc: 'TDS returns calculation and filing.', icon: Layers },
    { id: 'payroll', name: 'Payroll (PF, ESI & PT)', desc: 'Complete payroll, EPF, ESI and PT management.', icon: ShieldCheck },
    { id: 'form16', name: 'Form-16', desc: 'Employee Form-16 generation and filing.', icon: Mail },
    { id: 'accounts_mis', name: 'Accounts maintenance & MIS Reporting', desc: 'Bookkeeping and monthly management reports.', icon: RefreshCw },
    { id: 'stock', name: 'Stock Maintenance', desc: 'Inventory tracking and valuation support.', icon: Layers }
];

const AccountingServicesView = ({ setActiveTab, userInfo, onOrderSuccess }) => {
    const [loading, setLoading] = useState(true);
    const [selectedServices, setSelectedServices] = useState([]);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [successOrderData, setSuccessOrderData] = useState(null);

    useEffect(() => {
        const timer = setTimeout(() => setLoading(false), 500);
        return () => clearTimeout(timer);
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

        const selectedNames = ACCOUNTING_SERVICES
            .filter(s => selectedServices.includes(s.id))
            .map(s => s.name)
            .join(', ');
            
        const dynamicServiceName = `Accounting Consultation: ${selectedNames}`;

        const consultationPlan = {
            id: 'accounting-consultation',
            name: dynamicServiceName,
            price: 499,
            buttonText: 'Book CA Strategy Call'
        };

        launchCustomerCheckout({
            serviceName: dynamicServiceName,
            selectedPlan: consultationPlan,
            userInfo,
            onSubmittingChange: setIsSubmitting,
            onSuccess: (data) => {
                setSelectedServices([]);
                setSuccessOrderData(data);
            },
            onFailure: (error) => {
                console.error('Customer Payment Flow Error:', error);
                alert(error?.response?.data?.message || error?.description || error?.message || 'Something went wrong while processing payment.');
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
            <div className="flex justify-between items-end mb-2 px-1">
                <div>
                    <h1 className="text-2xl lg:text-3xl font-black text-slate-800 tracking-tight">Accounting Services</h1>
                    <p className="text-slate-500 text-sm">Select the specific modules you need for your business.</p>
                </div>
            </div>

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

            <div className="bg-white rounded-[32px] border border-slate-100 p-6 md:p-8 shadow-sm">
                <div className="flex justify-between items-center border-b border-slate-100 pb-6 mb-8">
                    <h2 className="text-xl font-bold text-slate-800">Select Your Requirements</h2>
                    <span className="bg-indigo-50 text-indigo-600 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-widest">
                        {selectedServices.length} Selected
                    </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {ACCOUNTING_SERVICES.map((service) => {
                        const isSelected = selectedServices.includes(service.id);
                        return (
                            <button
                                key={service.id}
                                onClick={() => toggleService(service.id)}
                                className={`relative flex flex-col items-start p-6 rounded-2xl border transition-all duration-300 text-left overflow-hidden ${
                                    isSelected 
                                    ? 'border-indigo-600 bg-indigo-50 shadow-md transform -translate-y-1' 
                                    : 'border-slate-100 bg-white hover:border-indigo-100 hover:shadow-sm'
                                }`}
                            >
                                <div className="flex w-full justify-between items-start mb-4">
                                    <div className={`p-3 rounded-2xl ${isSelected ? 'bg-indigo-600 text-white' : 'bg-slate-50 text-slate-500'}`}>
                                        <service.icon className="w-5 h-5" />
                                    </div>
                                    <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${isSelected ? 'border-indigo-600 bg-indigo-600' : 'border-slate-300'}`}>
                                        {isSelected && <CheckCircle2 className="w-3 h-3 text-white" />}
                                    </div>
                                </div>
                                <h3 className={`font-black text-sm mb-2 ${isSelected ? 'text-indigo-800' : 'text-slate-800'}`}>{service.name}</h3>
                                <p className="text-xs text-slate-500 line-clamp-3 leading-relaxed">{service.desc}</p>
                            </button>
                        );
                    })}
                </div>

                <div className="mt-10 bg-slate-50 rounded-[24px] p-6 border border-slate-100 flex flex-col sm:flex-row items-center justify-between gap-6">
                    <div>
                        <div className="font-bold text-slate-800 text-sm mb-1 uppercase tracking-widest">Consultation Fee</div>
                        <div className="text-3xl font-black text-indigo-600">₹499 <span className="text-xs font-bold text-slate-400 line-through ml-2">₹999</span></div>
                        <p className="text-xs text-slate-500 mt-2 font-medium">Fully adjustable against final package assignment.</p>
                    </div>
                    <button
                        onClick={handleProceed}
                        disabled={selectedServices.length === 0}
                        className={`w-full sm:w-auto px-8 py-4 rounded-2xl font-black text-xs uppercase tracking-widest flex items-center justify-center transition-all ${
                            selectedServices.length > 0
                            ? 'bg-indigo-600 text-white shadow-xl shadow-indigo-200 hover:bg-indigo-700 hover:-translate-y-1'
                            : 'bg-slate-200 text-slate-400 cursor-not-allowed opacity-70'
                        }`}
                    >
                        Proceed to Book <ArrowRight className="ml-2 w-4 h-4" />
                    </button>
                </div>
            </div>

            {/* In-App Customer Order Success Modal */}
            <CustomerOrderSuccessModal 
                isOpen={!!successOrderData}
                orderData={successOrderData}
                onClose={() => {
                    const data = successOrderData;
                    setSuccessOrderData(null);
                    if (onOrderSuccess) onOrderSuccess(data);
                }}
                onGoToWorkspace={() => {
                    const data = successOrderData;
                    setSuccessOrderData(null);
                    if (onOrderSuccess) onOrderSuccess(data);
                }}
            />
        </div>
    );
};

export default AccountingServicesView;
