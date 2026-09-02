import React, { useState, useEffect } from 'react';
import { 
    CheckCircle2, ArrowRight, RefreshCw, Star, Info, 
    ChevronRight, ArrowLeft, ShieldCheck, Check, ChevronDown,
    FileCheck, Sparkles, HelpCircle, PhoneCall, Layers
} from 'lucide-react';
import { fetchServicePageConfig } from '../../modules/service-editor/v1.1/services/serviceConfigApi';
import { launchRazorpayCheckout } from '../../utils/razorpayCheckout';
import { showPaymentSuccessPopup } from '../../utils/paymentSuccessPopup';

const formatCurrency = (amount) => {
    if (typeof amount === 'string' && (amount.includes('₹') || isNaN(Number(amount.replace(/[^0-9]/g, ''))))) {
        return amount;
    }
    const num = Number(String(amount).replace(/[^0-9]/g, '')) || 0;
    return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(num);
};

const ServiceDetailView = ({ service, onBack, setActiveTab, userInfo }) => {
    const [pageConfig, setPageConfig] = useState(null);
    const [loading, setLoading] = useState(true);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [activeFaq, setActiveFaq] = useState(null);

    const serviceTitle = service?.title || 'Business Compliance Service';
    const slug = service?.slug || 'pvt-ltd-registration';

    useEffect(() => {
        let isMounted = true;
        const loadConfig = async () => {
            setLoading(true);
            try {
                const configData = await fetchServicePageConfig(slug);
                if (isMounted && configData && (configData.packages || configData.hero || configData.title)) {
                    setPageConfig(configData);
                } else if (isMounted) {
                    setPageConfig(null);
                }
            } catch (err) {
                console.log('Using dynamic fallback for:', slug);
                if (isMounted) setPageConfig(null);
            } finally {
                if (isMounted) setLoading(false);
            }
        };

        if (slug) {
            loadConfig();
        }
        return () => { isMounted = false; };
    }, [slug]);

    // Fallback packages if no custom config exists in Service Master
    const activeHero = pageConfig?.hero || {
        badgeText: "Official MCA & Govt Filing",
        title: serviceTitle,
        subtitle: `Fast-track processing, dedicated CA & CS advisor, all-inclusive government compliance for ${serviceTitle}.`,
        consultationPrice: 499
    };

    const activePackages = (pageConfig?.packages && pageConfig.packages.length > 0) ? pageConfig.packages : [
        {
            id: 'starter',
            name: 'Standard Package',
            price: 2999,
            isPopular: false,
            description: `Essential setup & government registration for ${serviceTitle}.`,
            features: [
                'Full Application Preparation & Drafting',
                'Government Portal Filing & Document Submission',
                'Dedicated CA Review & Compliance Check',
                'Official Government Certificate Delivery',
                'Standard Email & Call Support'
            ],
            buttonText: 'Select Standard'
        },
        {
            id: 'growth',
            name: 'Premium Enterprise',
            price: 6499,
            isPopular: true,
            description: 'All-inclusive VIP fast-track processing with allied licenses.',
            features: [
                'Fast-Track Priority Processing (24-48 Hrs)',
                'Dedicated Senior CA & CS Manager',
                'Allied License & MSME Registration Included',
                'Permanent Digital Document Vault Storage',
                '1-Year Free Annual Compliance Roadmap'
            ],
            buttonText: 'Select Enterprise'
        }
    ];

    const activeGuide = pageConfig?.guide || {
        sections: [
            {
                title: "How the Process Works",
                content: "Our certified Chartered Accountants and Company Secretaries handle the entire filing end-to-end.",
                bullets: [
                    "Submit minimal business details and identity proofs via your secure vault",
                    "Our team drafts, notarizes, and reviews all required forms and declarations",
                    "Application submitted to the government ministry portal with real-time tracking",
                    "Final approved certificate and registration documents deposited into your Project Vault"
                ]
            }
        ],
        checklistTitle: "Documents Required for Filing",
        checklist: [
            "PAN Card & Aadhaar Card of Applicant / Directors",
            "Proof of Business Address (Electricity Bill / Rent Agreement)",
            "Passport Size Photograph",
            "Bank Statement / Cancelled Cheque"
        ]
    };

    const activeFaqs = (pageConfig?.faqs && pageConfig.faqs.length > 0) ? pageConfig.faqs : [
        {
            q: `What is the timeline to complete ${serviceTitle}?`,
            a: "Typically, government processing takes 3 to 7 working days once all necessary documents and authorizations are uploaded."
        },
        {
            q: "Will I get an official government certificate?",
            a: "Yes. Once approved by the ministry or department, the digitally signed government certificate and registration deed will be available in your Project Vault."
        },
        {
            q: "Are government fees included in the package?",
            a: "Our packages cover complete professional drafting, CA verification, and portal filing. Applicable statutory government stamp duties or challan fees are charged as per actual state rates."
        }
    ];

    const handleSelectPlan = (plan) => {
        const planPrice = typeof plan.price === 'string' 
            ? Number(plan.price.replace(/[^0-9]/g, '')) || 0 
            : Number(plan.price) || 0;

        launchRazorpayCheckout({
            serviceName: serviceTitle,
            selectedPlan: {
                ...plan,
                price: planPrice
            },
            formData: {
                name: userInfo?.name || 'Client',
                email: userInfo?.email || 'client@vrhere.in',
                phone: userInfo?.phone || ''
            },
            token: userInfo?.token,
            onSubmittingChange: setIsSubmitting,
            onSuccess: async (data) => {
                await showPaymentSuccessPopup({
                    serviceName: plan.name || serviceTitle,
                    paymentId: data?.payment?.paymentId || data?.razorpay_payment_id,
                    requiresEmailLogin: false
                });
                setActiveTab('Orders');
            },
            onFailure: (error) => {
                console.error('Payment Flow Error:', error);
                alert(error?.response?.data?.message || 'Something went wrong while processing payment.');
            }
        });
    };

    const handleBookConsultation = () => {
        handleSelectPlan({
            id: 'consultation',
            name: `${serviceTitle} Consultation`,
            price: activeHero.consultationPrice || 499,
            isAdjustable: true,
            description: 'Dedicated 30-min strategy call with senior CA. Fully adjustable against registration.',
            buttonText: 'Book Consultation'
        });
    };

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center p-20 bg-white rounded-3xl border border-slate-200">
                <div className="w-12 h-12 border-4 border-red-600 border-t-transparent rounded-full animate-spin mb-4"></div>
                <p className="text-slate-500 font-black text-xs uppercase tracking-widest">Loading Live Service Details...</p>
            </div>
        );
    }

    return (
        <div className="space-y-8 pb-24 lg:pb-12 animate-in fade-in slide-in-from-bottom-3 duration-500">
            {/* Top Breadcrumb Bar */}
            <div className="flex items-center justify-between">
                <button 
                    onClick={onBack}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-black uppercase tracking-wider rounded-xl border border-slate-200 shadow-2xs transition-colors group"
                >
                    <ArrowLeft size={14} className="group-hover:-translate-x-1 transition-transform" />
                    <span>Back to Services Catalog</span>
                </button>

                <span className="text-xs font-bold text-slate-400">
                    Live Sync with Service Master
                </span>
            </div>

            {/* 1. Hero Card */}
            <div className="bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 rounded-3xl p-6 sm:p-10 text-white relative overflow-hidden border border-slate-800 shadow-2xl">
                <div className="absolute top-0 right-0 w-96 h-96 bg-red-600/10 rounded-full blur-3xl pointer-events-none"></div>
                
                <div className="relative z-10 max-w-3xl space-y-4">
                    <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 text-red-400 border border-white/10 text-[11px] font-black uppercase tracking-wider">
                        <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                        <span>{activeHero.badgeText || 'Verified Legal Service'}</span>
                    </div>

                    <h1 className="text-2xl sm:text-4xl lg:text-5xl font-black text-white tracking-tight leading-tight">
                        {activeHero.title || serviceTitle}
                    </h1>

                    <p className="text-slate-300 text-sm sm:text-base leading-relaxed font-medium">
                        {activeHero.subtitle || `Comprehensive filing, drafting, and regulatory approval by CA & CS professionals.`}
                    </p>

                    <div className="pt-2 flex flex-wrap items-center gap-3">
                        <button
                            onClick={handleBookConsultation}
                            disabled={isSubmitting}
                            className="bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 text-white px-6 py-3.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-all shadow-lg shadow-red-600/30 flex items-center gap-2 disabled:opacity-50"
                        >
                            <PhoneCall size={15} />
                            <span>Book Consultation @ ₹{activeHero.consultationPrice || 499}</span>
                        </button>
                        <span className="text-[11px] text-slate-400 font-semibold flex items-center gap-1.5">
                            <ShieldCheck size={14} className="text-emerald-400" />
                            Fee fully adjustable against final package
                        </span>
                    </div>
                </div>
            </div>

            {/* 2. Packages Grid */}
            <div className="space-y-4">
                <div>
                    <h2 className="text-xl lg:text-2xl font-black text-slate-900 tracking-tight">Available Plans & Packages</h2>
                    <p className="text-slate-500 text-xs sm:text-sm font-medium">Transparent upfront fees with zero hidden charges.</p>
                </div>

                <div className={`grid gap-6 justify-center ${
                    activePackages.length === 1
                        ? 'max-w-md mx-auto grid-cols-1'
                        : activePackages.length === 2
                        ? 'grid-cols-1 md:grid-cols-2'
                        : activePackages.length === 3
                        ? 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3'
                        : 'grid-cols-1 md:grid-cols-2 lg:grid-cols-4'
                }`}>
                    {activePackages.map((pkg, idx) => (
                        <div 
                            key={pkg.id || idx}
                            className={`bg-white rounded-3xl p-6 sm:p-8 border transition-all duration-300 flex flex-col justify-between relative hover:shadow-xl ${
                                pkg.isPopular 
                                    ? 'border-red-600 shadow-lg shadow-red-500/10 ring-2 ring-red-600/20' 
                                    : 'border-slate-200/90 shadow-2xs hover:border-red-300'
                            }`}
                        >
                            {pkg.isPopular && (
                                <div className="absolute top-0 right-0 bg-red-600 text-white text-[10px] font-black px-3.5 py-1 rounded-bl-xl rounded-tr-3xl shadow-md uppercase tracking-wider">
                                    Recommended
                                </div>
                            )}

                            <div>
                                <h3 className="text-lg font-black text-slate-900 mb-1">{pkg.name}</h3>
                                <div className="text-3xl font-black text-slate-900 mb-4">
                                    {formatCurrency(pkg.price)}
                                    <span className="text-[10px] font-bold text-slate-400 ml-1 block mt-0.5">
                                        {pkg.isAdjustable ? '(Fully Adjustable)' : '+ Govt Fees & GST'}
                                    </span>
                                </div>

                                <p className="text-xs text-slate-500 font-medium mb-6 leading-relaxed">
                                    {pkg.description || 'Complete compliance & filing support.'}
                                </p>

                                <div className="space-y-3 mb-8 pt-4 border-t border-slate-100">
                                    <p className="text-[10px] font-black text-slate-400 uppercase tracking-wider">What is included:</p>
                                    {(pkg.features || []).map((feat, fIdx) => (
                                        <div key={fIdx} className="flex items-start text-xs font-semibold text-slate-700 gap-2.5">
                                            <CheckCircle2 size={16} className="text-emerald-500 shrink-0 mt-0.5" />
                                            <span>{feat}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <button
                                onClick={() => handleSelectPlan(pkg)}
                                disabled={isSubmitting}
                                className={`w-full py-3.5 rounded-xl font-black text-xs uppercase tracking-wider transition-all shadow-md flex items-center justify-center gap-2 disabled:opacity-50 ${
                                    pkg.isPopular 
                                        ? 'bg-red-600 hover:bg-red-700 text-white shadow-red-600/30' 
                                        : 'bg-slate-900 hover:bg-slate-800 text-white'
                                }`}
                            >
                                <span>{pkg.buttonText || 'Choose Plan'}</span>
                                <ArrowRight size={14} />
                            </button>
                        </div>
                    ))}
                </div>
            </div>

            {/* 3. Filing Process & Required Documents */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Guide Steps */}
                <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/90 shadow-2xs space-y-4">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-10 h-10 rounded-xl bg-red-50 text-red-600 flex items-center justify-center font-bold">
                            <Layers size={20} />
                        </div>
                        <div>
                            <h3 className="text-base font-black text-slate-900">How We Execute</h3>
                            <p className="text-xs text-slate-500">Step-by-step roadmap from filing to certification</p>
                        </div>
                    </div>

                    {(activeGuide.sections || []).map((sec, sIdx) => (
                        <div key={sIdx} className="space-y-2">
                            <p className="text-xs text-slate-600 font-medium leading-relaxed">{sec.content}</p>
                            {sec.bullets && (
                                <div className="space-y-2 pt-2">
                                    {sec.bullets.map((b, bIdx) => (
                                        <div key={bIdx} className="flex items-start gap-2.5 text-xs text-slate-700 font-medium">
                                            <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-700 flex items-center justify-center text-[10px] font-black shrink-0">
                                                {bIdx + 1}
                                            </span>
                                            <span>{b}</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    ))}
                </div>

                {/* Required Documents Checklist */}
                <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/90 shadow-2xs space-y-4">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-10 h-10 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center font-bold">
                            <FileCheck size={20} />
                        </div>
                        <div>
                            <h3 className="text-base font-black text-slate-900">{activeGuide.checklistTitle || 'Required Documents Checklist'}</h3>
                            <p className="text-xs text-slate-500">Proofs you will upload into your secure vault</p>
                        </div>
                    </div>

                    <div className="space-y-2.5">
                        {(activeGuide.checklist || []).map((item, cIdx) => (
                            <div key={cIdx} className="p-3 bg-slate-50 rounded-xl border border-slate-200/70 flex items-center gap-3 text-xs font-bold text-slate-700">
                                <Check size={16} className="text-emerald-500 shrink-0" />
                                <span>{item}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* 4. Frequently Asked Questions */}
            {activeFaqs.length > 0 && (
                <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/90 shadow-2xs space-y-4">
                    <div className="flex items-center gap-3 mb-4">
                        <div className="w-10 h-10 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center font-bold">
                            <HelpCircle size={20} />
                        </div>
                        <div>
                            <h3 className="text-base font-black text-slate-900">Frequently Asked Questions</h3>
                            <p className="text-xs text-slate-500">Clarifications & regulatory guidance</p>
                        </div>
                    </div>

                    <div className="space-y-3">
                        {activeFaqs.map((faq, fIdx) => (
                            <div key={fIdx} className="rounded-2xl border border-slate-200/80 overflow-hidden">
                                <button
                                    onClick={() => setActiveFaq(activeFaq === fIdx ? null : fIdx)}
                                    className="w-full p-4 flex items-center justify-between text-left font-bold text-xs sm:text-sm text-slate-800 hover:bg-slate-50 transition-colors"
                                >
                                    <span>{faq.q}</span>
                                    <ChevronDown size={16} className={`text-slate-400 transition-transform shrink-0 ml-2 ${activeFaq === fIdx ? 'rotate-180' : ''}`} />
                                </button>
                                {activeFaq === fIdx && (
                                    <div className="p-4 border-t border-slate-100 text-xs text-slate-600 leading-relaxed bg-slate-50/50 font-medium">
                                        {faq.a}
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default ServiceDetailView;
