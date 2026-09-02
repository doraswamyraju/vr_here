import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, FileText, CheckCircle2, ShieldCheck, AlertTriangle, Calendar, Layers, Activity, Phone, LayoutDashboard } from 'lucide-react';
import { SharedFooter, SharedHeader } from './components/SharedComponents';
import ConsultationPaymentModal from './components/ConsultationPaymentModal';
import { launchRazorpayCheckout } from './utils/razorpayCheckout';
import { showPaymentSuccessPopup } from './utils/paymentSuccessPopup';

const CompaniesComplianceScheme = () => {
    const navigate = useNavigate();

    // Staff Authorization Banner Setup
    const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
    const isAuthorized = userInfo && (userInfo.role === 'admin' || userInfo.role === 'employee');

    const [isScrolled, setIsScrolled] = useState(false);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [selectedPlan, setSelectedPlan] = useState(null);
    const [formData, setFormData] = useState({
        name: userInfo?.name || '',
        email: userInfo?.email || '',
        phone: userInfo?.phone || ''
    });

    useEffect(() => {
        const onScroll = () => setIsScrolled(window.scrollY > 20);
        window.addEventListener('scroll', onScroll);
        return () => window.removeEventListener('scroll', onScroll);
    }, []);

    const handleConsultationBook = () => {
        setSelectedPlan({
            id: 'consultation',
            name: 'Expert Consultation',
            price: 499,
            isAdjustable: true,
            description: 'Start here if you are unsure. Fee fully adjustable against registration.',
            features: ['30 Mins CA/CS Call', 'Eligibility Check', 'Compliance Roadmap'],
            buttonText: 'Book Consultation'
        });
        setIsModalOpen(true);
    };

    const handleFormSubmit = ({ formData: submittedFormData, termsAccepted }) => {
        if (!termsAccepted) {
            alert('Please accept the Terms & Conditions before proceeding.');
            return;
        }
        const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
        setFormData(submittedFormData);

        launchRazorpayCheckout({
            serviceName: 'CCFS Consultation',
            selectedPlan,
            formData: submittedFormData,
            token: userInfo?.token,
            onSubmittingChange: setIsSubmitting,
            onSuccess: async (data) => {
                const requiresEmailLogin = Boolean(data?.resetLinkSent);
                await showPaymentSuccessPopup({
                    serviceName: selectedPlan?.name || data?.order?.serviceName,
                    paymentId: data?.payment?.paymentId,
                    requiresEmailLogin
                });
                setIsModalOpen(false);
                setFormData({ name: '', email: '', phone: '' });
                window.location.href = requiresEmailLogin ? '/login' : '/customer-dashboard';
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

    return (
        <div className="min-h-screen bg-slate-50 text-slate-800">
            <SharedHeader isScrolled={isScrolled} />
            <ConsultationPaymentModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                selectedPlan={selectedPlan}
                initialFormData={formData}
                onSubmit={handleFormSubmit}
                isSubmitting={isSubmitting}
                formatCurrency={formatCurrency}
                title={selectedPlan?.buttonText || 'Book Consultation'}
                initialTermsAccepted={false}
            />

            {/* Hero Section */}
            <section className="relative overflow-hidden bg-slate-900 text-white pt-24 pb-20">
                <div className="absolute inset-0">
                    <div className="absolute -top-16 right-20 h-72 w-72 rounded-full bg-red-600/30 blur-3xl" />
                    <div className="absolute -bottom-16 left-10 h-72 w-72 rounded-full bg-orange-500/25 blur-3xl" />
                    <div className="absolute inset-0 opacity-20 bg-[radial-gradient(circle_at_20%_20%,#ffffff,transparent_30%),radial-gradient(circle_at_80%_40%,#ff7849,transparent_30%)]" />
                </div>
                <div className="relative z-10 max-w-6xl mx-auto px-4 text-center">
                    <div className="inline-flex items-center gap-2 rounded-full border border-red-500/30 bg-red-500/10 px-4 py-1.5 text-xs font-bold uppercase tracking-wider text-red-100 backdrop-blur-md mb-6">
                        <Activity className="w-4 h-4 text-red-400" />
                        Limited Time Compliance Window
                    </div>
                    <h1 className="text-4xl md:text-6xl font-black tracking-tight leading-tight">
                        Companies Compliance <br /> Facilitation Scheme 2026
                    </h1>
                    <p className="mt-6 max-w-3xl mx-auto text-lg text-slate-300">
                        Missed ROC filings for years? Clear your backlogs without heavy penalties. CCFS-2026 allows defaulting companies to file pending documents and regularise compliance with up to 90% savings on additional fees.
                    </p>
                    <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
                        <a href="/contact?service=CCFS-2026 Filing Support" className="inline-flex items-center gap-2 bg-red-600 hover:bg-red-700 px-6 py-3.5 rounded-xl font-bold text-sm shadow-xl shadow-red-600/20 transition-all hover:-translate-y-1">
                            Get Help with CCFS Filing <ArrowRight className="w-4 h-4" />
                        </a>
                        <button onClick={handleConsultationBook} className="inline-flex items-center gap-2 bg-white text-slate-900 border border-slate-200 hover:bg-slate-50 px-6 py-3.5 rounded-xl font-bold text-sm shadow-xl shadow-black/5 transition-all hover:-translate-y-1">
                            <Phone className="w-4 h-4 text-red-600" /> Book Consultation @ ₹499
                        </button>
                    </div>
                </div>
            </section>

            {/* Main Content */}
            <section className="max-w-6xl mx-auto px-4 py-16 grid lg:grid-cols-3 gap-8">
                
                {/* Left Column: Details */}
                <div className="lg:col-span-2 space-y-10">
                    {/* What is it? */}
                    <div>
                        <h2 className="text-2xl font-black text-slate-900 mb-4 flex items-center gap-2">
                            <Layers className="w-6 h-6 text-red-600" /> What is CCFS-2026?
                        </h2>
                        <div className="prose prose-slate max-w-none text-slate-600">
                            <p>
                                The Companies Compliance Facilitation Scheme is a temporary compliance window introduced by the MCA. Many companies fail to file statutory documents with the ROC, leading to heavy penalties. CCFS-2026 gives these companies a chance to clean up their records.
                            </p>
                            <p>
                                During the scheme period, <strong>only 10% of the additional fees</strong> applicable for delayed filings are payable. This scheme is wider in scope than previous ones, also accommodating options like dormancy and strike-off.
                            </p>
                        </div>
                    </div>

                    {/* Benefits */}
                    <div className="bg-white rounded-2xl border border-slate-200 p-6 md:p-8 shadow-sm">
                        <h2 className="text-2xl font-black text-slate-900 mb-6">Key Benefits</h2>
                        <div className="grid sm:grid-cols-2 gap-4">
                            {[
                                'Pay only 10% of additional penalties for delayed filings',
                                'Bring statutory records up to date for funding or loans',
                                'Significantly reduce regulatory exposure from ROC',
                                'Shift to dormancy or apply for strike-off smoothly',
                                'Obtain immunity from prosecution for delayed filings'
                            ].map((item, index) => (
                                <div key={index} className="flex items-start gap-3 bg-slate-50 p-4 rounded-xl border border-slate-100">
                                    <CheckCircle2 className="w-5 h-5 text-green-600 shrink-0 mt-0.5" />
                                    <span className="text-sm font-medium text-slate-700">{item}</span>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Flow/Steps */}
                    <div>
                        <h2 className="text-2xl font-black text-slate-900 mb-6">How to File Under CCFS-2026</h2>
                        <div className="space-y-4">
                            {[
                                { title: 'Identify Pending Filings', desc: 'Find all pending ROC filings from the MCA portal.' },
                                { title: 'Prepare Financials', desc: 'Prepare financial statements and supporting documents for the years unfiled.' },
                                { title: 'Submit e-Forms', desc: 'Submit the required event-based and annual e-forms through the MCA system.' },
                                { title: 'Pay Reduced Fees', desc: 'Pay standard filing fee + only 10% of the normal additional delayed fees.' }
                            ].map((step, index) => (
                                <div key={index} className="flex gap-4 p-5 rounded-xl border border-slate-200 bg-white hover:border-red-200 transition-colors">
                                    <div className="h-10 w-10 shrink-0 bg-red-100 text-red-600 rounded-full flex items-center justify-center font-black text-lg">
                                        {index + 1}
                                    </div>
                                    <div>
                                        <h3 className="font-bold text-slate-900">{step.title}</h3>
                                        <p className="text-sm text-slate-600 mt-1">{step.desc}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Right Column: Key Facts Widget */}
                <div className="space-y-6">
                    <div className="bg-slate-900 rounded-2xl p-6 text-white shadow-xl">
                        <h3 className="text-xl font-bold flex items-center gap-2 mb-4">
                            <Calendar className="w-5 h-5 text-red-400" /> Scheme Validity
                        </h3>
                        <p className="text-slate-300 text-sm mb-4">The window is strictly time-bound. Filings must be submitted before the scheme closes.</p>
                        <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                            <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Open Period</div>
                            <div className="text-red-400 font-bold text-lg">15 April 2026</div>
                            <div className="text-sm text-slate-500 my-1">to</div>
                            <div className="text-red-400 font-bold text-lg">15 July 2026</div>
                        </div>
                    </div>

                    <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm">
                        <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                            <AlertTriangle className="w-5 h-5 text-amber-500" /> Applicability
                        </h3>
                        <div className="text-sm text-slate-600 space-y-3">
                            <p><strong>Applies to:</strong> Defaulting companies that did not file annual returns, financial statements, or accumulated several years of pending forms.</p>
                            <p className="pt-2 border-t border-slate-100"><strong>Does NOT apply to:</strong></p>
                            <ul className="list-disc pl-4 space-y-1 text-slate-500">
                                <li>Companies with final strike-off notices</li>
                                <li>Companies amalgamated/dissolved</li>
                                <li>Vanishing companies</li>
                            </ul>
                        </div>
                    </div>

                    <div className="bg-red-50 rounded-2xl p-6 border border-red-100">
                        <h3 className="text-sm font-bold text-red-800 uppercase tracking-wide mb-2 flex items-center gap-2">
                            <FileText className="w-4 h-4" /> Eligible Forms
                        </h3>
                        <p className="text-sm text-red-900/80 mb-4">Includes Financial Statements, Annual Returns, and certain event-based forms that remain pending.</p>
                        <a href="/contact?service=CCFS Form Verification" className="w-full block text-center bg-white text-red-600 py-2.5 rounded-lg text-sm font-bold border border-red-200 hover:border-red-300 hover:bg-slate-50 transition">
                            Verify Your Eligibility
                        </a>
                    </div>

                    <div className="bg-gradient-to-br from-slate-900 to-slate-800 text-white rounded-2xl p-6 border border-slate-700 shadow-xl relative overflow-hidden group hover:shadow-2xl transition-all">
                        <div className="absolute -top-6 -right-6 p-4 opacity-10 group-hover:opacity-20 group-hover:rotate-12 transition-all duration-500">
                            <Phone className="w-32 h-32 text-orange-400" />
                        </div>
                        <div className="relative z-10">
                            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-orange-500/20 text-orange-300 border border-orange-500/30 text-xs font-black uppercase tracking-wider mb-4">
                                <Activity className="w-3.5 h-3.5" /> Expert Advice
                            </div>
                            <h3 className="text-2xl font-black mb-2 leading-tight">
                                Book a CCFS <br/> Consultation
                            </h3>
                            <p className="text-slate-400 text-sm mb-6 max-w-[90%]">
                                Unclear if your past pending forms qualify? Not sure about the process? Talk to our compliance experts directly.
                            </p>
                            <button onClick={handleConsultationBook} className="w-full flex items-center justify-center gap-2 bg-orange-500 hover:bg-orange-600 text-white py-3.5 rounded-xl font-bold shadow-lg shadow-orange-500/25 transition-all hover:-translate-y-0.5">
                                <Phone className="w-5 h-5" /> Book Now @ ₹499
                            </button>
                        </div>
                    </div>
                </div>

            </section>

            <SharedFooter />
        </div>
    );
};

export default CompaniesComplianceScheme;
