import React, { useState, useEffect } from 'react';
import {
    Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
    Phone, Menu, X, ChevronDown, Clock, Award, Search, ArrowRight, CheckCircle2,
    Building2, Mail, MapPin, CheckCircle, FileText, Star, Users, Check, HelpCircle,
    MessageSquare, Zap, ShieldCheck, TrendingUp, Anchor, Truck, Hammer, FileCheck,
    ChevronRight, Download, PlayCircle, Loader2, CreditCard, RefreshCw
} from 'lucide-react';
import { RAZORPAY_KEY_ID } from './config';
import { SharedHeader, SharedFooter } from './components/SharedComponents';
import ConsultationPaymentModal from './components/ConsultationPaymentModal';
import { launchRazorpayCheckout } from './utils/razorpayCheckout';

// SERVICES_DATA removed (handled by SharedHeader)

/* --- PACKAGES --- */
const PACKAGES = [
    {
        id: 'consultation',
        name: 'Expert Consultation',
        price: 499,
        isAdjustable: true,
        description: 'Start here if you are unsure. Fee fully adjusted against registration.',
        features: ['30 Mins CA/CS Call', 'Business Structure Advice', 'Name Availability Check', 'Capital Structure Guidance', 'Compliance Roadmap'],
        buttonText: 'Book Consultation'
    },
    {
        id: 'basic',
        name: 'Basic',
        price: 4899,
        description: 'Essential registration for partnership firms.',
        features: ['Partnership Deed Drafting', 'PAN & TAN Applications', 'Firm Registration', 'Legal Advice on Clause', 'Notary & Stamp Assistance'],
        buttonText: 'Select Basic'
    },
    {
        id: 'advance',
        name: 'Advance',
        price: 8221,
        isPopular: true,
        description: 'Registration plus core compliance setup.',
        features: ['Everything in Basic', 'GST Registration', 'MSME (Udyam) Registration', 'Current Account Assistance', 'Business Commencement Setup'],
        buttonText: 'Select Advance'
    },
    {
        id: 'expert',
        name: 'Expert',
        price: 10209,
        description: 'Comprehensive package with import/export code.',
        features: ['Everything in Advance', 'Import Export Code (IEC)', '2 Months GST Filing', 'Post-registration Guidance', 'Dedicated Relationship Manager'],
        buttonText: 'Select Expert'
    }
];

const PartnershipFirmPage = () => {
    // --- STATE ---
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    const [activeMobileCategory, setActiveMobileCategory] = useState(null);
    const [isServicesHovered, setIsServicesHovered] = useState(false);
    const [isScrolled, setIsScrolled] = useState(false);
    const [loading, setLoading] = useState(true);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [termsAccepted, setTermsAccepted] = useState(false);
    const [selectedPlan, setSelectedPlan] = useState(null);

    // --- EFFECTS ---
    useEffect(() => {
        const timer = setTimeout(() => setLoading(false), 1500);
        const handleScroll = () => {
            setIsScrolled(window.scrollY > 20);
            if (isServicesHovered) setIsServicesHovered(false);
        };
        window.addEventListener('scroll', handleScroll);
        return () => {
            window.removeEventListener('scroll', handleScroll);
            clearTimeout(timer);
        };
    }, [isServicesHovered]);

    // --- ACTIONS ---

    const [formData, setFormData] = useState({
        name: '',
        email: '',
        phone: ''
    });

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleConsultationBook = () => {
        setSelectedPlan(PACKAGES[0]); // Set consultation as selected
        setTermsAccepted(false);
        setIsModalOpen(true);
    };

    const handleSelectPlan = (plan) => {
        setSelectedPlan(plan);
        setTermsAccepted(false);
        setIsModalOpen(true);
    };

    const handleFormSubmit = (e) => {
        e.preventDefault();
        if (!termsAccepted) {
            alert('Please accept the Terms & Conditions before proceeding.');
            return;
        }
        const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');

        launchRazorpayCheckout({
            serviceName: 'Partnership Firm Registration',
            selectedPlan,
            formData,
            token: userInfo?.token,
            onSubmittingChange: setIsSubmitting,
            onSuccess: (data) => {
                alert(`Payment Successful! Booking Confirmed. Payment ID: ${data.payment.paymentId}`);
                setIsModalOpen(false);
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

    // --- SUB-COMPONENTS ---

    // Header definition removed

    // Floating Buttons
    const FloatingButtons = () => (
        <div className="fixed bottom-6 right-6 z-40 flex flex-col gap-3">
            <a href="https://wa.me/918008530606" target="_blank" rel="noreferrer" className="bg-green-500 hover:bg-green-600 text-white p-4 rounded-full shadow-lg hover:shadow-2xl transition-all duration-300 transform hover:scale-110 flex items-center justify-center group relative">
                <MessageSquare className="w-6 h-6" />
                <span className="absolute right-full mr-3 bg-black text-white text-xs font-bold px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">Chat on WhatsApp</span>
            </a>
            <a href="tel:+918008530606" className="bg-black hover:bg-slate-800 text-white p-4 rounded-full shadow-lg hover:shadow-2xl transition-all duration-300 transform hover:scale-110 flex items-center justify-center group relative">
                <Phone className="w-6 h-6" />
                <span className="absolute right-full mr-3 bg-black text-white text-xs font-bold px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">Call Expert</span>
            </a>
        </div>
    );

    // Preloader
    if (loading) {
        return (
            <div className="fixed inset-0 bg-white z-[100] flex flex-col items-center justify-center">
                <div className="w-20 h-20 bg-black rounded-2xl flex items-center justify-center mb-6 animate-bounce">
                    <span className="text-white font-black text-3xl">VR</span>
                </div>
                <div className="flex items-center space-x-2 text-sm font-bold tracking-widest text-slate-400">
                    LOADING EXPERIENCE...
                </div>
            </div>
        );
    }

    return (
        <div className="font-sans text-slate-800 bg-white min-h-screen selection:bg-red-100 selection:text-red-900 overflow-x-hidden">
            <SharedHeader isScrolled={isScrolled} />
            <ConsultationPaymentModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                selectedPlan={selectedPlan}
                formData={formData}
                onInputChange={handleInputChange}
                termsAccepted={termsAccepted}
                onTermsChange={setTermsAccepted}
                onSubmit={handleFormSubmit}
                isSubmitting={isSubmitting}
                formatCurrency={formatCurrency}
                title={selectedPlan?.id === 'consultation' ? 'Book Consultation' : 'Get Started'}
                nonAdjustableNote="+ Government Fees & GST"
            />
            <FloatingButtons />

            {/* LANDING CONTENT: PARTNERSHIP FIRM REGISTRATION */}
            <div className="animate-fade-in">

                {/* 1. Hero Section */}
                <div className="relative pt-16 pb-20 lg:pt-24 lg:pb-32 bg-slate-50 overflow-hidden">
                    <div className="absolute top-0 right-0 w-1/2 h-full bg-red-50 skew-x-12 opacity-50 z-0 translate-x-1/3"></div>
                    <div className="max-w-7xl mx-auto px-4 relative z-10 flex flex-col lg:flex-row items-center gap-12">
                        <div className="lg:w-1/2">
                            <div className="inline-flex items-center px-4 py-1.5 rounded-full bg-white border border-slate-200 shadow-sm text-sm font-bold text-slate-600 mb-6">
                                <span className="w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></span>
                                India's #1 Registration Platform
                            </div>
                            <h1 className="text-4xl lg:text-6xl font-black text-slate-900 tracking-tight leading-[1.1] mb-6">
                                Register Your <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-600 to-orange-600">Partnership Firm</span> Online.
                            </h1>
                            <p className="text-xl text-slate-600 leading-relaxed mb-8">
                                Start your journey with a valid Partnership Deed, PAN, and Registration. Fastest processing with expert legal drafting.
                            </p>

                            <div className="flex flex-col sm:flex-row gap-4 mb-8">
                                <button onClick={handleConsultationBook} className="bg-red-600 text-white px-8 py-4 rounded-xl font-bold text-lg hover:bg-red-700 transition shadow-xl shadow-red-600/20 transform hover:-translate-y-1 active:scale-95 flex items-center justify-center">
                                    Book Consultation @ ₹499 <ArrowRight className="ml-2 w-5 h-5" />
                                </button>
                                <p className="text-xs text-slate-500 sm:hidden text-center mt-2">Adjusted against final package</p>
                            </div>
                            <div className="flex items-center space-x-2 text-sm font-medium text-slate-500">
                                <CheckCircle2 className="w-4 h-4 text-green-500" /> <span>Fee adjustable in final package</span>
                            </div>
                        </div>

                        {/* Hero Graphic */}
                        <div className="lg:w-1/2 relative hidden lg:block">
                            <div className="relative z-10 bg-white p-8 rounded-2xl shadow-2xl border border-slate-100 transform rotate-2 hover:rotate-0 transition duration-500">
                                <div className="flex justify-between items-start mb-6">
                                    <div>
                                        <h3 className="text-xl font-bold text-slate-900">Partnership Package</h3>
                                        <p className="text-slate-500 text-sm">All-inclusive starting at ₹4,899</p>
                                    </div>
                                    <div className="bg-green-100 text-green-700 font-bold px-3 py-1 rounded text-xs">VERIFIED</div>
                                </div>
                                <div className="space-y-4">
                                    {['Partnership Deed Drafting', 'Firm Registration', 'PAN & TAN Applications', 'Notary & Stamp Paper Support', 'Business Setup Advice'].map((item, i) => (
                                        <div key={i} className="flex items-center p-3 bg-slate-50 rounded-lg">
                                            <CheckCircle className="w-5 h-5 text-red-600 mr-3" />
                                            <span className="font-medium text-slate-700">{item}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                            {/* Abstract Blob */}
                            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[120%] h-[120%] bg-gradient-to-tr from-red-100 to-orange-100 rounded-full blur-3xl -z-10 opacity-60"></div>
                        </div>
                    </div>
                </div>

                {/* 2. Stats & Trust */}
                <div className="bg-black py-12 border-t-4 border-red-600">
                    <div className="max-w-7xl mx-auto px-4 grid grid-cols-2 md:grid-cols-4 gap-8 text-center divide-x divide-slate-800">
                        <div className="group hover:bg-slate-900/50 p-2 rounded transition"><div className="text-3xl md:text-4xl font-bold text-white mb-1 group-hover:text-red-500 transition-colors">4 Days</div><div className="text-red-500 text-sm uppercase tracking-wide font-bold group-hover:text-white transition-colors">Avg. Turnaround</div></div>
                        <div className="group hover:bg-slate-900/50 p-2 rounded transition"><div className="text-3xl md:text-4xl font-bold text-white mb-1 group-hover:text-red-500 transition-colors">2000+</div><div className="text-red-500 text-sm uppercase tracking-wide font-bold group-hover:text-white transition-colors">Partnerships</div></div>
                        <div className="group hover:bg-slate-900/50 p-2 rounded transition"><div className="text-3xl md:text-4xl font-bold text-white mb-1 group-hover:text-red-500 transition-colors">4.8/5</div><div className="text-red-500 text-sm uppercase tracking-wide font-bold group-hover:text-white transition-colors">Google Rating</div></div>
                        <div className="group hover:bg-slate-900/50 p-2 rounded transition"><div className="text-3xl md:text-4xl font-bold text-white mb-1 group-hover:text-red-500 transition-colors">100%</div><div className="text-red-500 text-sm uppercase tracking-wide font-bold group-hover:text-white transition-colors">Transparency</div></div>
                    </div>
                </div>

                {/* 3. Steps to Register */}
                <section className="py-20 bg-white">
                    <div className="max-w-6xl mx-auto px-4">
                        <div className="text-center mb-16">
                            <h2 className="text-3xl font-black text-slate-900 mb-4">How It Works</h2>
                            <p className="text-lg text-slate-600">Form your partnership in 3 simple steps.</p>
                        </div>
                        <div className="grid md:grid-cols-3 gap-8 relative">
                            <div className="hidden md:block absolute top-12 left-0 w-full h-0.5 bg-slate-100 -z-10"></div>
                            {[
                                { title: "Share Details", desc: "Fill our simple form and expert consultation to draft the best deed." },
                                { title: "Drafting & Review", desc: "We draft the Partnership Deed and send it for your approval and signature." },
                                { title: "Registration", desc: "We apply for PAN, TAN and register the firm with the authorities." }
                            ].map((step, i) => (
                                <div key={i} className="bg-white p-8 rounded-2xl shadow-lg border border-slate-100 text-center hover:-translate-y-2 transition-transform duration-300">
                                    <div className="w-16 h-16 bg-red-600 text-white rounded-full flex items-center justify-center text-2xl font-black mx-auto mb-6 shadow-md border-4 border-white">{i + 1}</div>
                                    <h3 className="font-bold text-xl text-slate-900 mb-3">{step.title}</h3>
                                    <p className="text-slate-600">{step.desc}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                </section>

                {/* 4. Why Partnership? */}
                <section className="py-20 bg-slate-50">
                    <div className="max-w-7xl mx-auto px-4 flex flex-col md:flex-row gap-12 items-center">
                        <div className="md:w-1/2">
                            <h2 className="text-3xl font-black text-slate-900 mb-6">Why Register a Partnership Firm?</h2>
                            <p className="text-slate-600 mb-8 leading-relaxed">
                                Partnerships are ideal for small businesses with multiple owners. They offer flexibility in operations and shared responsibilities.
                            </p>
                            <div className="grid grid-cols-1 gap-4">
                                {[
                                    { t: "Easy Formation", d: "Simpler and cheaper to start compared to LLP or Pvt Ltd." },
                                    { t: "Shared Responsibility", d: "Partners share duties, profits, and liabilities." },
                                    { t: "Less Compliance", d: "Fewer annual filings and statutory audits required." },
                                    { t: "Flexibility", d: "Decision making is faster and deed can be changed easily." }
                                ].map((item, i) => (
                                    <div key={i} className="flex items-start p-4 bg-white rounded-xl border border-slate-200">
                                        <CheckCircle2 className="w-6 h-6 text-green-500 mr-4 flex-shrink-0" />
                                        <div>
                                            <h4 className="font-bold text-slate-900">{item.t}</h4>
                                            <p className="text-sm text-slate-500">{item.d}</p>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                        <div className="md:w-1/2">
                            <div className="bg-white p-8 rounded-3xl shadow-xl border border-slate-100">
                                <h3 className="text-xl font-black text-slate-900 mb-6 text-center">Minimum Requirements</h3>
                                <ul className="space-y-4">
                                    {[
                                        "Minimum 2 Partners",
                                        "A Partnership Deed",
                                        "Business Place Address Proof",
                                        "Identity Proof of Partners"
                                    ].map((req, i) => (
                                        <li key={i} className="flex items-center text-slate-700 bg-slate-50 p-3 rounded-lg">
                                            <Users className="w-5 h-5 text-red-600 mr-3" /> {req}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Pricing */}
                <section id="pricing" className="py-20 bg-slate-50">
                    <div className="max-w-[1400px] mx-auto px-4">
                        <div className="text-center mb-16"><h2 className="text-3xl font-black text-slate-900 mb-4">Registration Fees & Packages</h2><p className="text-slate-600">Transparent pricing. 499 Consultation adjusted in final bill.</p></div>
                        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-[1400px] mx-auto">
                            {PACKAGES.map((pkg) => (
                                <div key={pkg.id} className={`bg-white rounded-2xl p-8 border transition-all duration-300 flex flex-col relative transform hover:-translate-y-4 hover:shadow-2xl ${pkg.isPopular ? 'border-red-600 shadow-xl scale-105 z-10' : 'border-slate-200 hover:border-red-300 shadow-sm'}`}>
                                    {pkg.isPopular && <div className="absolute top-0 right-0 bg-red-600 text-white text-xs font-bold px-3 py-1 rounded-bl-lg rounded-tr-lg shadow-md">RECOMMENDED</div>}

                                    <h3 className="text-xl font-bold text-slate-900 mb-2">{pkg.name}</h3>
                                    <div className="text-4xl font-black text-slate-900 mb-6">
                                        {formatCurrency(pkg.price)}
                                        <span className="text-[10px] font-bold text-slate-500 ml-1 block mt-1">
                                            {pkg.isAdjustable ? '(Fully Adjustable)' : '+ Govt Fees & GST'}
                                        </span>
                                    </div>

                                    {pkg.isAdjustable && (
                                        <div className="bg-green-50 text-green-700 text-xs font-bold p-2 rounded mb-4 flex items-center">
                                            <RefreshCw className="w-3 h-3 mr-1" /> Fee Adjustable in Final Package
                                        </div>
                                    )}

                                    <p className="text-sm text-slate-600 mb-6">{pkg.description}</p>

                                    <div className="space-y-4 mb-8 flex-1">
                                        {pkg.features.map((feat, i) => (
                                            <div key={i} className="flex items-start text-sm text-slate-700 font-medium group"><CheckCircle2 className="w-4 h-4 text-green-500 mr-2 mt-0.5 flex-shrink-0 group-hover:scale-125 transition-transform" />{feat}</div>
                                        ))}
                                    </div>
                                    <button onClick={() => handleSelectPlan(pkg)} className={`w-full py-4 rounded-xl font-bold transition transform active:scale-95 ${pkg.isPopular || pkg.isAdjustable ? 'bg-red-600 text-white hover:bg-red-700 shadow-lg shadow-red-600/30' : 'bg-slate-100 text-slate-900 hover:bg-slate-200'}`}>
                                        {pkg.buttonText}
                                    </button>
                                </div>
                            ))}
                        </div>
                    </div>
                </section>

                {/* 5. Consultation CTA Area */}
                <section className="py-24 bg-slate-900 text-white relative overflow-hidden">
                    <div className="absolute inset-0 opacity-20 bg-[radial-gradient(#ffffff_1px,transparent_1px)] [background-size:16px_16px]"></div>
                    <div className="max-w-4xl mx-auto px-4 text-center relative z-10">
                        <h2 className="text-3xl lg:text-5xl font-black mb-6">Need clarity on Partnerships?</h2>
                        <p className="text-xl text-slate-400 mb-10">
                            Speak with our legal experts. We help you draft the perfect Deed to avoid future disputes.
                        </p>
                        <div className="bg-white/10 backdrop-blur-md p-8 rounded-3xl border border-white/10 inline-block w-full max-w-md">
                            <div className="text-sm font-bold text-red-400 uppercase tracking-widest mb-2">Consultation Offer</div>
                            <div className="text-5xl font-black mb-2">₹499</div>
                            <p className="text-slate-300 text-sm mb-6">Fully adjustable against registration fees</p>
                            <button onClick={handleConsultationBook} className="w-full bg-red-600 text-white font-bold py-4 rounded-xl hover:bg-red-700 transition shadow-lg shadow-red-600/30 flex items-center justify-center">
                                Book Now <ArrowRight className="ml-2 w-5 h-5" />
                            </button>
                        </div>
                    </div>
                </section>

            </div>

            {/* RICH FOOTER SECTION (Kept Same) */}
            <SharedFooter />
        </div>
    );
};

export default PartnershipFirmPage;
