import React, { useState, useEffect } from 'react';
import {
  Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
  Phone, Menu, X, ChevronDown, Clock, Award, Search, ArrowRight, CheckCircle2,
  Building2, Mail, MapPin, CheckCircle, FileText, Star, User as UsersIcon, Check, HelpCircle,
  MessageSquare, Zap, ShieldCheck, TrendingUp, Anchor, Truck, Hammer, FileCheck,
  ChevronRight, Download, PlayCircle, Loader2, CreditCard, RefreshCw
} from 'lucide-react';
import * as Lucide from 'lucide-react';
import { SharedHeader, SharedFooter } from './components/SharedComponents';
import ConsultationPaymentModal from './components/ConsultationPaymentModal';
import { launchRazorpayCheckout } from './utils/razorpayCheckout';
import { useNavigate } from 'react-router-dom';
import { showPaymentSuccessPopup } from './utils/paymentSuccessPopup';
import { fetchServicePageConfig, updateServicePageConfig } from './modules/service-editor/v1.1/services/serviceConfigApi';
import InlineEditOverlay from './modules/service-editor/v1.1/components/InlineEditOverlay';
import SeoAeoDashboard from './modules/seo-aeo-analyzer/v1.1/components/SeoAeoDashboard';
import { injectTrackingScripts } from './modules/seo-aeo-analyzer/v1.1/components/TrackingSettings';

// Cache-busting trigger: May 29 2026 15:05

/* --- UPDATED PACKAGES --- */
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
    price: 5499,
    description: 'Essential registration for verified startups.',
    features: ['Name Approval (RUN)', 'Certificate of Incorporation', 'PAN & TAN', 'MOA & AOA', '2 DIN & 2 DSC', 'PF & ESI Registration', 'MSME Registration', '1 Month Accounts Support'],
    buttonText: 'Select Basic'
  },
  {
    id: 'advance',
    name: 'Advance',
    price: 11399,
    isPopular: true,
    description: 'Complete compliance & web presence.',
    features: ['Everything in Basic', 'GST Registration', 'Import Export Code (IEC)', 'ISO Certification', 'GST Returns (2 Months)', 'Auditor Appointment', 'Business Commencement', 'Professional Website', '1 Yr Domain & Hosting'],
    buttonText: 'Select Advance'
  },
  {
    id: 'expert',
    name: 'Expert',
    price: 17699,
    description: 'Comprehensive package with IT filing.',
    features: ['Everything in Advance', 'Individual IT Filing', 'Google Analytics', 'Web Mails', 'Basic On-page SEO', 'Website Support (1 Yr)', 'Dedicated Relationship Mgr'],
    buttonText: 'Select Expert'
  }
];

/* --- NEW COMPONENT DATA --- */
import { 
  Briefcase as SuiteIcon
} from 'lucide-react';

const LOGOS = [
  { name: 'Stripe for Startups', icon: SuiteIcon, color: 'text-indigo-600' },
  { name: 'Razorpay Partner', icon: Zap, color: 'text-blue-500' },
  { name: 'Google Cloud Program', icon: Globe, color: 'text-red-500' },
  { name: 'AWS Activate', icon: Factory, color: 'text-orange-500' },
  { name: 'Microsoft Founders Hub', icon: Building2, color: 'text-blue-600' },
  { name: 'Shopify Partners', icon: ShieldCheck, color: 'text-emerald-500' },
  { name: 'HubSpot Ecosystem', icon: Award, color: 'text-orange-600' }
];

const REVIEWS = [
  {
    name: "Vikram Malhotra",
    company: "Trident Tech Solutions Pvt Ltd",
    avatar: "VM",
    rating: 5,
    date: "14 May 2026",
    text: "The Pvt Ltd registration was amazingly fast! We paid the consultation fee of 499, and it was fully adjusted in our final payment. We got our COI, PAN, and TAN in exactly 6 days without any follow-ups.",
    verified: true
  },
  {
    name: "Ananya Iyer",
    company: "Aura CleanTech Pvt Ltd",
    avatar: "AI",
    rating: 5,
    date: "28 April 2026",
    text: "Excellent service. The dashboard was super simple to upload documents, and their CA walked us through the name approval rules which saved us from rejection. Highly recommended for first-time founders!",
    verified: true
  },
  {
    name: "Ritesh Deshmukh",
    company: "Pixel Labs Pvt Ltd",
    avatar: "RD",
    rating: 5,
    date: "03 May 2026",
    text: "Top-notch professionalism. I got my company incorporated, PF/ESI registration, and even a premium business website set up through their Advance Package. Everything was delivered transparently.",
    verified: true
  }
];

const STEPS = [
  {
    number: "01",
    title: "1-Tap Expert Consultation",
    desc: "Book a consultation for just ₹499. Our CAs and CS specialists analyze your business idea, recommend the ideal package, and check name availability.",
    badge: "Takes 15 Mins"
  },
  {
    number: "02",
    title: "Secure Document Vault Upload",
    desc: "Upload basic KYC details (Aadhaar, PAN, and address proof) to our secure vault. Your information is protected by industry-leading security.",
    badge: "Takes 10 Mins"
  },
  {
    number: "03",
    title: "Government Filing & Incorporation",
    desc: "We file the RUN name approval, SPICe+ incorporation forms, PAN/TAN, and MSME registrations. You receive the Certificate of Incorporation by email!",
    badge: "Delivered in 7 Days"
  }
];

const FAQS = [
  {
    q: "How much time does it take to register a Private Limited Company?",
    a: "On average, the entire process takes about 5 to 7 working days, subject to state-wise government processing times. This includes obtaining DSC, DIN, name approval, and the final Certificate of Incorporation (COI)."
  },
  {
    q: "Is the ₹499 consultation fee really refundable?",
    a: "Yes, 100%! When you book a CA/CS consultation for ₹499, the full amount is converted into a coupon credit. Once you proceed to purchase any of our packages (Basic, Advance, or Expert), the ₹499 is automatically deducted from your final package price."
  },
  {
    q: "What are the minimum requirements to register a Pvt Ltd company?",
    a: "You need a minimum of 2 directors (who can also be the shareholders), at least one of whom must be an Indian resident, and a registered address in India (which can be a residential or rented address)."
  },
  {
    q: "Do I need a commercial office address to register my business?",
    a: "No. The MCA allows you to register your company using a residential address. You only need to provide a recent utility bill (electricity/gas bill) and a No Objection Certificate (NOC) from the owner."
  }
];

const RELATED_SERVICES = [
  {
    title: "Limited Liability Partnership (LLP)",
    price: "₹7,899",
    desc: "Perfect for partners who want limited liability with simpler compliances compared to a Private Limited company.",
    link: "/llp-registration"
  },
  {
    title: "One Person Company (OPC)",
    price: "₹5,999",
    desc: "Single founder setup with all the benefits of a Private Limited company. Protect your personal liability with full control.",
    link: "/opc-registration"
  },
  {
    title: "GST Registration & Filing",
    price: "₹2,569",
    desc: "Get your GSTIN quickly and ensure smooth tax compliance. Highly recommended for e-commerce and interstate vendors.",
    link: "/gst-registration"
  },
  {
    title: "Trademark Registration",
    price: "₹4,500",
    desc: "Secure your brand name, logo, and slogan. Protect your brand identity from competitors and copycats legally.",
    link: "/trademark"
  }
];

const PrivateLimitedPage = () => {
  const navigate = useNavigate();
  // --- STATE ---
  const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
  const isAuthorized = userInfo && (userInfo.role === 'admin' || userInfo.role === 'employee');

  const [pageConfig, setPageConfig] = useState(null);
  const [pageHtmlContent, setPageHtmlContent] = useState('');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activeMobileCategory, setActiveMobileCategory] = useState(null);
  const [isServicesHovered, setIsServicesHovered] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [isSeoExpanded, setIsSeoExpanded] = useState(false);
  const [activeFaq, setActiveFaq] = useState(null);
  const [savingOverlay, setSavingOverlay] = useState(false);

  const handleUpdateSeoSettings = async (seo) => {
    setSavingOverlay(true);
    try {
      const updated = { ...pageConfig, seoSettings: seo };
      const data = await updateServicePageConfig('private-limited', updated);
      setPageConfig(data.page);
    } catch (err) {
      console.error('Failed to update SEO settings:', err);
    } finally {
      setSavingOverlay(false);
    }
  };

  const handleUpdateTrackingSettings = async (tracking) => {
    setSavingOverlay(true);
    try {
      const updated = { ...pageConfig, trackingSettings: tracking };
      const data = await updateServicePageConfig('private-limited', updated);
      setPageConfig(data.page);
    } catch (err) {
      console.error('Failed to update tracking settings:', err);
    } finally {
      setSavingOverlay(false);
    }
  };

  // --- CONFIG EFFECTS ---
  useEffect(() => {
    const loadConfig = async () => {
      try {
        const configData = await fetchServicePageConfig('private-limited');
        setPageConfig(configData);
        if (configData.trackingSettings) {
          injectTrackingScripts(
            configData.trackingSettings.googleAnalyticsId,
            configData.trackingSettings.metaPixelId
          );
        }
      } catch (err) {
        console.error('Failed to load page config, utilizing hardcoded backups:', err);
      }
    };
    loadConfig();
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      const mainEl = document.getElementById('private-limited-container');
      if (mainEl) {
        setPageHtmlContent(mainEl.innerHTML);
      }
    }, 2000);
    return () => clearTimeout(timer);
  }, [pageConfig, loading]);

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
  const activeHero = pageConfig?.hero || {
    title: "Register Your Private Limited Company Online",
    subtitle: "Launch your startup with the most credible legal structure. Get Certificate of Incorporation, PAN, TAN & MOA/AOA in just 7 days.",
    badgeText: "India's #1 Secure Registration Platform",
    consultationPrice: 499
  };

  const activeStats = pageConfig?.stats || [
    { value: '7 Days', label: 'Avg. Turnaround' },
    { value: '5000+', label: 'Happy Founders' },
    { value: '4.9/5', label: 'Google Rating' },
    { value: '100%', label: 'Online Process' }
  ];

  const activeLogos = pageConfig?.logos || LOGOS;
  const activePackages = pageConfig?.packages || PACKAGES;
  const activeReviews = pageConfig?.reviews || REVIEWS;
  const activeSteps = pageConfig?.steps || STEPS;
  const activeFaqs = pageConfig?.faqs || FAQS;

  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: ''
  });

  const handleConsultationBook = () => {
    setSelectedPlan(activePackages[0]); // Set consultation as selected
    setIsModalOpen(true);
  };

  const handleSelectPlan = (plan) => {
    setSelectedPlan(plan);
    setIsModalOpen(true); // Open modal for all plans for simplicity in this landing page demo
  };

  const handleFormSubmit = ({ formData: submittedFormData, termsAccepted }) => {
    if (!termsAccepted) {
      alert('Please accept the Terms & Conditions before proceeding.');
      return;
    }
    const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
    setFormData(submittedFormData);

    launchRazorpayCheckout({
      serviceName: 'Private Limited Registration',
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
        initialFormData={formData}
        onSubmit={handleFormSubmit}
        isSubmitting={isSubmitting}
        formatCurrency={formatCurrency}
        title={selectedPlan?.id === 'consultation' ? 'Book Consultation' : 'Get Started'}
        initialTermsAccepted={false}
      />

      {/* LANDING CONTENT: PRIVATE LIMITED REGISTRATION */}
      <div id="private-limited-container" className="animate-fade-in">

        {/* 1. Hero Section */}
        <div className="relative pt-16 pb-20 lg:pt-24 lg:pb-32 bg-slate-50 overflow-hidden">
          <div className="absolute top-0 right-0 w-1/2 h-full bg-red-50 skew-x-12 opacity-50 z-0 translate-x-1/3"></div>
          <div className="max-w-7xl mx-auto px-4 relative z-10 flex flex-col lg:flex-row items-center gap-12">
            <div className="lg:w-1/2">
              <div className="inline-flex items-center px-4 py-1.5 rounded-full bg-white border border-slate-200 shadow-sm text-sm font-bold text-slate-600 mb-6">
                <span className="w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></span>
                {activeHero.badgeText}
              </div>
              <h1 className="text-4xl lg:text-6xl font-black text-slate-900 tracking-tight leading-[1.1] mb-6">
                {activeHero.title}
              </h1>
              <p className="text-xl text-slate-600 leading-relaxed mb-8">
                {activeHero.subtitle}
              </p>

              <div className="flex flex-col sm:flex-row gap-4 mb-8">
                <button onClick={handleConsultationBook} className="bg-red-600 text-white px-8 py-4 rounded-xl font-bold text-lg hover:bg-red-700 transition shadow-xl shadow-red-600/20 transform hover:-translate-y-1 active:scale-95 flex items-center justify-center">
                  Book Consultation @ ₹{activeHero.consultationPrice} <ArrowRight className="ml-2 w-5 h-5" />
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
                    <h3 className="text-xl font-bold text-slate-900">Registration Package</h3>
                    <p className="text-slate-500 text-sm">All-inclusive starting at ₹6,499</p>
                  </div>
                  <div className="bg-green-100 text-green-700 font-bold px-3 py-1 rounded text-xs">VERIFIED</div>
                </div>
                <div className="space-y-4">
                  {['Director Identification Number (DIN)', 'Digital Signature (DSC)', 'Name Approval (RUN)', 'MOA & AOA Drafting', 'PAN & TAN Creation'].map((item, i) => (
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

        {/* 2. Client Logos Marquee & Stats */}
        <div className="bg-slate-900 py-12 relative overflow-hidden">
          {/* Custom Styles Injection */}
          <style>{`
            @keyframes marquee {
              0% { transform: translateX(0%); }
              100% { transform: translateX(-50%); }
            }
            .animate-marquee {
              display: flex;
              animation: marquee 25s linear infinite;
            }
          `}</style>

          <div className="max-w-7xl mx-auto px-4 mb-6 text-center">
            <p className="text-xs uppercase font-black tracking-widest text-red-400">Trusted By Over 5,000+ Fast-Growing Indian Startups</p>
          </div>

          {/* Infinite Horizontal Marquee */}
          <div className="w-full overflow-hidden relative flex py-4 mb-8 bg-slate-900/50 border-y border-slate-800">
            <div className="animate-marquee space-x-12">
              {/* Set 1 */}
              {activeLogos.map((logo, idx) => {
                const Icon = Lucide[logo.iconKey] || Lucide.Globe;
                return (
                  <div key={`logo-1-${idx}`} className="inline-flex items-center gap-2.5 px-6 py-2.5 bg-slate-800/40 rounded-xl border border-slate-700/30 flex-shrink-0">
                    <Icon className={`w-4.5 h-4.5 ${logo.colorClass || logo.color || 'text-slate-500'}`} />
                    <span className="text-xs font-black tracking-tight text-slate-300">{logo.name}</span>
                  </div>
                );
              })}
              {/* Set 2 */}
              {activeLogos.map((logo, idx) => {
                const Icon = Lucide[logo.iconKey] || Lucide.Globe;
                return (
                  <div key={`logo-2-${idx}`} className="inline-flex items-center gap-2.5 px-6 py-2.5 bg-slate-800/40 rounded-xl border border-slate-700/30 flex-shrink-0">
                    <Icon className={`w-4.5 h-4.5 ${logo.colorClass || logo.color || 'text-slate-500'}`} />
                    <span className="text-xs font-black tracking-tight text-slate-300">{logo.name}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Stats Grid */}
          <div className="max-w-7xl mx-auto px-4 grid grid-cols-2 md:grid-cols-4 gap-8 text-center divide-x divide-slate-800 border-t border-slate-800/50 pt-8">
            {activeStats.map((stat, idx) => (
              <div key={idx} className="group p-2 rounded transition">
                <div className="text-3xl md:text-4xl font-black text-white mb-1 group-hover:text-red-500 transition-colors">{stat.value}</div>
                <div className="text-red-500 text-[10px] uppercase tracking-wider font-black group-hover:text-white transition-colors">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* 3. Pricing / Packages */}
        <section id="pricing" className="py-20 bg-slate-50">
          <div className="max-w-7xl mx-auto px-4">
            <div className="text-center mb-16">
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mb-4 tracking-tight">Registration Fees & Packages</h2>
              <p className="text-slate-600 font-medium">Transparent pricing. No hidden fees.</p>
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-[1400px] mx-auto">
              {activePackages.map((pkg) => (
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
                    {pkg.features && pkg.features.map((feat, i) => (
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

        {/* 4. New Customer Reviews */}
        <section className="py-20 bg-white border-y border-slate-100">
          <div className="max-w-7xl mx-auto px-4">
            <div className="text-center mb-16">
              <span className="text-xs uppercase font-black tracking-widest text-red-600 bg-red-50 px-3 py-1.5 rounded-full font-bold">Success Stories</span>
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mt-4 tracking-tight">What Our Founders Say</h2>
              <p className="text-lg text-slate-600 mt-2 font-medium">Hear directly from companies registered and powered by VR Here.</p>
            </div>
            <div className="grid md:grid-cols-3 gap-6">
              {activeReviews.map((review, idx) => (
                <div key={idx} className="bg-slate-50/50 p-8 rounded-2xl border border-slate-200 shadow-sm hover:shadow-md transition flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-1 text-amber-400 mb-4">
                      {[...Array(review.rating)].map((_, i) => (
                        <Star key={i} className="w-4 h-4 fill-current" />
                      ))}
                    </div>
                    <p className="text-slate-600 text-sm leading-relaxed mb-6 font-medium italic">"{review.text}"</p>
                  </div>
                  <div className="flex items-center gap-4 border-t border-slate-200/50 pt-4 mt-auto">
                    <div className="w-10 h-10 bg-gradient-to-br from-red-500 to-orange-500 rounded-full flex items-center justify-center text-white font-black text-xs shadow-sm">
                      {review.avatar}
                    </div>
                    <div>
                      <div className="flex items-center gap-1.5">
                        <h4 className="font-bold text-slate-900 text-sm">{review.name}</h4>
                        {review.verified && <CheckCircle className="w-3.5 h-3.5 text-emerald-500" title="Verified Customer" />}
                      </div>
                      <p className="text-slate-400 text-[10px] font-black uppercase tracking-wider">{review.company}</p>
                      <p className="text-[9px] text-slate-300 font-bold mt-0.5">{review.date}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 5. Redesigned How It Works */}
        <section className="py-24 bg-slate-50">
          <div className="max-w-6xl mx-auto px-4">
            <div className="text-center mb-20">
              <span className="text-xs uppercase font-black tracking-widest text-red-600 bg-red-50 px-3 py-1.5 rounded-full font-bold">Incorporation Flow</span>
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mt-4 tracking-tight">Redesigned, Effortless Steps</h2>
              <p className="text-lg text-slate-600 mt-2 font-medium">Get fully registered online from the comfort of your home.</p>
            </div>
            <div className="grid md:grid-cols-3 gap-8 relative z-10">
              <div className="hidden md:block absolute top-[68px] left-0 w-full h-1 bg-gradient-to-r from-red-100 via-orange-200 to-red-100 -z-10"></div>
              {activeSteps.map((step, i) => (
                <div key={i} className="bg-white p-8 rounded-3xl shadow-xl border border-slate-100 text-center hover:-translate-y-2 transition-all duration-300 relative group">
                  <div className="w-16 h-16 bg-gradient-to-br from-red-600 to-orange-600 text-white rounded-2xl flex items-center justify-center text-2xl font-black mx-auto mb-6 shadow-xl shadow-red-600/20 transform group-hover:rotate-6 transition-all border-4 border-white">{step.number}</div>
                  <div className="inline-block px-3 py-1 bg-slate-50 border border-slate-100 rounded-full text-[10px] font-black uppercase text-slate-500 mb-4">{step.badge}</div>
                  <h3 className="font-bold text-xl text-slate-900 mb-3 tracking-tight">{step.title}</h3>
                  <p className="text-slate-600 text-sm leading-relaxed font-medium">{step.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 6. Why Pvt Ltd? */}
        <section className="py-20 bg-white">
          <div className="max-w-7xl mx-auto px-4 flex flex-col md:flex-row gap-12 items-center">
            <div className="md:w-1/2">
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mb-6 tracking-tight">Why Register a Private Limited Company?</h2>
              <p className="text-slate-600 mb-8 leading-relaxed font-medium">
                It is the most popular legal structure for startups in India because it allows outside funding and limits the liabilities of its shareholders.
              </p>
              <div className="grid grid-cols-1 gap-4">
                {[
                  { t: "Limited Liability", d: "Your personal assets are safe in case of business loss." },
                  { t: "Easy Fundraising", d: "Investors & VCs prefer Pvt Ltd structure for equity investment." },
                  { t: "Separate Legal Entity", d: "The company can own assets and sue/be sued in its own name." },
                  { t: "Credibility", d: "Increases trust among vendors, customers, and employees." }
                ].map((item, i) => (
                  <div key={i} className="flex items-start p-4 bg-slate-50 rounded-xl border border-slate-200">
                    <CheckCircle2 className="w-5 h-5 text-green-500 mr-4 flex-shrink-0 mt-0.5" />
                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">{item.t}</h4>
                      <p className="text-xs text-slate-500 font-medium mt-0.5">{item.d}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="md:w-1/2">
              <div className="bg-slate-50 p-8 rounded-3xl border border-slate-200 shadow-sm">
                <h3 className="text-xl font-black text-slate-900 mb-6 text-center">Minimum Requirements</h3>
                <ul className="space-y-4">
                  {[
                    "Minimum 2 Directors (Adults)",
                    "Minimum 2 Shareholders (Can be same as directors)",
                    "Indian Resident Director (At least 1)",
                    "Registered Office Address (Residential allowed)"
                  ].map((req, i) => (
                    <li key={i} className="flex items-center text-slate-700 bg-white p-3.5 rounded-xl border border-slate-200 shadow-inner text-sm font-semibold">
                      <UsersIcon className="w-5 h-5 text-red-600 mr-3" /> {req}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* 7. New Expanding SEO Section (Detailed Text, FAQs, Popular Searches) */}
        <section className="py-12 bg-white">
          <div className="max-w-7xl mx-auto px-4 text-center">
            <button 
              onClick={() => setIsSeoExpanded(!isSeoExpanded)}
              className="inline-flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-white px-8 py-4 rounded-xl font-bold transition shadow-xl active:scale-95 text-sm"
            >
              <span>{isSeoExpanded ? 'Hide Detailed Guide & FAQs' : 'Show Detailed Guide & FAQs'}</span>
              <ChevronDown className={`w-5 h-5 transition-transform duration-300 ${isSeoExpanded ? 'rotate-180' : ''}`} />
            </button>

            {isSeoExpanded && (
              <div className="mt-12 text-left bg-slate-50 p-8 md:p-12 rounded-3xl border border-slate-200 animate-in fade-in slide-in-from-top-4 duration-300 grid grid-cols-1 lg:grid-cols-3 gap-12">
                {/* Column A: Detailed SEO Text */}
                <div className="lg:col-span-1 space-y-6 max-h-[500px] overflow-y-auto pr-4 scrollbar-thin scrollbar-thumb-slate-300">
                  <h3 className="text-xl font-black text-slate-900 border-b-2 border-red-500 pb-2">Guide to Company Registration</h3>
                  
                  <div className="space-y-4">
                    <p className="text-xs text-slate-600 leading-relaxed font-semibold">
                      Incorporating a <strong>Private Limited Company</strong> in India is the most widely recognized and preferred corporate structure for startups, offering credibility, structured governance, and investor-friendly access.
                    </p>

                    <div>
                      <h4 className="text-xs font-black uppercase text-slate-950 tracking-wide mb-1.5">What is Private Limited Company Registration?</h4>
                      <p className="text-[11px] text-slate-500 leading-relaxed font-medium">
                        It is the legal process of incorporating a business entity under the <strong>Companies Act, 2013</strong>, governed by the Ministry of Corporate Affairs (MCA). A private limited company restricts share transfers and limits members to 200. It becomes a separate legal entity distinct from directors and shareholders, allowing the company to own assets, enter contracts, and sue or be sued in its own name.
                      </p>
                    </div>

                    <div>
                      <h4 className="text-xs font-black uppercase text-slate-950 tracking-wide mb-1.5">Forms of Private Limited Company</h4>
                      <ul className="text-[11px] text-slate-500 space-y-2 font-medium">
                        <li><strong>1. Company Limited by Shares:</strong> The most common form where shareholder liability is strictly limited to the face value of unpaid shares. Personal assets are 100% protected.</li>
                        <li><strong>2. Company Limited by Guarantee:</strong> Liability of members is limited to the amount they agree to contribute in case of winding up (common for NGOs / Section 8).</li>
                        <li><strong>3. Unlimited Private Company:</strong> Rare form where members have unlimited personal liability, offering capital distribution flexibility.</li>
                      </ul>
                    </div>

                    <div>
                      <h4 className="text-xs font-black uppercase text-slate-950 tracking-wide mb-1.5">Private Limited Minimum Requirements</h4>
                      <ul className="text-[11px] text-slate-500 space-y-1 font-medium list-disc pl-4">
                        <li>Minimum 2 Directors & maximum 15 directors.</li>
                        <li>Minimum 2 Shareholders & maximum 200 shareholders.</li>
                        <li>At least 1 Indian Resident Director.</li>
                        <li>Proposed directors must obtain DIN & DSC.</li>
                        <li>No minimum paid-up capital requirement.</li>
                      </ul>
                    </div>

                    <div>
                      <h4 className="text-xs font-black uppercase text-slate-950 tracking-wide mb-1.5">Incorporation Step-by-Step Process</h4>
                      <ol className="text-[11px] text-slate-500 space-y-2 font-medium">
                        <li><strong>Step 1: Obtain DSC:</strong> Proposed directors apply for Digital Signature Certificate from a government certified agency.</li>
                        <li><strong>Step 2: Reserve Unique Name (RUN):</strong> Reserving the company name through the MCA RUN portal.</li>
                        <li><strong>Step 3: SPICe+ Form:</strong> Filing the integrated electronic form covering PAN, TAN, GSTIN, EPFO, ESIC, and Profession Tax.</li>
                        <li><strong>Step 4: MoA & AoA:</strong> Drafting Memorandum of Association and Articles of Association to establish rules and objectives.</li>
                        <li><strong>Step 5: COI Issuance:</strong> ROC issues the official Certificate of Incorporation.</li>
                      </ol>
                    </div>

                    <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-inner">
                      <h4 className="text-xs font-black uppercase text-slate-950 tracking-wide mb-2">Checklist of Documents Needed</h4>
                      <ul className="text-[10px] text-slate-600 space-y-1.5 font-bold">
                        <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-green-500" /> PAN & Aadhaar of all Directors</li>
                        <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-green-500" /> Passport Size Photograph of Directors</li>
                        <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-green-500" /> Electricity/Water Bill (Registered Address)</li>
                        <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-green-500" /> NOC from property owner</li>
                        <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-green-500" /> Bank Statement / Utility Bill of Proposed Directors</li>
                      </ul>
                    </div>
                  </div>
                </div>

                {/* Column B: FAQ Accordion */}
                <div className="lg:col-span-1 space-y-4">
                  <h3 className="text-xl font-black text-slate-900 border-b-2 border-orange-500 pb-2 mb-6">Frequently Asked Questions</h3>
                  <div className="space-y-3">
                    {activeFaqs.map((faq, idx) => (
                      <div key={idx} className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                        <button 
                          onClick={() => setActiveFaq(activeFaq === idx ? null : idx)}
                          className="w-full p-4 flex items-center justify-between text-left font-bold text-sm text-slate-800 hover:bg-slate-50 transition"
                        >
                          <span>{faq.q}</span>
                          <ChevronDown className={`w-4 h-4 text-slate-400 transition-transform flex-shrink-0 ml-2 ${activeFaq === idx ? 'rotate-180' : ''}`} />
                        </button>
                        {activeFaq === idx && (
                          <div className="p-4 border-t border-slate-100 text-xs text-slate-600 leading-relaxed bg-slate-50/50 font-medium">
                            {faq.a}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Column C: Popular Searches */}
                <div className="lg:col-span-1 space-y-6">
                  <h3 className="text-xl font-black text-slate-900 border-b-2 border-indigo-500 pb-2">Popular Searches</h3>
                  <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">SEO Keywords & Search Phrases</p>
                  <div className="flex flex-wrap gap-2">
                    {[
                      'Register Company Online', 'Private Limited Company Registration', 'Pvt Ltd Registration Fees', 
                      'Company Incorporation India', 'How to register startup', 'CA Consultation Online', 
                      'Pvt Ltd vs LLP', 'Name Approval RUN Process', 'Director Identification Number (DIN)', 
                      'Digital Signature Certificate', 'MSME Certificate Online', 'Startup India Registration',
                      'GST Registration CA Services', 'Cheapest Company Registration'
                    ].map((tag, idx) => (
                      <span key={idx} className="px-3 py-1.5 bg-white hover:bg-red-50 hover:text-red-700 rounded-lg border border-slate-200 text-xs font-semibold text-slate-600 cursor-default transition">
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* 8. New Related Services */}
        <section className="py-20 bg-slate-50 border-t border-slate-200/50">
          <div className="max-w-7xl mx-auto px-4">
            <div className="text-center mb-16">
              <span className="text-xs uppercase font-black tracking-widest text-red-600 bg-red-50 px-3 py-1.5 rounded-full font-bold">Explore Catalog</span>
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mt-4 tracking-tight">Related Compliance Services</h2>
              <p className="text-lg text-slate-600 mt-2 font-medium">Grow your business legally with our allied setup packages.</p>
            </div>
            <div className="grid md:grid-cols-4 gap-6">
              {RELATED_SERVICES.map((service, idx) => (
                <div key={idx} className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm hover:shadow-md transition flex flex-col justify-between">
                  <div>
                    <h3 className="font-black text-base text-slate-900 mb-2">{service.title}</h3>
                    <div className="text-red-600 font-black text-lg mb-4">{service.price} <span className="text-[10px] text-slate-400 font-bold uppercase">+ Govt Fees</span></div>
                    <p className="text-slate-500 text-xs leading-relaxed font-medium mb-6">{service.desc}</p>
                  </div>
                  <button onClick={() => navigate(service.link)} className="w-full py-2 bg-slate-100 hover:bg-red-600 hover:text-white rounded-xl text-xs font-bold text-slate-800 transition flex items-center justify-center gap-1.5">
                    <span>Explore Plan</span>
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 9. Consultation CTA Area (Confused about process) */}
        <section className="py-24 bg-slate-900 text-white relative overflow-hidden">
          <div className="absolute inset-0 opacity-20 bg-[radial-gradient(#ffffff_1px,transparent_1px)] [background-size:16px_16px]"></div>
          <div className="max-w-4xl mx-auto px-4 text-center relative z-10">
            <h2 className="text-3xl lg:text-5xl font-black mb-6">Confused about the process?</h2>
            <p className="text-xl text-slate-400 mb-10 leading-relaxed font-medium">
              Talk to our experts before you commit. Pay a small booking fee now, and we will deduct it from your final bill.
            </p>
            <div className="bg-white/10 backdrop-blur-md p-8 rounded-3xl border border-white/10 inline-block w-full max-w-md">
              <div className="text-sm font-bold text-red-400 uppercase tracking-widest mb-2 font-black">Consultation Offer</div>
              <div className="text-5xl font-black mb-2">₹499</div>
              <p className="text-slate-300 text-sm mb-6 font-medium">Fully adjustable against registration fees</p>
              <button onClick={handleConsultationBook} className="w-full bg-red-600 text-white font-bold py-4 rounded-xl hover:bg-red-700 transition shadow-lg shadow-red-600/30 flex items-center justify-center">
                Book Now <ArrowRight className="ml-2 w-5 h-5" />
              </button>
            </div>
          </div>
        </section>

      </div>

      {/* Dynamic inline customize overlays & Real-time scoring checking widgets */}
      {pageConfig && isAuthorized && (
        <>
          <InlineEditOverlay
            pageId="private-limited"
            config={pageConfig}
            onConfigUpdate={setPageConfig}
          />
          <SeoAeoDashboard
            pageId="private-limited"
            config={pageConfig}
            currentHtml={pageHtmlContent}
            faqList={activeFaqs}
            seoSettings={pageConfig.seoSettings || {}}
            onUpdateSeoSettings={handleUpdateSeoSettings}
            trackingSettings={pageConfig.trackingSettings || {}}
            onUpdateTrackingSettings={handleUpdateTrackingSettings}
            isSaving={savingOverlay}
          />
        </>
      )}

      <SharedFooter />
    </div>
  );
};

export default PrivateLimitedPage;
