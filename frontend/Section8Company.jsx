import React, { useState, useEffect } from 'react';
import {
  Briefcase, Globe, Zap, Clock, Award, ArrowRight, CheckCircle2,
  Building2, CheckCircle, FileText, Star, User as UsersIcon, Check, HelpCircle,
  MessageSquare, ShieldCheck, TrendingUp, Anchor, Truck, Hammer, FileCheck,
  ChevronRight, ChevronDown, Download, PlayCircle, Loader2, CreditCard, RefreshCw
} from 'lucide-react';
import * as Lucide from 'lucide-react';
import { SharedHeader, SharedFooter } from './components/SharedComponents';
import ConsultationPaymentModal from './components/ConsultationPaymentModal';
import { launchRazorpayCheckout } from './utils/razorpayCheckout';
import { useNavigate } from 'react-router-dom';
import { showPaymentSuccessPopup } from './utils/paymentSuccessPopup';
import { fetchServicePageConfig } from './modules/service-editor/v1.1/services/serviceConfigApi';
import { injectTrackingScripts } from './modules/seo-aeo-analyzer/v1.1/components/TrackingSettings';
import { section8Config } from '../backend/data/serviceConfigs/section8.js';

const PAGE_ID = 'section-8-company';

const RELATED_SERVICES = [
  {
    title: "Society & Trust Registration",
    price: "₹8,499",
    desc: "Public Charitable Trust deed drafting and Sub-Registrar execution across India.",
    link: "/society-trust-registration"
  },
  {
    title: "Private Limited Company",
    price: "₹6,499",
    desc: "For-profit startup corporate structure with equity and investment capabilities.",
    link: "/pvt-ltd-registration"
  },
  {
    title: "Limited Liability Partnership (LLP)",
    price: "₹7,899",
    desc: "Perfect structure for partner-led initiatives with lower annual compliance burden.",
    link: "/llp-registration"
  },
  {
    title: "GST Registration & Filing",
    price: "₹2,569",
    desc: "Essential tax registration for institutions selling educational materials or merchandise.",
    link: "/gst-registration"
  }
];

const sanitizeText = (text, city) => {
  if (!text) return '';
  if (city) {
    return text.replace(/\{city\}/gi, city).replace(/\{state\}/gi, '').replace(/\{landmark\}/gi, city);
  }
  return text
    .replace(/in\s*\{city\},\s*\{state\}/gi, 'across India')
    .replace(/in\s*\{city\}/gi, 'Online in India')
    .replace(/\{city\},\s*\{state\}/gi, 'India')
    .replace(/\{city\}/gi, 'Online')
    .replace(/\{state\}/gi, 'India')
    .replace(/\{landmark\}/gi, '')
    .replace(/\{district\}/gi, '')
    .replace(/\{pincode\}/gi, '')
    .trim();
};

const Section8CompanyPage = () => {
  const navigate = useNavigate();

  const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
  const isAuthorized = userInfo && (userInfo.role === 'admin' || userInfo.role === 'employee');

  const [pageConfig, setPageConfig] = useState(section8Config);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [isScrolled, setIsScrolled] = useState(false);
  const [isServicesHovered, setIsServicesHovered] = useState(false);
  const [isSeoExpanded, setIsSeoExpanded] = useState(false);
  const [activeFaq, setActiveFaq] = useState(null);
  const [formData, setFormData] = useState({ name: '', email: '', phone: '' });

  useEffect(() => {
    const loadConfig = async () => {
      try {
        const rawPath = window.location.pathname.replace(/^\//, '') || PAGE_ID;
        const configData = await fetchServicePageConfig(rawPath);
        setPageConfig(configData);

        if (configData.seoSettings?.titleTag || configData.title) {
          document.title = sanitizeText(configData.seoSettings?.titleTag || configData.title, configData.city);
        }

        if (configData.seoSettings?.metaDescription) {
          let metaEl = document.querySelector('meta[name="description"]');
          if (!metaEl) {
            metaEl = document.createElement('meta');
            metaEl.name = 'description';
            document.head.appendChild(metaEl);
          }
          metaEl.content = sanitizeText(configData.seoSettings.metaDescription, configData.city);
        }

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
      const mainEl = document.getElementById('section8-container');
      if (mainEl) {
        setPageHtmlContent(mainEl.innerHTML);
      }
    }, 2000);
    return () => clearTimeout(timer);
  }, [pageConfig, loading]);

  useEffect(() => {
    const timer = setTimeout(() => setLoading(false), 1200);
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

  const activeHero = pageConfig?.hero || section8Config.hero;
  const activeStats = pageConfig?.stats || section8Config.stats;
  const activeLogos = pageConfig?.logos || section8Config.logos;
  const activePackages = pageConfig?.packages || section8Config.packages;
  const activeReviews = pageConfig?.reviews || section8Config.reviews;
  const activeSteps = pageConfig?.steps || section8Config.steps;
  const activeFaqs = pageConfig?.faqs || section8Config.faqs;
  const activeGuide = pageConfig?.guide || section8Config.guide;
  const activePopularSearches = pageConfig?.popularSearches || section8Config.popularSearches;

  const handleConsultationBook = () => {
    setSelectedPlan(activePackages[0]);
    setIsModalOpen(true);
  };

  const handleSelectPlan = (plan) => {
    setSelectedPlan(plan);
    setIsModalOpen(true);
  };

  const handleFormSubmit = ({ formData: submittedFormData, termsAccepted }) => {
    if (!termsAccepted) {
      alert('Please accept the Terms & Conditions before proceeding.');
      return;
    }
    const currentMember = JSON.parse(localStorage.getItem('userInfo') || 'null');
    setFormData(submittedFormData);

    launchRazorpayCheckout({
      serviceName: 'Section 8 Company Registration',
      selectedPlan,
      formData: submittedFormData,
      token: currentMember?.token,
      onSubmittingChange: setIsSubmitting,
      onSuccess: async (data) => {
        const requiresEmailLogin = Boolean(data?.resetLinkSent);
        await showPaymentSuccessPopup({
          serviceName: selectedPlan?.name || data?.order?.serviceName || 'Section 8 Company Registration',
          paymentId: data?.payment?.paymentId || data?.razorpay_payment_id,
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
      {/* Header */}
      <SharedHeader isScrolled={isScrolled} />

      <ConsultationPaymentModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        selectedPlan={selectedPlan}
        initialFormData={formData}
        onSubmit={handleFormSubmit}
        isSubmitting={isSubmitting}
        formatCurrency={formatCurrency}
        title={selectedPlan?.id === 'consultation' ? 'Book NGO Legal Advisory' : 'Select Section 8 Package'}
        initialTermsAccepted={false}
      />

      <div id="section8-container" className="animate-fade-in">
        {/* 1. Hero Section */}
        <div className="relative pt-16 pb-20 lg:pt-24 lg:pb-32 bg-slate-50 overflow-hidden">
          <div className="absolute top-0 right-0 w-1/2 h-full bg-red-50 skew-x-12 opacity-50 z-0 translate-x-1/3"></div>
          <div className="max-w-7xl mx-auto px-4 relative z-10 flex flex-col lg:flex-row items-center gap-12">
            <div className="lg:w-1/2">
              <div className="inline-flex items-center px-4 py-1.5 rounded-full bg-white border border-slate-200 shadow-sm text-sm font-bold text-slate-600 mb-6">
                <span className="w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></span>
                {sanitizeText(activeHero.badgeText, pageConfig?.city) || 'Eligible for CSR & Govt Grants'}
              </div>
              <h1 className="text-4xl lg:text-6xl font-black text-slate-900 tracking-tight leading-[1.1] mb-6">
                {sanitizeText(activeHero.title, pageConfig?.city) || 'Register Section 8 NGO Company Online'}
              </h1>
              <p className="text-xl text-slate-600 leading-relaxed mb-8">
                {sanitizeText(activeHero.subtitle, pageConfig?.city) || 'Launch your non-profit institution with highest credibility, CSR funding eligibility, and 12A/80G tax exemptions.'}
              </p>

              <div className="flex flex-col sm:flex-row gap-4 mb-8">
                <button
                  onClick={handleConsultationBook}
                  className="bg-red-600 text-white px-8 py-4 rounded-xl font-bold text-lg hover:bg-red-700 transition shadow-xl shadow-red-600/20 transform hover:-translate-y-1 active:scale-95 flex items-center justify-center"
                >
                  Book Legal Call @ ₹{activeHero.consultationPrice || 999} <ArrowRight className="ml-2 w-5 h-5" />
                </button>
                <p className="text-xs text-slate-500 sm:hidden text-center mt-2">Adjusted against final package</p>
              </div>
              <div className="flex items-center space-x-2 text-sm font-medium text-slate-500">
                <CheckCircle2 className="w-4 h-4 text-green-500" />
                <span>Consultation fee of ₹{activeHero.consultationPrice || 999} is 100% adjustable in final package</span>
              </div>
            </div>

            {/* Hero Graphic Card */}
            <div className="lg:w-1/2 relative hidden lg:block">
              <div className="relative z-10 bg-white p-8 rounded-2xl shadow-2xl border border-slate-100 transform rotate-2 hover:rotate-0 transition duration-500">
                <div className="flex justify-between items-start mb-6">
                  <div>
                    <h3 className="text-xl font-bold text-slate-900">Section 8 NGO Kit</h3>
                    <p className="text-slate-500 text-sm">All-inclusive non-profit setup from ₹12,499</p>
                  </div>
                  <div className="bg-green-100 text-green-700 font-bold px-3 py-1 rounded text-xs">INC-12 LICENSE</div>
                </div>
                <div className="space-y-4">
                  {['Section 8 Central Govt License (INC-12)', 'Non-Profit MoA & AoA Clauses Drafting', 'Provisional 12A Income Tax Exemption', 'Provisional 80G Tax Exemption for Donors', 'NITI Aayog NGO DARPAN & CSR-1 Support'].map((item, i) => (
                    <div key={i} className="flex items-center p-3 bg-slate-50 rounded-lg">
                      <CheckCircle className="w-5 h-5 text-red-600 mr-3" />
                      <span className="font-medium text-slate-700">{item}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[120%] h-[120%] bg-gradient-to-tr from-red-100 to-orange-100 rounded-full blur-3xl -z-10 opacity-60"></div>
            </div>
          </div>
        </div>

        {/* 2. Client Logos Marquee & Stats */}
        <div className="bg-slate-900 py-12 relative overflow-hidden">
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
            <p className="text-xs uppercase font-black tracking-widest text-red-400">
              Trusted By Over 500+ NGOs, Foundations & Social Impact Leaders
            </p>
          </div>

          <div className="w-full overflow-hidden relative flex py-4 mb-8 bg-slate-900/50 border-y border-slate-800">
            <div className="animate-marquee space-x-12">
              {activeLogos.map((logo, idx) => {
                const Icon = Lucide[logo.iconKey] || Lucide.Globe;
                return (
                  <div key={`logo-1-${idx}`} className="inline-flex items-center gap-2.5 px-6 py-2.5 bg-slate-800/40 rounded-xl border border-slate-700/30 flex-shrink-0">
                    <Icon className={`w-4.5 h-4.5 ${logo.colorClass || logo.color || 'text-slate-500'}`} />
                    <span className="text-xs font-black tracking-tight text-slate-300">{logo.name}</span>
                  </div>
                );
              })}
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
                      {pkg.isAdjustable ? '(Fully Adjustable)' : '+ MCA & Govt Fees'}
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
                      <div key={i} className="flex items-start text-sm text-slate-700 font-medium group">
                        <CheckCircle2 className="w-4 h-4 text-green-500 mr-2 mt-0.5 flex-shrink-0 group-hover:scale-125 transition-transform" />
                        {feat}
                      </div>
                    ))}
                  </div>
                  <button
                    onClick={() => handleSelectPlan(pkg)}
                    className={`w-full py-4 rounded-xl font-bold transition transform active:scale-95 ${
                      pkg.isPopular || pkg.isAdjustable ? 'bg-red-600 text-white hover:bg-red-700 shadow-lg shadow-red-600/30' : 'bg-slate-100 text-slate-900 hover:bg-slate-200'
                    }`}
                  >
                    {pkg.buttonText || 'Select Package'}
                  </button>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 4. Customer Reviews */}
        <section className="py-20 bg-white border-y border-slate-100">
          <div className="max-w-7xl mx-auto px-4">
            <div className="text-center mb-16">
              <span className="text-xs uppercase font-black tracking-widest text-red-600 bg-red-50 px-3 py-1.5 rounded-full font-bold">Success Stories</span>
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mt-4 tracking-tight">What NGO Leaders Say</h2>
              <p className="text-lg text-slate-600 mt-2 font-medium">Hear directly from non-profit foundations incorporated and certified through VR Here.</p>
            </div>
            <div className="grid md:grid-cols-2 gap-6 max-w-4xl mx-auto">
              {activeReviews.map((review, idx) => (
                <div key={idx} className="bg-slate-50/50 p-8 rounded-2xl border border-slate-200 shadow-sm hover:shadow-md transition flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-1 text-amber-400 mb-4">
                      {[...Array(review.rating || 5)].map((_, i) => (
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

        {/* 5. How It Works Steps */}
        <section className="py-24 bg-slate-50">
          <div className="max-w-6xl mx-auto px-4">
            <div className="text-center mb-20">
              <span className="text-xs uppercase font-black tracking-widest text-red-600 bg-red-50 px-3 py-1.5 rounded-full font-bold">Incorporation Flow</span>
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mt-4 tracking-tight">Redesigned, Effortless Steps</h2>
              <p className="text-lg text-slate-600 mt-2 font-medium">Non-profit licensing and 12A/80G tax exemptions executed 100% digitally.</p>
            </div>
            <div className="grid md:grid-cols-4 gap-6 relative z-10">
              {activeSteps.map((step, i) => (
                <div key={i} className="bg-white p-8 rounded-3xl shadow-xl border border-slate-100 text-center hover:-translate-y-2 transition-all duration-300 relative group">
                  <div className="w-16 h-16 bg-gradient-to-br from-red-600 to-orange-600 text-white rounded-2xl flex items-center justify-center text-2xl font-black mx-auto mb-6 shadow-xl shadow-red-600/20 transform group-hover:rotate-6 transition-all border-4 border-white">
                    {step.number}
                  </div>
                  <div className="inline-block px-3 py-1 bg-slate-50 border border-slate-100 rounded-full text-[10px] font-black uppercase text-slate-500 mb-4">
                    {step.badge}
                  </div>
                  <h3 className="font-bold text-lg text-slate-900 mb-3 tracking-tight">{step.title}</h3>
                  <p className="text-slate-600 text-xs leading-relaxed font-medium">{step.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 6. Why Section 8 & Requirements */}
        <section className="py-20 bg-white">
          <div className="max-w-7xl mx-auto px-4 flex flex-col md:flex-row gap-12 items-center">
            <div className="md:w-1/2">
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mb-6 tracking-tight">
                Why Choose a Section 8 NGO?
              </h2>
              <p className="text-slate-600 mb-8 leading-relaxed font-medium">
                Section 8 is the gold standard for foundations, research bodies, schools, and charitable institutions seeking nationwide credibility and CSR grants.
              </p>
              <div className="grid grid-cols-1 gap-4">
                {[
                  { t: "CSR Funding Eligibility", d: "Directly eligible to receive corporate CSR grants from top Indian and MNC enterprises." },
                  { t: "12A & 80G Tax Exemptions", d: "100% tax exemption on non-profit income and 50% tax deduction benefit for your donors." },
                  { t: "Nationwide Legal Recognition", d: "Operate across all states in India without needing separate state sub-registrar registrations." },
                  { t: "Corporate Governance", d: "Clear MoA/AoA rules preventing ownership disputes and ensuring institutional legacy." }
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
                <h3 className="text-xl font-black text-slate-900 mb-6 text-center">Section 8 Minimum Requirements</h3>
                <ul className="space-y-4">
                  {[
                    "Minimum 2 Directors & 2 Shareholders (Can be same)",
                    "Clear Social / Charitable / Educational Objects",
                    "No Profit / Dividend Distribution to Promoters Clause",
                    "INC-12 Central Government License Approval",
                    "Registered Office Address Proof with Landlord NOC"
                  ].map((req, i) => (
                    <li key={i} className="flex items-center text-slate-700 bg-white p-3.5 rounded-xl border border-slate-200 shadow-inner text-sm font-semibold">
                      <UsersIcon className="w-5 h-5 text-red-600 mr-3 shrink-0" /> {req}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* 7. Collapsible 3-Block Section (Guide, FAQs, Popular Searches) */}
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
                {/* Column A: Guide */}
                <div className="lg:col-span-1 space-y-6 max-h-[500px] overflow-y-auto pr-4 scrollbar-thin scrollbar-thumb-slate-300">
                  <h3 className="text-xl font-black text-slate-900 border-b-2 border-red-500 pb-2">
                    {activeGuide.title || 'Guide to Section 8 Company Registration'}
                  </h3>
                  
                  <div className="space-y-4">
                    {activeGuide.overview && (
                      <p className="text-xs text-slate-600 leading-relaxed font-semibold">
                        {sanitizeText(activeGuide.overview, pageConfig?.city)}
                      </p>
                    )}

                    {activeGuide.sections && activeGuide.sections.map((sec, sIdx) => (
                      <div key={sIdx}>
                        {sec.heading && <h4 className="text-xs font-black uppercase text-slate-950 tracking-wide mb-1.5">{sec.heading}</h4>}
                        {sec.content && (
                          <p className="text-[11px] text-slate-500 leading-relaxed font-medium mb-2">
                            {sanitizeText(sec.content, pageConfig?.city)}
                          </p>
                        )}
                        {sec.bullets && sec.bullets.length > 0 && (
                          <ul className="text-[11px] text-slate-500 space-y-1.5 font-medium list-disc pl-4">
                            {sec.bullets.map((b, bIdx) => (
                              <li key={bIdx}>{sanitizeText(b, pageConfig?.city)}</li>
                            ))}
                          </ul>
                        )}
                      </div>
                    ))}

                    {activeGuide.checklist && activeGuide.checklist.length > 0 && (
                      <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-inner">
                        <h4 className="text-xs font-black uppercase text-slate-950 tracking-wide mb-2">
                          {activeGuide.checklistTitle || 'Checklist of Documents Needed'}
                        </h4>
                        <ul className="text-[10px] text-slate-600 space-y-1.5 font-bold">
                          {activeGuide.checklist.map((item, cIdx) => (
                            <li key={cIdx} className="flex items-center gap-1.5">
                              <Check className="w-3.5 h-3.5 text-green-500 flex-shrink-0" />
                              <span>{sanitizeText(item, pageConfig?.city)}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>

                {/* Column B: FAQs */}
                <div className="lg:col-span-1 space-y-4">
                  <h3 className="text-xl font-black text-slate-900 border-b-2 border-orange-500 pb-2 mb-6">Frequently Asked Questions</h3>
                  <div className="space-y-3">
                    {activeFaqs.map((faq, idx) => (
                      <div key={idx} className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                        <button
                          onClick={() => setActiveFaq(activeFaq === idx ? null : idx)}
                          className="w-full p-4 flex items-center justify-between text-left font-bold text-sm text-slate-800 hover:bg-slate-50 transition"
                        >
                          <span>{sanitizeText(faq.q, pageConfig?.city)}</span>
                          <ChevronDown className={`w-4 h-4 text-slate-400 transition-transform flex-shrink-0 ml-2 ${activeFaq === idx ? 'rotate-180' : ''}`} />
                        </button>
                        {activeFaq === idx && (
                          <div className="p-4 border-t border-slate-100 text-xs text-slate-600 leading-relaxed bg-slate-50/50 font-medium">
                            {sanitizeText(faq.a, pageConfig?.city)}
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
                    {activePopularSearches.map((tag, idx) => (
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

        {/* 8. Related Services */}
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

        {/* 9. Bottom Consultation Banner */}
        <section className="py-24 bg-slate-900 text-white relative overflow-hidden">
          <div className="absolute inset-0 opacity-20 bg-[radial-gradient(#ffffff_1px,transparent_1px)] [background-size:16px_16px]"></div>
          <div className="max-w-4xl mx-auto px-4 text-center relative z-10">
            <h2 className="text-3xl lg:text-5xl font-black mb-6">Confused about the process?</h2>
            <p className="text-xl text-slate-400 mb-10 leading-relaxed font-medium">
              Talk to our NGO legal specialists before you commit. Pay a small booking fee now, and we will deduct it from your final bill.
            </p>
            <div className="bg-white/10 backdrop-blur-md p-8 rounded-3xl border border-white/10 inline-block w-full max-w-md">
              <div className="text-sm font-bold text-red-400 uppercase tracking-widest mb-2 font-black">Consultation Offer</div>
              <div className="text-5xl font-black mb-2">₹{activeHero.consultationPrice || 999}</div>
              <p className="text-slate-300 text-sm mb-6 font-medium">Fully adjustable against registration fees</p>
              <button onClick={handleConsultationBook} className="w-full bg-red-600 text-white font-bold py-4 rounded-xl hover:bg-red-700 transition shadow-lg shadow-red-600/30 flex items-center justify-center">
                Book Now <ArrowRight className="ml-2 w-5 h-5" />
              </button>
            </div>
          </div>
        </section>
      </div>

      <SharedFooter />
    </div>
  );
};

export default Section8CompanyPage;
