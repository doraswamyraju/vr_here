import React, { useState, useEffect } from 'react';
import {
  Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
  Phone, Menu, X, ChevronDown, Clock, Award, Search, ArrowRight, CheckCircle2,
  Building2, Mail, MapPin, CheckCircle, FileText, Star, User as UsersIcon, Check, HelpCircle,
  MessageSquare, Zap, ShieldCheck, TrendingUp, Anchor, Truck, Hammer, FileCheck,
  ChevronRight, Download, PlayCircle, Loader2, CreditCard, RefreshCw, Sparkles
} from 'lucide-react';
import * as Lucide from 'lucide-react';
import { SharedHeader, SharedFooter } from './SharedComponents';
import ConsultationPaymentModal from './ConsultationPaymentModal';
import { launchRazorpayCheckout } from '../utils/razorpayCheckout';
import { useNavigate } from 'react-router-dom';
import { showPaymentSuccessPopup } from '../utils/paymentSuccessPopup';
import { fetchServicePageConfig } from '../modules/service-editor/v1.1/services/serviceConfigApi';
import { trackLead } from '../utils/leadTelemetry';

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

const DEFAULT_LOGOS = [
  { name: 'Stripe for Startups', iconKey: 'Briefcase', colorClass: 'text-indigo-600' },
  { name: 'Razorpay Partner', iconKey: 'Zap', colorClass: 'text-blue-500' },
  { name: 'Google Cloud Program', iconKey: 'Globe', colorClass: 'text-red-500' },
  { name: 'AWS Activate', iconKey: 'Factory', colorClass: 'text-orange-500' },
  { name: 'Microsoft Founders Hub', iconKey: 'Building2', colorClass: 'text-blue-600' },
  { name: 'Shopify Partners', iconKey: 'ShieldCheck', colorClass: 'text-emerald-500' },
  { name: 'HubSpot Ecosystem', iconKey: 'Award', colorClass: 'text-orange-600' }
];

const UniversalServicePage = ({ config, pageId: propPageId }) => {
  const navigate = useNavigate();
  const pageId = propPageId || config?.pageId || 'service';

  const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
  const isAuthorized = userInfo && (userInfo.role === 'admin' || userInfo.role === 'employee');

  const [pageConfig, setPageConfig] = useState(config || null);
  const [loading, setLoading] = useState(true);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [showConsultationModal, setShowConsultationModal] = useState(false);
  const [activeFaq, setActiveFaq] = useState(null);
  const [isSeoExpanded, setIsSeoExpanded] = useState(false);

  const serviceTitle = pageConfig?.title || config?.title || 'Professional Service';

  useEffect(() => {
    // Category A Lead Telemetry
    trackLead({
      serviceId: pageId,
      serviceName: serviceTitle,
      category: 'PAGE_VIEW',
      source: 'web'
    });

    const loadConfig = async () => {
      try {
        setLoading(true);
        const data = await fetchServicePageConfig(pageId);
        if (data && data.hero) {
          setPageConfig(data);
        } else {
          setPageConfig(config);
        }
      } catch (err) {
        console.warn(`[UniversalServicePage] Using default config for ${pageId}`, err);
        setPageConfig(config);
      } finally {
        setLoading(false);
      }
    };
    loadConfig();
  }, [pageId]);


  const activeHero = pageConfig?.hero || config?.hero || {
    title: `${serviceTitle} Online in {city}`,
    subtitle: `Fast, transparent, 100% online ${serviceTitle} with dedicated CA/CS assistance across {city}, {state}.`,
    badgeText: "GOVT & STATUTORY VERIFIED",
    consultationPrice: 499
  };

  const activeStats = pageConfig?.stats || config?.stats || [
    { value: "3-5 Days", label: "AVG. TURNAROUND" },
    { value: "5,000+", label: "HAPPY CLIENTS" },
    { value: "4.9/5", label: "GOOGLE RATING" },
    { value: "100%", label: "ONLINE PROCESS" }
  ];

  const activeLogos = pageConfig?.logos || config?.logos || DEFAULT_LOGOS;

  const activeHeroGraphicItems = pageConfig?.heroGraphicItems || pageConfig?.hero?.inclusions || config?.heroGraphicItems || [
    'Dedicated CA/CS Specialist Assigned',
    'Government & Statutory Portal Submission',
    'Digital Document Verification & Quality Audit',
    'Official Filing Receipts / Certificate Delivered',
    'Lifetime Compliance & Advisory Support'
  ];

  const activeReviews = pageConfig?.reviews || config?.reviews || [
    {
      name: "Rajesh Kulkarni",
      company: "Kulkarni Enterprises",
      avatar: "RK",
      rating: 5,
      date: "12 June 2026",
      text: `VR Here handled our ${serviceTitle} with supreme professionalism. The team delivered all documents on schedule with zero hassles.`,
      verified: true
    },
    {
      name: "Pooja Sharma",
      company: "Apex Tech Innovations",
      avatar: "PS",
      rating: 5,
      date: "25 May 2026",
      text: `Very fast and transparent service for ${serviceTitle}. Their CA guided us step-by-step through the requirements. Highly recommended!`,
      verified: true
    },
    {
      name: "Suresh Menon",
      company: "Menon Logistics & Supply",
      avatar: "SM",
      rating: 5,
      date: "04 July 2026",
      text: `Top-tier customer support. We got our ${serviceTitle} completed without any office visits. Superb experience!`,
      verified: true
    }
  ];

  const activePackages = pageConfig?.packages || config?.packages || [];
  
  const activeSteps = pageConfig?.steps || config?.steps || [
    { number: '01', title: 'KYC & Data Upload', desc: 'Securely submit required business details and identity documents.', badge: 'Step 1' },
    { number: '02', title: 'Legal & Dept Drafting', desc: 'Practicing Chartered Accountants draft and verify applications.', badge: 'Step 2' },
    { number: '03', title: 'Statutory Portal Filing', desc: 'Application filed on official central or state government portals.', badge: 'Step 3' },
    { number: '04', title: 'Delivery & Advisory', desc: 'Official government certificate and filing receipt delivered digitally.', badge: 'Step 4' }
  ];

  const activeWhyChoose = pageConfig?.whyChoose || config?.whyChoose || {
    title: `Why Choose VR Here for ${serviceTitle}?`,
    subtitle: `Get certified legal execution, dedicated financial modeling, and end-to-end statutory assistance from senior chartered accountants.`,
    benefits: [
      { t: "100% Online & Paperless", d: `Complete ${serviceTitle} from the comfort of your home or office.` },
      { t: "Verified CA/CS Oversight", d: "Every document and application is verified by senior practitioners." },
      { t: "Zero Penalty Guarantee", d: "Timely filing ensuring complete statutory compliance and protection." },
      { t: "Transparent Pricing", d: "Clear itemized billing with no hidden fees or surprise charges." }
    ],
    requirements: [
      "PAN Card of Business / Applicant",
      "Aadhaar Card linked with active Mobile No.",
      "Registered Address Proof (Electricity Bill / Rent Agreement)",
      "Bank Account Statement / Cancelled Cheque"
    ]
  };

  const activeGuide = pageConfig?.guide || config?.guide || {
    title: `Guide to ${serviceTitle}`,
    overview: `Professional ${serviceTitle} ensures strict compliance with Indian statutory authorities while saving valuable business time.`,
    checklistTitle: 'Required Documents',
    checklist: activeWhyChoose.requirements || ['PAN Card of Business / Applicant', 'Aadhaar Card linked with Mobile', 'Registered Business Address Proof', 'Bank Statement / Cancelled Cheque']
  };

  const activeFaqs = pageConfig?.faqs || config?.faqs || [
    { q: `How long does the ${serviceTitle} process take?`, a: 'Standard turnaround is 3 to 5 business days subject to departmental approval queues.' },
    { q: 'Can I adjust the consultation fee against the final package?', a: 'Yes! If you book an expert CA/CS consultation at ₹499, the full ₹499 is credited and deducted when you upgrade to any full registration plan.' }
  ];

  const activePopularSearches = pageConfig?.popularSearches || config?.popularSearches || [serviceTitle, `${serviceTitle} Online`, `${serviceTitle} Fees in India`, `${serviceTitle} Consultant`];
  
  const activeRelatedServices = config?.relatedServices || [
    { title: "Private Limited Company", price: "₹6,499", desc: "Corporate incorporation with full MCA, PAN, TAN and bank setup.", link: "/pvt-ltd-registration" },
    { title: "GST Registration & Filing", price: "₹2,569", desc: "GSTIN registration with monthly compliance filing.", link: "/gst-registration" },
    { title: "Trademark Registration", price: "₹1,999", desc: "Protect your brand name, logo, and intellectual property.", link: "/trademark-registration" },
    { title: "ISO 9001:2015 Certification", price: "₹4,499", desc: "Quality management certification with IAF global accreditation.", link: "/iso-9001-certification" }
  ];

  const handlePackageClick = (pkg) => {
    setSelectedPlan(pkg);
    trackLead({
      serviceId: pageId,
      serviceName: serviceTitle,
      packageName: pkg.name,
      price: pkg.price,
      category: 'PACKAGE_CLICK',
      source: 'web'
    });

    if (userInfo && userInfo.token) {
      launchRazorpayCheckout({
        amount: pkg.price,
        serviceName: serviceTitle,
        packageName: pkg.name,
        customerName: userInfo.name || 'Client',
        customerEmail: userInfo.email || 'client@vrhere.in',
        customerPhone: userInfo.phone || '',
        onSuccess: (paymentId, orderId, signature) => {
          showPaymentSuccessPopup({
            serviceName: serviceTitle,
            packageName: pkg.name,
            amount: pkg.price,
            paymentId: paymentId
          });
        }
      });
    } else {
      setShowConsultationModal(true);
    }
  };

  const handleConsultationBook = () => {
    trackLead({
      serviceId: pageId,
      serviceName: serviceTitle,
      packageName: 'Expert Consultation',
      price: activeHero.consultationPrice || 499,
      category: 'PACKAGE_CLICK',
      source: 'web'
    });
    setShowConsultationModal(true);
  };

  return (
    <div className="min-h-screen bg-white flex flex-col font-sans antialiased text-slate-900">
      <SharedHeader />

      <div id="main-service-container" className="flex-1">
        {/* 1. Hero Section */}
        <section className="relative pt-24 pb-20 lg:pt-32 lg:pb-28 bg-slate-50 overflow-hidden">
          <div className="absolute top-0 right-0 w-1/2 h-full bg-red-50 skew-x-12 opacity-50 z-0 translate-x-1/3"></div>
          
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 flex flex-col lg:flex-row items-center gap-12">
            <div className="lg:w-1/2">
              <div className="inline-flex items-center px-4 py-1.5 rounded-full bg-white border border-slate-200 shadow-xs text-xs font-black text-slate-700 mb-6 uppercase tracking-wider">
                <span className="w-2 h-2 bg-emerald-500 rounded-full mr-2 animate-pulse"></span>
                {sanitizeText(activeHero.badgeText, pageConfig?.city)}
              </div>

              <h1 className="text-3xl sm:text-5xl lg:text-6xl font-black text-slate-900 tracking-tight leading-[1.1] mb-6">
                {sanitizeText(activeHero.title, pageConfig?.city)}
              </h1>

              <p className="text-lg text-slate-600 leading-relaxed mb-8 font-medium">
                {sanitizeText(activeHero.subtitle, pageConfig?.city)}
              </p>

              <div className="flex flex-col sm:flex-row gap-4 mb-6">
                <button
                  onClick={handleConsultationBook}
                  className="bg-red-600 text-white px-8 py-4 rounded-2xl font-black text-base hover:bg-red-700 transition shadow-xl shadow-red-600/20 transform hover:-translate-y-0.5 active:scale-95 flex items-center justify-center gap-2"
                >
                  <span>Book Consultation @ ₹{activeHero.consultationPrice || 499}</span>
                  <ArrowRight className="w-5 h-5" />
                </button>
                <a
                  href="#pricing-plans"
                  className="px-8 py-4 bg-white hover:bg-slate-100 text-slate-800 border border-slate-200 rounded-2xl font-bold text-base transition flex items-center justify-center gap-2 shadow-xs"
                >
                  <span>View All Packages</span>
                  <ChevronDown className="w-4 h-4" />
                </a>
              </div>

              <div className="flex items-center space-x-2 text-xs font-bold text-slate-500">
                <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                <span>100% Fee adjustable against your final package</span>
              </div>
            </div>

            {/* Hero Graphic Card */}
            <div className="lg:w-1/2 relative hidden lg:block">
              <div className="relative z-10 bg-white p-8 rounded-3xl shadow-2xl border border-slate-100 transform rotate-1 hover:rotate-0 transition duration-500">
                <div className="flex justify-between items-start mb-6">
                  <div>
                    <h3 className="text-xl font-bold text-slate-900">{serviceTitle}</h3>
                    <p className="text-slate-500 text-xs font-semibold mt-0.5">All-inclusive professional execution</p>
                  </div>
                  <div className="bg-emerald-50 text-emerald-700 font-black px-3 py-1 rounded-full text-[10px] uppercase tracking-wider border border-emerald-200">
                    VERIFIED & COMPLIANT
                  </div>
                </div>
                <div className="space-y-3">
                  {activeHeroGraphicItems.map((item, i) => (
                    <div key={i} className="flex items-center p-3 bg-slate-50 rounded-xl border border-slate-100">
                      <CheckCircle className="w-4 h-4 text-red-600 mr-3 shrink-0" />
                      <span className="font-semibold text-xs text-slate-700">{item}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[120%] h-[120%] bg-gradient-to-tr from-red-100 to-orange-100 rounded-full blur-3xl -z-10 opacity-60"></div>
            </div>
          </div>
        </section>

        {/* 2. Client Logos Marquee & Stats */}
        <section className="bg-slate-900 py-10 relative overflow-hidden">
          <style>{`
            @keyframes universalMarquee {
              0% { transform: translateX(0%); }
              100% { transform: translateX(-50%); }
            }
            .animate-universal-marquee {
              display: flex;
              animation: universalMarquee 25s linear infinite;
            }
          `}</style>

          <div className="max-w-7xl mx-auto px-4 mb-4 text-center">
            <p className="text-[11px] uppercase font-black tracking-widest text-red-400">
              Trusted By Over 5,000+ Fast-Growing Indian Startups & Businesses
            </p>
          </div>

          <div className="w-full overflow-hidden relative flex py-3 mb-8 bg-slate-900/60 border-y border-slate-800">
            <div className="animate-universal-marquee space-x-12">
              {[...activeLogos, ...activeLogos].map((logo, idx) => {
                const Icon = Lucide[logo.iconKey] || Lucide.Globe;
                return (
                  <div key={idx} className="inline-flex items-center gap-2.5 px-6 py-2 bg-slate-800/40 rounded-xl border border-slate-700/30 shrink-0">
                    <Icon className={`w-4 h-4 ${logo.colorClass || 'text-slate-400'}`} />
                    <span className="text-xs font-black tracking-tight text-slate-300">{logo.name}</span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="max-w-7xl mx-auto px-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
              {activeStats.map((stat, idx) => (
                <div key={idx} className="p-2">
                  <div className="text-2xl sm:text-4xl font-black text-white">{stat.value}</div>
                  <div className="text-[10px] sm:text-xs font-black tracking-widest text-red-400 uppercase mt-1">
                    {stat.label}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 3. Pricing / Packages */}
        <section id="pricing" className="py-20 bg-slate-50">
          <div id="pricing-plans" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center mb-16">
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mb-4 tracking-tight">
                Registration Fees & Packages
              </h2>
              <p className="text-slate-600 font-medium">
                Transparent pricing. No hidden fees.
              </p>
            </div>

            <div
              className={`grid gap-6 justify-center ${
                activePackages.length === 1
                  ? 'max-w-md mx-auto grid-cols-1'
                  : activePackages.length === 2
                  ? 'max-w-3xl mx-auto grid-cols-1 md:grid-cols-2'
                  : activePackages.length === 3
                  ? 'max-w-5xl mx-auto grid-cols-1 md:grid-cols-3'
                  : 'max-w-[1400px] mx-auto grid-cols-1 md:grid-cols-2 lg:grid-cols-4'
              }`}
            >
              {activePackages.map((pkg, idx) => {
                const isPopular = pkg.isPopular !== undefined ? pkg.isPopular : (activePackages.length > 1 && idx === 1);
                return (
                  <div
                    key={pkg.id || idx}
                    className={`bg-white rounded-2xl p-8 border transition-all duration-300 flex flex-col relative transform hover:-translate-y-4 hover:shadow-2xl ${
                      isPopular
                        ? 'border-red-600 shadow-xl scale-105 z-10'
                        : 'border-slate-200 hover:border-red-300 shadow-sm'
                    }`}
                  >
                    {isPopular && (
                      <div className="absolute top-0 right-0 bg-red-600 text-white text-xs font-bold px-3 py-1 rounded-bl-lg rounded-tr-lg shadow-md">
                        RECOMMENDED
                      </div>
                    )}

                    <h3 className="text-xl font-bold text-slate-900 mb-2">{pkg.name}</h3>
                    <div className="text-4xl font-black text-slate-900 mb-6">
                      ₹{pkg.price?.toLocaleString('en-IN') || pkg.price}
                      <span className="text-[10px] font-bold text-slate-500 ml-1 block mt-1">
                        {pkg.isAdjustable ? '(Fully Adjustable)' : '+ Govt Fees & GST'}
                      </span>
                    </div>

                    {pkg.isAdjustable && (
                      <div className="bg-green-50 text-green-700 text-xs font-bold p-2 rounded mb-4 flex items-center">
                        <RefreshCw className="w-3 h-3 mr-1" /> Fee Adjustable in Final Package
                      </div>
                    )}

                    <p className="text-sm text-slate-600 mb-6 font-medium leading-relaxed">
                      {pkg.description || `Full statutory ${serviceTitle} execution.`}
                    </p>

                    <div className="space-y-4 mb-8 flex-1">
                      {(pkg.features || []).map((feat, fIdx) => (
                        <div key={fIdx} className="flex items-start text-sm text-slate-700 font-medium group">
                          <CheckCircle2 className="w-4 h-4 text-green-500 mr-2 mt-0.5 flex-shrink-0 group-hover:scale-125 transition-transform" />
                          <span>{feat}</span>
                        </div>
                      ))}
                    </div>

                    <button
                      onClick={() => handlePackageClick(pkg)}
                      className={`w-full py-4 rounded-xl font-bold transition transform active:scale-95 ${
                        isPopular || pkg.isAdjustable
                          ? 'bg-red-600 text-white hover:bg-red-700 shadow-lg shadow-red-600/30'
                          : 'bg-slate-100 text-slate-900 hover:bg-slate-200'
                      }`}
                    >
                      {pkg.creativeButtonText || pkg.buttonText || (isPopular ? `Select ${pkg.name}` : `Select ${pkg.name}`)}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        {/* 4. Customer Reviews Section */}
        <section className="py-20 bg-white border-t border-slate-100">
          <div className="max-w-7xl mx-auto px-4">
            <div className="text-center mb-16">
              <span className="text-xs uppercase font-black tracking-widest text-red-600 bg-red-50 px-3 py-1.5 rounded-full font-bold">
                Real Client Reviews
              </span>
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mt-4 tracking-tight">
                Trusted by 5,000+ Founders
              </h2>
            </div>
            <div className="grid md:grid-cols-3 gap-6">
              {activeReviews.map((review, i) => (
                <div key={i} className="bg-slate-50 p-8 rounded-3xl border border-slate-200/80 shadow-xs flex flex-col justify-between hover:shadow-md transition">
                  <div>
                    <div className="flex items-center mb-4 text-amber-400">
                      {[...Array(review.rating || 5)].map((_, r) => (
                        <Star key={r} className="w-4 h-4 fill-amber-400" />
                      ))}
                    </div>
                    <p className="text-slate-600 text-xs leading-relaxed font-medium mb-6 italic">
                      "{review.text}"
                    </p>
                  </div>
                  <div className="flex items-center gap-3 border-t border-slate-200/50 pt-4">
                    <div className="w-10 h-10 rounded-full bg-slate-900 text-white flex items-center justify-center font-black text-xs">
                      {review.avatar || review.name?.charAt(0)}
                    </div>
                    <div>
                      <div className="flex items-center gap-1.5">
                        <h4 className="font-bold text-slate-900 text-sm">{review.name}</h4>
                        {review.verified && <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />}
                      </div>
                      <p className="text-slate-400 text-[10px] font-black uppercase tracking-wider">{review.company}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 5. Process Roadmap */}
        {activeSteps.length > 0 && (
          <section className="py-24 bg-slate-50 border-t border-slate-100">
            <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="text-center mb-20">
                <span className="text-xs uppercase font-black tracking-widest text-red-600 bg-red-50 px-3 py-1.5 rounded-full font-bold">
                  Execution Flow
                </span>
                <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mt-4 tracking-tight">
                  Redesigned, Effortless Steps
                </h2>
                <p className="text-base text-slate-600 mt-2 font-medium">
                  100% online process managed by senior legal & financial practitioners.
                </p>
              </div>

              <div className="grid md:grid-cols-4 gap-6">
                {activeSteps.map((step, idx) => (
                  <div key={idx} className="bg-white p-8 rounded-3xl shadow-xl border border-slate-100 text-center hover:-translate-y-2 transition-all duration-300 relative group">
                    <div className="w-16 h-16 bg-gradient-to-br from-red-600 to-orange-600 text-white rounded-2xl flex items-center justify-center text-2xl font-black mx-auto mb-6 shadow-xl shadow-red-600/20 transform group-hover:rotate-6 transition-all border-4 border-white">
                      {step.number || `0${idx + 1}`}
                    </div>
                    <div className="inline-block px-3 py-1 bg-slate-50 border border-slate-100 rounded-full text-[10px] font-black uppercase text-slate-500 mb-4">
                      {step.badge || `Step ${idx + 1}`}
                    </div>
                    <h3 className="font-bold text-base text-slate-900 mb-2 tracking-tight">{step.title}</h3>
                    <p className="text-slate-600 text-xs leading-relaxed font-medium">{step.desc}</p>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        {/* 6. Why Choose & Statutory Requirements */}
        <section className="py-20 bg-white border-t border-slate-100">
          <div className="max-w-7xl mx-auto px-4 flex flex-col md:flex-row gap-12 items-center">
            <div className="md:w-1/2">
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mb-6 tracking-tight">
                {activeWhyChoose.title || `Why Choose VR Here for ${serviceTitle}?`}
              </h2>
              <p className="text-slate-600 mb-8 leading-relaxed font-medium text-sm">
                {activeWhyChoose.subtitle || `Get certified legal execution, dedicated financial modeling, and end-to-end statutory assistance from senior chartered accountants.`}
              </p>
              <div className="grid grid-cols-1 gap-4">
                {(activeWhyChoose.benefits || []).map((item, i) => (
                  <div key={i} className="flex items-start p-4 bg-slate-50 rounded-2xl border border-slate-200/80">
                    <CheckCircle2 className="w-5 h-5 text-emerald-500 mr-4 shrink-0 mt-0.5" />
                    <div>
                      <h4 className="font-bold text-slate-900 text-sm">{item.t}</h4>
                      <p className="text-xs text-slate-500 font-medium mt-0.5">{item.d}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="md:w-1/2">
              <div className="bg-slate-50 p-8 rounded-3xl border border-slate-200 shadow-xs">
                <h3 className="text-xl font-black text-slate-900 mb-6 text-center">Required Checklist</h3>
                <ul className="space-y-3.5">
                  {(activeWhyChoose.requirements || activeGuide.checklist || [
                    "PAN & Aadhaar Card of Applicant / Directors",
                    "Registered Business Address Proof (Electricity Bill / Rent Deed)",
                    "Digital Signature Certificate (Class 3 DSC) for online filings",
                    "Active Mobile Number & Email linked with Aadhaar",
                    "Bank Account Details with Cancelled Cheque"
                  ]).map((req, i) => (
                    <li key={i} className="flex items-center text-slate-700 bg-white p-3.5 rounded-xl border border-slate-200 shadow-2xs text-xs font-bold">
                      <UsersIcon className="w-4 h-4 text-red-600 mr-3 shrink-0" /> {req}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* 7. Collapsible 3-Block Section (Guide, FAQs, Popular Searches) */}
        <section className="py-16 bg-white border-t border-slate-100">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
            <button
              onClick={() => setIsSeoExpanded(!isSeoExpanded)}
              className="inline-flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-white px-8 py-4 rounded-xl font-bold transition shadow-xl active:scale-95 text-xs uppercase tracking-wider"
            >
              <span>{isSeoExpanded ? 'Hide Detailed Guide & FAQs' : 'Show Detailed Guide & FAQs'}</span>
              <ChevronDown className={`w-4 h-4 transition-transform duration-300 ${isSeoExpanded ? 'rotate-180' : ''}`} />
            </button>

            {isSeoExpanded && (
              <div className="mt-12 text-left bg-slate-50 p-8 md:p-12 rounded-3xl border border-slate-200 animate-in fade-in slide-in-from-top-4 duration-300 grid grid-cols-1 lg:grid-cols-3 gap-10">
                {/* Column 1: Guide */}
                <div className="space-y-4 max-h-[500px] overflow-y-auto pr-4">
                  <h3 className="text-lg font-black text-slate-900 border-b-2 border-red-500 pb-2">
                    {activeGuide.title || `Guide to ${serviceTitle}`}
                  </h3>
                  {activeGuide.overview && (
                    <p className="text-xs text-slate-600 leading-relaxed font-semibold">
                      {sanitizeText(activeGuide.overview, pageConfig?.city)}
                    </p>
                  )}
                  {activeGuide.checklist && activeGuide.checklist.length > 0 && (
                    <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-inner">
                      <h4 className="text-xs font-black uppercase text-slate-900 mb-2">
                        {activeGuide.checklistTitle || 'Required Documents'}
                      </h4>
                      <ul className="text-xs text-slate-600 space-y-1.5 font-bold">
                        {activeGuide.checklist.map((item, cIdx) => (
                          <li key={cIdx} className="flex items-center gap-1.5">
                            <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                            <span>{sanitizeText(item, pageConfig?.city)}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Column 2: FAQs */}
                <div className="space-y-4">
                  <h3 className="text-lg font-black text-slate-900 border-b-2 border-orange-500 pb-2">
                    Frequently Asked Questions
                  </h3>
                  <div className="space-y-2.5">
                    {activeFaqs.map((faq, idx) => (
                      <div key={idx} className="bg-white rounded-xl border border-slate-200 overflow-hidden">
                        <button
                          onClick={() => setActiveFaq(activeFaq === idx ? null : idx)}
                          className="w-full p-3.5 flex items-center justify-between text-left font-bold text-xs text-slate-800 hover:bg-slate-50 transition"
                        >
                          <span>{sanitizeText(faq.q, pageConfig?.city)}</span>
                          <ChevronDown className={`w-3.5 h-3.5 text-slate-400 shrink-0 ml-2 transition-transform ${activeFaq === idx ? 'rotate-180' : ''}`} />
                        </button>
                        {activeFaq === idx && (
                          <div className="p-3.5 border-t border-slate-100 text-xs text-slate-600 leading-relaxed bg-slate-50/50 font-medium">
                            {sanitizeText(faq.a, pageConfig?.city)}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Column 3: Searches */}
                <div className="space-y-4">
                  <h3 className="text-lg font-black text-slate-900 border-b-2 border-indigo-500 pb-2">
                    Popular Searches
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {activePopularSearches.map((tag, idx) => (
                      <span key={idx} className="px-2.5 py-1 bg-white hover:bg-red-50 text-slate-600 hover:text-red-700 rounded-lg border border-slate-200 text-[11px] font-semibold transition cursor-default">
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
        <section className="py-20 bg-slate-50 border-t border-slate-200/60">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-xl mx-auto mb-16">
              <span className="text-xs uppercase font-black tracking-widest text-red-600 bg-red-50 px-3 py-1.5 rounded-full font-bold">
                Explore Catalog
              </span>
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mt-4 tracking-tight">
                Related Compliance Services
              </h2>
              <p className="text-base text-slate-600 mt-2 font-medium">Grow your business legally with our allied setup packages.</p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              {activeRelatedServices.map((srv, idx) => (
                <div key={idx} className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm hover:shadow-md transition flex flex-col justify-between">
                  <div>
                    <h3 className="font-bold text-base text-slate-900 mb-1">{srv.title}</h3>
                    <div className="text-red-600 font-black text-lg mb-3">{srv.price} <span className="text-[10px] text-slate-400 font-bold uppercase">+ Govt Fees</span></div>
                    <p className="text-slate-500 text-xs leading-relaxed font-medium mb-6">{srv.desc}</p>
                  </div>
                  <button
                    onClick={() => navigate(srv.link)}
                    className="w-full py-2.5 bg-slate-100 hover:bg-red-600 hover:text-white rounded-xl text-xs font-bold text-slate-800 transition flex items-center justify-center gap-1.5"
                  >
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
            <p className="text-lg text-slate-400 mb-10 leading-relaxed font-medium">
              Talk to our CA/CS specialists before you commit. Pay a small booking fee now, and we will deduct it from your final bill.
            </p>
            <div className="bg-white/10 backdrop-blur-md p-8 rounded-3xl border border-white/10 inline-block w-full max-w-md">
              <div className="text-xs font-black text-red-400 uppercase tracking-widest mb-2">Consultation Offer</div>
              <div className="text-5xl font-black mb-2">₹{activeHero.consultationPrice || 499}</div>
              <p className="text-slate-300 text-xs mb-6 font-medium">Fully adjustable against registration fees</p>
              <button
                onClick={handleConsultationBook}
                className="w-full bg-red-600 text-white font-bold py-4 rounded-2xl hover:bg-red-700 transition shadow-lg shadow-red-600/30 flex items-center justify-center text-sm font-black"
              >
                Book Now <ArrowRight className="ml-2 w-5 h-5" />
              </button>
            </div>
          </div>
        </section>
      </div>

      {/* Consultation Modal */}
      {showConsultationModal && (
        <ConsultationPaymentModal
          isOpen={showConsultationModal}
          onClose={() => {
            setShowConsultationModal(false);
            setSelectedPlan(null);
          }}
          selectedPlan={selectedPlan || {
            name: `${serviceTitle} Consultation`,
            price: activeHero.consultationPrice || 499,
            isAdjustable: true
          }}
          title={selectedPlan ? `Get Started: ${selectedPlan.name}` : `Consultation: ${serviceTitle}`}
          defaultService={serviceTitle}
          price={selectedPlan?.price || activeHero.consultationPrice || 499}
        />
      )}

      <SharedFooter />
    </div>
  );
};

export default UniversalServicePage;
