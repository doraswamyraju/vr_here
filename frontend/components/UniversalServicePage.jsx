import React, { useState, useEffect } from 'react';
import {
  Briefcase, Globe, Zap, Clock, Award, ArrowRight, CheckCircle2,
  Building2, CheckCircle, FileText, Star, User as UsersIcon, Check, HelpCircle,
  MessageSquare, ShieldCheck, TrendingUp, ChevronRight, ChevronDown, Download,
  Loader2, CreditCard, RefreshCw, Phone, Sparkles
} from 'lucide-react';
import { SharedHeader, SharedFooter } from './SharedComponents';
import ConsultationPaymentModal from './ConsultationPaymentModal';
import { launchRazorpayCheckout } from '../utils/razorpayCheckout';
import { useNavigate } from 'react-router-dom';
import { showPaymentSuccessPopup } from '../utils/paymentSuccessPopup';
import { fetchServicePageConfig, updateServicePageConfig } from '../modules/service-editor/v1.1/services/serviceConfigApi';
import InlineEditOverlay from '../modules/service-editor/v1.1/components/InlineEditOverlay';
import SeoAeoDashboard from '../modules/seo-aeo-analyzer/v1.1/components/SeoAeoDashboard';
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
  const [isCustomizerOpen, setIsCustomizerOpen] = useState(false);
  const [isSeoGraderOpen, setIsSeoGraderOpen] = useState(false);
  const [savingOverlay, setSavingOverlay] = useState(false);
  const [pageHtmlContent, setPageHtmlContent] = useState('');

  useEffect(() => {
    // 1. Send Category A Lead Telemetry (PAGE_VIEW / Warm Lead)
    trackLead({
      serviceId: pageId,
      serviceName: config?.title || 'VR Here Legal Service',
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

  useEffect(() => {
    const el = document.getElementById('main-service-container');
    if (el) setPageHtmlContent(el.innerHTML);
  }, [pageConfig, loading]);

  const activeHero = pageConfig?.hero || config?.hero || {
    title: config?.title || "Legal & Compliance Service Online",
    subtitle: "Fast, transparent, 100% online filings with dedicated CA/CS assistance.",
    badgeText: "GOVT & ISO VERIFIED",
    consultationPrice: 499
  };

  const activeStats = pageConfig?.stats || config?.stats || [
    { value: "7 Days", label: "AVG. TURNAROUND" },
    { value: "5,000+", label: "HAPPY FOUNDERS" },
    { value: "4.9/5", label: "GOOGLE RATING" },
    { value: "100%", label: "ONLINE PROCESS" }
  ];

  const activePackages = pageConfig?.packages || config?.packages || [];
  const activeSteps = pageConfig?.steps || config?.steps || [];
  const activeGuide = pageConfig?.guide || config?.guide || {};
  const activeFaqs = pageConfig?.faqs || config?.faqs || [];
  const activePopularSearches = pageConfig?.popularSearches || config?.popularSearches || [];
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
      serviceName: pageConfig?.title || config?.title || 'Service',
      packageName: pkg.name,
      price: pkg.price,
      category: 'PACKAGE_CLICK',
      source: 'web'
    });

    if (userInfo && userInfo.token) {
      launchRazorpayCheckout({
        amount: pkg.price,
        serviceName: pageConfig?.title || config?.title || 'Service',
        packageName: pkg.name,
        customerName: userInfo.name || 'Client',
        customerEmail: userInfo.email || 'client@vrhere.in',
        customerPhone: userInfo.phone || '',
        onSuccess: (paymentId, orderId, signature) => {
          showPaymentSuccessPopup({
            serviceName: pageConfig?.title || config?.title || 'Service',
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
      serviceName: pageConfig?.title || config?.title || 'Service',
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
        <section className="relative pt-32 pb-20 md:pt-40 md:pb-28 bg-gradient-to-b from-slate-950 via-slate-900 to-indigo-950 text-white overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(#6366f1_1px,transparent_1px)] [background-size:24px_24px] opacity-20"></div>
          
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
            <div className="max-w-3xl mx-auto text-center">
              {/* Badge */}
              <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-indigo-500/10 border border-indigo-400/30 text-indigo-300 text-xs font-black tracking-wider uppercase mb-6 backdrop-blur-md">
                <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                <span>{sanitizeText(activeHero.badgeText, pageConfig?.city)}</span>
              </div>

              {/* Title */}
              <h1 className="text-3xl sm:text-5xl lg:text-6xl font-black tracking-tight text-white leading-tight">
                {sanitizeText(activeHero.title, pageConfig?.city)}
              </h1>

              {/* Subtitle */}
              <p className="mt-6 text-base sm:text-lg text-slate-300 font-medium leading-relaxed max-w-2xl mx-auto">
                {sanitizeText(activeHero.subtitle, pageConfig?.city)}
              </p>

              {/* Consultation CTA Pill */}
              <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
                <button
                  onClick={handleConsultationBook}
                  className="w-full sm:w-auto px-8 py-4 bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-700 hover:to-orange-700 text-white rounded-2xl font-black text-sm shadow-xl shadow-red-600/30 transition transform hover:-translate-y-0.5 active:translate-y-0 flex items-center justify-center gap-2"
                >
                  <span>Book CA/CS Call @ ₹{activeHero.consultationPrice || 499}</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
                
                <a
                  href="#pricing-plans"
                  className="w-full sm:w-auto px-8 py-4 bg-white/10 hover:bg-white/20 text-white border border-white/20 rounded-2xl font-bold text-sm backdrop-blur-md transition flex items-center justify-center gap-2"
                >
                  <span>View All Packages</span>
                  <ChevronDown className="w-4 h-4" />
                </a>
              </div>
            </div>
          </div>
        </section>

        {/* 2. Stats Trust Marquee */}
        <section className="bg-slate-900 border-y border-slate-800 py-6">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
              {activeStats.map((stat, idx) => (
                <div key={idx} className="p-3">
                  <div className="text-2xl sm:text-3xl font-black text-white">{stat.value}</div>
                  <div className="text-[10px] sm:text-xs font-black tracking-widest text-indigo-400 uppercase mt-1">
                    {stat.label}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 3. Pricing Packages */}
        <section id="pricing-plans" className="py-20 bg-slate-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-2xl mx-auto mb-16">
              <span className="text-xs uppercase font-black tracking-widest text-indigo-600 bg-indigo-50 px-3 py-1.5 rounded-full border border-indigo-100 font-bold">
                Transparent Pricing
              </span>
              <h2 className="text-3xl sm:text-4xl font-black text-slate-900 mt-4 tracking-tight">
                Select Your Registration Plan
              </h2>
              <p className="text-sm sm:text-base text-slate-600 mt-2 font-medium">
                No hidden costs. 100% money-back compliance guarantee.
              </p>
            </div>

            <div className={`grid gap-8 ${activePackages.length === 1 ? 'max-w-md mx-auto' : activePackages.length === 2 ? 'max-w-3xl mx-auto md:grid-cols-2' : 'grid-cols-1 md:grid-cols-3'}`}>
              {activePackages.map((pkg, idx) => {
                const isPopular = pkg.isPopular || idx === 1;
                return (
                  <div
                    key={idx}
                    className={`bg-white rounded-3xl p-8 border transition-all duration-300 flex flex-col justify-between relative ${
                      isPopular
                        ? 'border-indigo-600 shadow-2xl shadow-indigo-600/10 ring-2 ring-indigo-600/20 md:-translate-y-2'
                        : 'border-slate-200 shadow-md hover:shadow-xl'
                    }`}
                  >
                    {isPopular && (
                      <div className="absolute -top-3.5 left-1/2 transform -translate-x-1/2 px-4 py-1 bg-gradient-to-r from-red-600 to-orange-600 text-white text-[10px] font-black uppercase tracking-wider rounded-full shadow-md">
                        MOST POPULAR
                      </div>
                    )}

                    <div>
                      <h3 className="text-xl font-bold text-slate-900">{pkg.name}</h3>
                      <div className="mt-4 flex items-baseline gap-1">
                        <span className="text-4xl font-black text-slate-950">₹{pkg.price?.toLocaleString()}</span>
                        <span className="text-xs text-slate-500 font-semibold">
                          {pkg.isAdjustable ? '(100% credited)' : '+ Govt Fees'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-500 mt-2 leading-relaxed font-medium">
                        {pkg.description || 'Full statutory registration & compliance certificate.'}
                      </p>

                      <hr className="my-6 border-slate-100" />

                      <ul className="space-y-3 mb-8">
                        {(pkg.features || []).map((feat, fIdx) => (
                          <li key={fIdx} className="flex items-start gap-2 text-xs font-semibold text-slate-700">
                            <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                            <span>{feat}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <button
                      onClick={() => handlePackageClick(pkg)}
                      className={`w-full py-4 rounded-xl font-black text-xs uppercase tracking-wider transition-all shadow-md flex items-center justify-center gap-2 ${
                        isPopular
                          ? 'bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white shadow-indigo-600/30'
                          : 'bg-slate-900 hover:bg-slate-800 text-white'
                      }`}
                    >
                      <span>{pkg.creativeButtonText || `PROCEED WITH ${pkg.name}`}</span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        {/* 4. Process Roadmap */}
        {activeSteps.length > 0 && (
          <section className="py-20 bg-white border-t border-slate-100">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="text-center max-w-2xl mx-auto mb-16">
                <span className="text-xs uppercase font-black tracking-widest text-indigo-600 bg-indigo-50 px-3 py-1.5 rounded-full border border-indigo-100 font-bold">
                  Step-by-Step Roadmap
                </span>
                <h2 className="text-3xl sm:text-4xl font-black text-slate-900 mt-4 tracking-tight">
                  How the Process Works
                </h2>
                <p className="text-sm sm:text-base text-slate-600 mt-2 font-medium">
                  Effortless 4-step onboarding handled by certified legal practitioners.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                {activeSteps.map((step, idx) => (
                  <div key={idx} className="bg-slate-50 p-6 rounded-3xl border border-slate-200/80 text-center relative group hover:-translate-y-1 transition">
                    <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-indigo-600 to-indigo-800 text-white text-xl font-black flex items-center justify-center mx-auto mb-4 shadow-lg shadow-indigo-600/20">
                      {step.number || `0${idx + 1}`}
                    </div>
                    <span className="inline-block text-[10px] font-black uppercase text-indigo-600 bg-indigo-50 px-2.5 py-0.5 rounded-md mb-2">
                      {step.badge || `Step ${idx + 1}`}
                    </span>
                    <h3 className="text-base font-bold text-slate-900 mb-2">{step.title}</h3>
                    <p className="text-xs text-slate-600 font-medium leading-relaxed">{step.desc}</p>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        {/* 5. Detailed Guide, FAQs & SEO Searches */}
        <section className="py-16 bg-white border-t border-slate-100">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
            <button
              onClick={() => setIsSeoExpanded(!isSeoExpanded)}
              className="inline-flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-white px-8 py-3.5 rounded-xl font-bold transition shadow-lg text-xs"
            >
              <span>{isSeoExpanded ? 'Hide Detailed Guide & FAQs' : 'Show Detailed Guide & FAQs'}</span>
              <ChevronDown className={`w-4 h-4 transition-transform duration-300 ${isSeoExpanded ? 'rotate-180' : ''}`} />
            </button>

            {isSeoExpanded && (
              <div className="mt-12 text-left bg-slate-50 p-8 md:p-12 rounded-3xl border border-slate-200 animate-in fade-in slide-in-from-top-4 duration-300 grid grid-cols-1 lg:grid-cols-3 gap-10">
                {/* Column 1: Guide */}
                <div className="space-y-4 max-h-[500px] overflow-y-auto pr-4">
                  <h3 className="text-lg font-black text-slate-900 border-b-2 border-indigo-500 pb-2">
                    {activeGuide.title || 'Service Overview & Documents'}
                  </h3>
                  {activeGuide.overview && (
                    <p className="text-xs text-slate-600 leading-relaxed font-semibold">
                      {sanitizeText(activeGuide.overview, pageConfig?.city)}
                    </p>
                  )}
                  {activeGuide.checklist && activeGuide.checklist.length > 0 && (
                    <div className="p-4 bg-white border border-slate-200 rounded-2xl">
                      <h4 className="text-xs font-black uppercase text-slate-900 mb-2">
                        {activeGuide.checklistTitle || 'Required Documents'}
                      </h4>
                      <ul className="text-xs text-slate-600 space-y-1.5 font-medium">
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
                  <h3 className="text-lg font-black text-slate-900 border-b-2 border-emerald-500 pb-2">
                    Popular Searches
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {activePopularSearches.map((tag, idx) => (
                      <span key={idx} className="px-2.5 py-1 bg-white hover:bg-indigo-50 text-slate-600 hover:text-indigo-700 rounded-lg border border-slate-200 text-[11px] font-semibold transition cursor-default">
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* 6. Related Services */}
        <section className="py-16 bg-slate-50 border-t border-slate-200/60">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-xl mx-auto mb-12">
              <span className="text-xs uppercase font-black tracking-widest text-indigo-600 bg-indigo-50 px-3 py-1.5 rounded-full font-bold">
                Allied Solutions
              </span>
              <h2 className="text-2xl sm:text-3xl font-black text-slate-900 mt-3 tracking-tight">
                Related Compliance Services
              </h2>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              {activeRelatedServices.map((srv, idx) => (
                <div key={idx} className="bg-white p-6 rounded-2xl border border-slate-200 shadow-2xs hover:shadow-md transition flex flex-col justify-between">
                  <div>
                    <h3 className="font-bold text-sm text-slate-900 mb-1">{srv.title}</h3>
                    <div className="text-indigo-600 font-black text-base mb-3">{srv.price}</div>
                    <p className="text-slate-500 text-xs leading-relaxed font-medium mb-4">{srv.desc}</p>
                  </div>
                  <button
                    onClick={() => navigate(srv.link)}
                    className="w-full py-2 bg-slate-100 hover:bg-indigo-600 hover:text-white rounded-xl text-xs font-bold text-slate-700 transition flex items-center justify-center gap-1"
                  >
                    <span>Explore Plan</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>

      {/* Consultation Modal */}
      {showConsultationModal && (
        <ConsultationPaymentModal
          isOpen={showConsultationModal}
          onClose={() => setShowConsultationModal(false)}
          defaultService={pageConfig?.title || config?.title || 'Service'}
          price={activeHero.consultationPrice || 499}
        />
      )}

      {/* Admin Customizer Overlay */}
      {pageConfig && isAuthorized && (
        <>
          <InlineEditOverlay
            pageId={pageId}
            config={pageConfig}
            onConfigUpdate={setPageConfig}
            isOpen={isCustomizerOpen}
            setIsOpen={setIsCustomizerOpen}
          />
          <SeoAeoDashboard
            pageId={pageId}
            config={pageConfig}
            currentHtml={pageHtmlContent}
            faqList={activeFaqs}
            seoSettings={pageConfig.seoSettings || {}}
            onUpdateSeoSettings={async (newSettings) => {
              setSavingOverlay(true);
              try {
                const res = await updateServicePageConfig(pageId, { ...pageConfig, seoSettings: newSettings });
                setPageConfig(res);
              } catch (e) {
                console.error(e);
              } finally {
                setSavingOverlay(false);
              }
            }}
            trackingSettings={pageConfig.trackingSettings || {}}
            onUpdateTrackingSettings={async (newSettings) => {
              setSavingOverlay(true);
              try {
                const res = await updateServicePageConfig(pageId, { ...pageConfig, trackingSettings: newSettings });
                setPageConfig(res);
              } catch (e) {
                console.error(e);
              } finally {
                setSavingOverlay(false);
              }
            }}
            isSaving={savingOverlay}
            isOpen={isSeoGraderOpen}
            setIsOpen={setIsSeoGraderOpen}
          />
        </>
      )}

      <SharedFooter />
    </div>
  );
};

export default UniversalServicePage;
