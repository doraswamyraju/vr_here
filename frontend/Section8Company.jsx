import React, { useState, useEffect } from 'react';
import {
  Briefcase, Globe, Zap, Clock, Award, ArrowRight, CheckCircle2,
  Building2, CheckCircle, FileText, Star, User as UsersIcon, Check, HelpCircle,
  MessageSquare, ShieldCheck, TrendingUp, Anchor, Truck, Hammer, FileCheck,
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
import { section8Config } from '../backend/data/serviceConfigs/section8.js';

const PAGE_ID = 'section-8-company';

const Section8CompanyPage = () => {
  const navigate = useNavigate();

  const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
  const isAuthorized = userInfo && (userInfo.role === 'admin' || userInfo.role === 'employee');

  const [pageConfig, setPageConfig] = useState(section8Config);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [isScrolled, setIsScrolled] = useState(false);
  const [isServicesHovered, setIsServicesHovered] = useState(false);
  const [isCollapsibleOpen, setIsCollapsibleOpen] = useState(false);
  const [pageHtmlContent, setPageHtmlContent] = useState('');
  const [savingOverlay, setSavingOverlay] = useState(false);
  const [isCustomizerOpen, setIsCustomizerOpen] = useState(false);
  const [isSeoGraderOpen, setIsSeoGraderOpen] = useState(false);

  const handleUpdateSeoSettings = async (seo) => {
    setSavingOverlay(true);
    try {
      const updated = { ...pageConfig, seoSettings: seo };
      const data = await updateServicePageConfig(PAGE_ID, updated);
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
      const data = await updateServicePageConfig(PAGE_ID, updated);
      setPageConfig(data.page);
    } catch (err) {
      console.error('Failed to update tracking settings:', err);
    } finally {
      setSavingOverlay(false);
    }
  };

  useEffect(() => {
    const loadConfig = async () => {
      try {
        const rawPath = window.location.pathname.replace(/^\//, '') || PAGE_ID;
        const configData = await fetchServicePageConfig(rawPath);
        setPageConfig(configData);

        if (configData.seoSettings?.titleTag || configData.title) {
          document.title = configData.seoSettings?.titleTag || configData.title;
        }

        if (configData.seoSettings?.metaDescription) {
          let metaEl = document.querySelector('meta[name="description"]');
          if (!metaEl) {
            metaEl = document.createElement('meta');
            metaEl.name = 'description';
            document.head.appendChild(metaEl);
          }
          metaEl.content = configData.seoSettings.metaDescription;
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

  const [formData, setFormData] = useState({ name: '', email: '', phone: '' });

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
      onSuccess: (paymentData) => {
        setIsModalOpen(false);
        showPaymentSuccessPopup({
          planName: selectedPlan.name,
          serviceName: 'Section 8 Company Registration',
          amount: selectedPlan.price,
          paymentId: paymentData.razorpay_payment_id || paymentData.paymentId,
          customerName: submittedFormData.name,
          customerPhone: submittedFormData.phone,
          customerEmail: submittedFormData.email,
          onContinue: () => {
            navigate('/customer-dashboard', {
              state: {
                activeTab: 'service-progress',
                serviceName: 'Section 8 Company Registration',
                paymentId: paymentData.razorpay_payment_id || paymentData.paymentId
              }
            });
          }
        });
      },
      onError: (error) => {
        alert(error.message || 'Payment initiation failed. Please try again.');
      }
    });
  };

  return (
    <div id="section8-container" className="min-h-screen bg-slate-50 text-slate-900 flex flex-col justify-between font-sans selection:bg-rose-500 selection:text-white">
      {/* 1. Header */}
      <SharedHeader
        isScrolled={isScrolled}
        isServicesHovered={isServicesHovered}
        setIsServicesHovered={setIsServicesHovered}
      />

      {/* Staff Floating Edit Bar */}
      {isAuthorized && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 bg-slate-900 text-white px-4 py-2.5 rounded-2xl shadow-2xl border border-slate-700">
          <button
            onClick={() => setIsCustomizerOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-rose-600 hover:bg-rose-700 rounded-xl text-xs font-bold transition shadow-sm"
          >
            Edit Page
          </button>
          <button
            onClick={() => setIsSeoGraderOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 rounded-xl text-xs font-bold transition shadow-sm"
          >
            SEO Grader
          </button>
        </div>
      )}

      {/* 2. Hero Section */}
      <main className="flex-grow pt-28 lg:pt-36">
        <section className="relative overflow-hidden bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 text-white py-16 lg:py-24">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(225,29,72,0.15),rgba(255,255,255,0))] pointer-events-none"></div>
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
            <div className="grid lg:grid-cols-12 gap-12 items-center">
              <div className="lg:col-span-7 space-y-6 text-center lg:text-left">
                <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-black uppercase tracking-wider">
                  <Award className="w-3.5 h-3.5 text-rose-400" />
                  <span>{activeHero.badgeText || 'Eligible for CSR & Govt Grants'}</span>
                </div>
                <h1 className="text-3xl sm:text-4xl lg:text-5xl font-black tracking-tight leading-tight">
                  {activeHero.title || 'Register Section 8 NGO Company in {city}'}
                </h1>
                <p className="text-base sm:text-lg text-slate-300 font-medium max-w-2xl mx-auto lg:mx-0">
                  {activeHero.subtitle || 'Launch your charitable trust or non-profit institution with highest credibility, CSR funding eligibility, and 12A/80G tax exemptions in {city}, {state}.'}
                </p>

                <div className="flex flex-wrap items-center justify-center lg:justify-start gap-4 pt-2">
                  <button
                    onClick={handleConsultationBook}
                    className="flex items-center gap-2 px-6 py-3.5 rounded-xl bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white font-bold text-sm shadow-lg shadow-rose-600/30 transition transform hover:-translate-y-0.5"
                  >
                    <span>Book Legal Call @ ₹{activeHero.consultationPrice || 999}</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                  <a
                    href="#packages-section"
                    className="px-6 py-3.5 rounded-xl bg-white/10 hover:bg-white/15 text-white font-bold text-sm border border-white/10 transition"
                  >
                    View Pricing Plans
                  </a>
                </div>

                <div className="flex items-center justify-center lg:justify-start gap-2 text-xs font-semibold text-emerald-400 pt-1">
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Consultation fee of ₹{activeHero.consultationPrice || 999} is 100% adjustable in your final package</span>
                </div>
              </div>

              {/* Hero Stats Card */}
              <div className="lg:col-span-5">
                <div className="bg-slate-800/80 backdrop-blur-md rounded-3xl p-6 lg:p-8 border border-slate-700/60 shadow-2xl space-y-6">
                  <div className="border-b border-slate-700 pb-4">
                    <h3 className="text-lg font-black text-white">Section 8 Highlights</h3>
                    <p className="text-xs text-slate-400">Non-profit corporate governance & CSR readiness</p>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    {activeStats.map((stat, i) => (
                      <div key={i} className="bg-slate-900/60 p-3.5 rounded-2xl border border-slate-700/40">
                        <div className="text-2xl font-black text-white">{stat.value}</div>
                        <div className="text-[11px] font-bold text-rose-400 uppercase tracking-wider mt-0.5">{stat.label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 3. Logos Marquee */}
        <section className="bg-slate-900 border-y border-slate-800 py-6">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <p className="text-center text-xs font-bold uppercase tracking-widest text-slate-400 mb-4">
              Integrated with Leading Donation & CSR Portals
            </p>
            <div className="flex flex-wrap items-center justify-center gap-4 lg:gap-8">
              {activeLogos.map((logo, i) => {
                const IconComponent = Lucide[logo.iconKey] || Briefcase;
                return (
                  <div key={i} className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-slate-800/60 border border-slate-700/50">
                    <IconComponent className={`w-4 h-4 ${logo.colorClass || 'text-indigo-400'}`} />
                    <span className="text-xs font-bold text-slate-300">{logo.name}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        {/* 4. Commercial Packages Section */}
        <section id="packages-section" className="py-20 bg-slate-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-3xl mx-auto mb-16 space-y-3">
              <div className="inline-block text-rose-600 text-xs font-black uppercase tracking-widest">
                Non-Profit Pricing
              </div>
              <h2 className="text-3xl lg:text-4xl font-black text-slate-900 tracking-tight">
                Section 8 NGO Packages & Formation
              </h2>
              <p className="text-sm text-slate-600">
                Complete incorporation, INC-12 license, 12A/80G tax exemptions, and CSR-1 filing.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {activePackages.map((pkg, idx) => (
                <div
                  key={pkg.id || idx}
                  className={`bg-white rounded-3xl p-6 border flex flex-col justify-between transition-all duration-300 relative shadow-sm hover:shadow-xl ${
                    pkg.isPopular ? 'border-rose-500 ring-2 ring-rose-500/20' : 'border-slate-200'
                  }`}
                >
                  {pkg.isPopular && (
                    <div className="absolute -top-3.5 left-1/2 transform -translate-x-1/2 bg-rose-600 text-white text-[10px] font-black uppercase px-3 py-1 rounded-full shadow-md">
                      RECOMMENDED
                    </div>
                  )}

                  <div>
                    <h3 className="text-xl font-black text-slate-900 mb-1">{pkg.name}</h3>
                    <p className="text-xs text-slate-500 min-h-[32px] mb-4">{pkg.description}</p>
                    <div className="bg-slate-50 rounded-2xl p-4 mb-6 border border-slate-100">
                      <div className="flex items-baseline gap-1">
                        <span className="text-3xl font-black text-slate-900">₹{Number(pkg.price).toLocaleString('en-IN')}</span>
                      </div>
                      <div className="text-[10px] font-bold text-slate-400 mt-0.5">
                        {pkg.isAdjustable ? '(Fully Adjustable against Package)' : '+ MCA & Govt Fees'}
                      </div>
                    </div>

                    <div className="space-y-2.5 mb-6">
                      <div className="text-[11px] font-black uppercase tracking-wider text-slate-400">Included Services</div>
                      {(pkg.features || []).map((feat, fIdx) => (
                        <div key={fIdx} className="flex items-start gap-2 text-xs text-slate-700 font-medium">
                          <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                          <span>{feat}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <button
                    onClick={() => handleSelectPlan(pkg)}
                    className={`w-full py-3 rounded-xl font-bold text-xs transition shadow-sm ${
                      pkg.isPopular
                        ? 'bg-rose-600 hover:bg-rose-700 text-white shadow-rose-600/30'
                        : 'bg-slate-900 hover:bg-slate-800 text-white'
                    }`}
                  >
                    {pkg.buttonText || 'Select Plan'}
                  </button>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 5. Process Steps */}
        <section className="py-20 bg-white border-y border-slate-200">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-3xl mx-auto mb-16 space-y-3">
              <div className="inline-block text-rose-600 text-xs font-black uppercase tracking-widest">
                Non-Profit Workflow
              </div>
              <h2 className="text-3xl lg:text-4xl font-black text-slate-900 tracking-tight">
                Section 8 Incorporation Process
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {activeSteps.map((step, idx) => (
                <div key={idx} className="bg-slate-50 rounded-3xl p-6 border border-slate-200 relative space-y-3">
                  <div className="text-3xl font-black text-rose-600/30">{step.number}</div>
                  <h4 className="text-base font-bold text-slate-900">{step.title}</h4>
                  <p className="text-xs text-slate-600 leading-relaxed">{step.desc}</p>
                  <div className="inline-block text-[10px] font-bold uppercase tracking-wider text-rose-600 bg-rose-50 px-2.5 py-1 rounded-md">
                    {step.badge}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 6. Testimonials */}
        <section className="py-20 bg-slate-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-3xl mx-auto mb-16 space-y-3">
              <div className="inline-block text-rose-600 text-xs font-black uppercase tracking-widest">
                NGO Leaders Feedback
              </div>
              <h2 className="text-3xl lg:text-4xl font-black text-slate-900 tracking-tight">
                Section 8 Testimonials
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl mx-auto">
              {activeReviews.map((rev, idx) => (
                <div key={idx} className="bg-white rounded-3xl p-6 border border-slate-200 shadow-sm space-y-4">
                  <div className="flex items-center gap-1 text-amber-400">
                    {[...Array(rev.rating || 5)].map((_, i) => (
                      <Star key={i} className="w-4 h-4 fill-amber-400 text-amber-400" />
                    ))}
                  </div>
                  <p className="text-xs text-slate-700 italic leading-relaxed">"{rev.text}"</p>
                  <div className="pt-2 border-t border-slate-100">
                    <div className="font-bold text-slate-900 text-xs">{rev.name}</div>
                    <div className="text-[11px] text-slate-400">{rev.company} • {rev.date}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 7. Collapsible 3-Block Detailed Guide, FAQs & Popular Searches */}
        <section className="py-12 bg-white border-t border-slate-200">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <button
              onClick={() => setIsCollapsibleOpen(!isCollapsibleOpen)}
              className="w-full flex items-center justify-between p-6 bg-slate-50 hover:bg-slate-100/80 rounded-2xl border border-slate-200 transition"
            >
              <div className="flex items-center gap-3">
                <HelpCircle className="w-6 h-6 text-rose-600" />
                <div className="text-left">
                  <h3 className="text-base font-extrabold text-slate-900">
                    {isCollapsibleOpen ? 'Hide Detailed Legal Guide, FAQs & Search Tags' : 'Show Detailed Legal Guide, FAQs & Search Tags'}
                  </h3>
                  <p className="text-xs text-slate-500">In-depth Section 8 rules, 12A/80G criteria, document checklist & FAQs</p>
                </div>
              </div>
              <ChevronRight className={`w-5 h-5 text-slate-400 transition-transform duration-300 ${isCollapsibleOpen ? 'rotate-90' : ''}`} />
            </button>

            {isCollapsibleOpen && (
              <div className="mt-8 grid grid-cols-1 lg:grid-cols-12 gap-8 pt-6 border-t border-slate-100">
                {/* Block 1: Guide */}
                <div className="lg:col-span-5 space-y-6">
                  <div className="space-y-2">
                    <h4 className="text-lg font-black text-slate-900">{activeGuide.title}</h4>
                    <p className="text-xs text-slate-600 leading-relaxed">{activeGuide.overview}</p>
                  </div>

                  {(activeGuide.sections || []).map((sec, sIdx) => (
                    <div key={sIdx} className="space-y-2">
                      <h5 className="text-xs font-bold text-slate-900 uppercase tracking-wider">{sec.heading}</h5>
                      {sec.content && <p className="text-xs text-slate-600 leading-relaxed">{sec.content}</p>}
                      {sec.bullets && sec.bullets.length > 0 && (
                        <ul className="space-y-1.5 pl-3 text-xs text-slate-600">
                          {sec.bullets.map((b, bIdx) => (
                            <li key={bIdx} className="list-disc leading-relaxed">{b}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}

                  {/* Checklist */}
                  {activeGuide.checklist && activeGuide.checklist.length > 0 && (
                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 space-y-2">
                      <h5 className="text-xs font-black uppercase tracking-wider text-rose-600">{activeGuide.checklistTitle}</h5>
                      <ul className="space-y-1 pl-3 text-xs text-slate-700">
                        {activeGuide.checklist.map((item, cIdx) => (
                          <li key={cIdx} className="list-disc">{item}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Block 2: FAQs */}
                <div className="lg:col-span-4 space-y-4">
                  <h4 className="text-lg font-black text-slate-900">Frequently Asked Questions</h4>
                  <div className="space-y-3">
                    {activeFaqs.map((faq, fIdx) => (
                      <div key={fIdx} className="bg-slate-50 p-4 rounded-2xl border border-slate-200 space-y-1.5">
                        <div className="font-bold text-xs text-slate-900">{faq.q}</div>
                        <div className="text-xs text-slate-600 leading-relaxed">{faq.a}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Block 3: Popular Searches */}
                <div className="lg:col-span-3 space-y-4">
                  <h4 className="text-lg font-black text-slate-900">Popular Searches</h4>
                  <div className="flex flex-wrap gap-2">
                    {activePopularSearches.map((tag, tIdx) => (
                      <span key={tIdx} className="px-2.5 py-1 bg-slate-100 text-slate-700 text-[11px] font-semibold rounded-lg border border-slate-200">
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>
      </main>

      {/* Payment Modal */}
      {isModalOpen && selectedPlan && (
        <ConsultationPaymentModal
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          onSubmit={handleFormSubmit}
          plan={selectedPlan}
          serviceName="Section 8 Company Registration"
        />
      )}

      {/* Admin Overlays */}
      {isAuthorized && isCustomizerOpen && (
        <InlineEditOverlay
          pageId={PAGE_ID}
          pageConfig={pageConfig}
          onClose={() => setIsCustomizerOpen(false)}
          onSaveSuccess={(updated) => setPageConfig(updated)}
        />
      )}

      {isAuthorized && isSeoGraderOpen && (
        <SeoAeoDashboard
          pageConfig={pageConfig}
          pageHtmlContent={pageHtmlContent}
          onClose={() => setIsSeoGraderOpen(false)}
          onUpdateSeoSettings={handleUpdateSeoSettings}
          onUpdateTrackingSettings={handleUpdateTrackingSettings}
        />
      )}

      {/* Footer */}
      <SharedFooter />
    </div>
  );
};

export default Section8CompanyPage;
