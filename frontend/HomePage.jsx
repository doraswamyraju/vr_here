// Force verify build update
import React, { useState, useEffect } from 'react';
import {
  Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
  Phone, Menu, X, ChevronDown, Clock, Award, Search, ArrowRight, CheckCircle2,
  Building2, Mail, MapPin, CheckCircle, Smartphone, ShieldCheck, RefreshCw,
  CreditCard, Loader2, MessageSquare, User as UsersIcon, Star, Quote, HelpCircle, ChevronUp
} from 'lucide-react';
import { SharedHeader, SharedFooter } from './components/SharedComponents';
import ConsultationPaymentModal from './components/ConsultationPaymentModal';
import ProfessionalsModule from './components/OurTeamModule';
import { launchRazorpayCheckout } from './utils/razorpayCheckout';
import { showPaymentSuccessPopup } from './utils/paymentSuccessPopup';
import axios from 'axios';
import PhysicsCapsules from './components/PhysicsCapsules';

// MENU_DATA removed (moved to SharedComponents)

/* --- DATA FOR HOMEPAGE SERVICE GRID --- */
const SERVICES_GRID_DATA = [
  {
    id: 'accounting-compliance-taxation',
    title: 'Accounting, Compliance & Taxation',
    icon: Calculator,
    color: 'bg-red-50 text-red-600 border-red-200',
    badge: 'Popular',
    description: 'Cloud Bookkeeping, GST Returns, ITR 1-7, TDS/TCS & Statutory Audit Support.',
    tags: ['Cloud Accounting', 'GST & ITR', 'Statutory Audits'],
    link: '/all-services?category=accounting-compliance-taxation'
  },
  {
    id: 'certification-quality-management',
    title: 'Certification & Quality Management',
    icon: Stamp,
    color: 'bg-blue-50 text-blue-600 border-blue-200',
    badge: 'Global Standards',
    description: 'ISO 9001, 14001, 27001, 45001, GMP/HACCP, CE, BIS & Halal certifications.',
    tags: ['ISO Standards', 'GMP / HACCP', 'CE & BIS'],
    link: '/all-services?category=certification-quality-management'
  },
  {
    id: 'business-registration-licensing-corporate',
    title: 'Business Registrations & Corporate',
    icon: Briefcase,
    color: 'bg-rose-50 text-rose-600 border-rose-200',
    badge: 'Fast-Track MCA',
    description: 'Private Limited, LLP, Section 8 NGO, OPC, Partnerships, Udyam & FSSAI licenses.',
    tags: ['Pvt Ltd & LLP', 'Section 8 NGO', 'MSME / FSSAI'],
    link: '/all-services?category=business-registration-licensing-corporate'
  },
  {
    id: 'government-portal-registrations',
    title: 'Government Portal Registrations',
    icon: Globe,
    color: 'bg-emerald-50 text-emerald-600 border-emerald-200',
    badge: 'Govt Verified',
    description: 'GeM Seller & OEM, TReDS, RERA, Single-Window & Public Tender management.',
    tags: ['GeM Seller/OEM', 'TReDS Portal', 'RERA Approvals'],
    link: '/all-services?category=government-portal-registrations'
  },
  {
    id: 'industrial-msme-consultancy',
    title: 'Industrial & MSME Consultancy',
    icon: IndianRupee,
    color: 'bg-amber-50 text-amber-600 border-amber-200',
    badge: 'Subsidies & Loans',
    description: 'Bankable DPR preparation, CMA data, PMEGP, CGTMSE loans & state subsidies.',
    tags: ['Bank DPR & CMA', 'PMEGP / CGTMSE', 'State Subsidies'],
    link: '/all-services?category=industrial-msme-consultancy'
  },
  {
    id: 'branding-documentation-startup-support',
    title: 'Branding & Startup Support',
    icon: Lightbulb,
    color: 'bg-purple-50 text-purple-600 border-purple-200',
    badge: 'Growth Ready',
    description: 'Pitch decks for funding, business plans, SOPs, HR documentation & Trademark/IP.',
    tags: ['Pitch Decks', 'SOPs & HR Manuals', 'Trademark & IP'],
    link: '/all-services?category=branding-documentation-startup-support'
  },
  {
    id: 'machinery-industrial-support',
    title: 'Machinery & Industrial Setup',
    icon: Factory,
    color: 'bg-cyan-50 text-cyan-600 border-cyan-200',
    badge: 'Turnkey Execution',
    description: 'Machinery imports, supplier verification, turnkey setup & feasibility studies.',
    tags: ['Machine Imports', 'Supplier Audits', 'Plant Feasibility'],
    link: '/all-services?category=machinery-industrial-support'
  },
  {
    id: 'corporate-compliances-roc',
    title: 'ROC & Corporate Compliances',
    icon: ShieldCheck,
    color: 'bg-orange-50 text-orange-600 border-orange-200',
    badge: 'Statutory Safe',
    description: 'CCFS-2026 penalty relief, ROC annual filings (AOC-4/MGT-7), Director KYC & DSC.',
    tags: ['CCFS-2026 Scheme', 'Annual Filings', 'Director KYC'],
    link: '/compliance-scheme-2026'
  }
];

/* --- PACKAGES DATA (For Modal) --- */
const PACKAGES = [
  {
    id: 'consultation',
    name: 'Expert Consultation',
    price: 499,
    isAdjustable: true,
    description: 'Start here if you are unsure. Fee fully adjusted against registration.',
    features: ['30 Mins CA/CS Call', 'Business Structure Advice', 'Name Availability Check'],
    buttonText: 'Book Consultation'
  }
];

/* --- FAQ DATA --- */
const FAQS = [
  {
    category: "Process & Delivery",
    question: "Do I need to visit your office physically?",
    answer: "Not at all. VR HERE is a 100% cloud-native platform. Document verification, government filings, and fee payments are handled digitally via our encrypted portal. Final certificates, DIN, DSC, and ROC approvals are delivered directly to your email and client dashboard."
  },
  {
    category: "Timeline",
    question: "How long does company registration and licensing take?",
    answer: "Typically, Private Limited & LLP incorporations take 5 to 7 business days, subject to MCA portal processing. Digital signatures (DSC) and PAN/TAN are issued within 24-48 hours. Our dedicated team pre-checks documents to guarantee zero rejection delay."
  },
  {
    category: "Industrial & Finance",
    question: "Can you help with Industrial Project Loans & MSME Subsidies?",
    answer: "Yes! We specialize in end-to-end industrial finance. We prepare bankable Detailed Project Reports (DPR), CMA data, and liaise with major financial institutions for collateral-free loans under CGTMSE, PMEGP, Stand-Up India, and state subsidy schemes."
  },
  {
    category: "Pricing Guarantee",
    question: "How does the '₹499 Consultation Fee Adjustment' work?",
    answer: "Your initial ₹499 consultation fee is 100% credited against any package purchase. When you proceed with your registration, certification, or compliance order within 30 days, ₹499 is automatically deducted from the final invoice."
  },
  {
    category: "Post-Registration",
    question: "What compliance support is provided after registration?",
    answer: "We offer complete post-incorporation compliance including GST return filing, TDS/TCS management, ROC annual filings (AOC-4 & MGT-7), Director KYC, Cloud Bookkeeping on Tally/Zoho, and ISO audit certifications."
  },
  {
    category: "Data Security",
    question: "Is my company and financial data secure?",
    answer: "Absolutely. All documents are encrypted with 256-bit SSL encryption, stored in enterprise vaults, and handled under strict Non-Disclosure Agreements (NDAs). We adhere to ISO 27001:2022 security protocols."
  }
];

/* --- TESTIMONIALS DATA --- */
const TESTIMONIALS = [
  { name: "Srikanth M", role: "Paints & hardware", business: "Bluecat Hardware" },
  { name: "Prashanth B", role: "Sports Event", business: "T Fight club" },
  { name: "PD Manohar", role: "Portfolio Management", business: "ELP Wealth Managers" },
  { name: "Sai Kumar M", role: "Cyber Security services", business: "Cyber Combat" },
  { name: "Santosh G", role: "Food Industry", business: "Swadha Sudha" },
  { name: "Mounica R D", role: "Interior Designing", business: "Mr Dimensions" },
  { name: "Venkatesh A", role: "Constructions", business: "Sai Manogna Constructions" },
  { name: "Radhika P", role: "Manufacturing", business: "Trishul Industries" },
  { name: "Jyothi", role: "Software", business: "Byte weave" },
  { name: "Amit S R", role: "Interview training", business: "Career Egnitor" },
  { name: "Sai Sudha G", role: "Corporate training", business: "Rocksvel" },
  { name: "Moinudeen", role: "AC supporting services", business: "Zain Infra" },
  { name: "Jyasree D", role: "Software & Ocupenture", business: "Sri Urjith" }
];

/* --- SEARCH DATA --- */
const ALL_SERVICES = [
  { name: 'Income Tax Return (ITR) Filing', link: '/income-tax-return', type: 'page' },
  { name: 'Companies Compliance Scheme 2026 (CCFS)', link: '/compliance-scheme-2026', type: 'page' },
  { name: 'Private Limited Registration', link: '/pvt-ltd-registration', type: 'page' },
  { name: 'Partnership Firm Registration', link: '/partnership-firm', type: 'page' },
  { name: 'GST Registration', link: '/gst-registration', type: 'page' },
  { name: 'LLP Registration', link: '/contact?service=LLP Registration', type: 'inquiry' },
  { name: 'One Person Company (OPC)', link: '/contact?service=OPC Registration', type: 'inquiry' },
  { name: 'Section 8 Company (NGO)', link: '/contact?service=Section 8 NGO', type: 'inquiry' },
  { name: 'GST Filing', link: '/contact?service=GST Filing', type: 'inquiry' },
  { name: 'CCFS Form Verification', link: '/contact?service=CCFS Form Verification', type: 'inquiry' },
  { name: 'Trademark Registration', link: '/contact?service=Trademark', type: 'inquiry' },
  { name: 'ISO Certification', link: '/contact?service=ISO Certification', type: 'inquiry' },
  { name: 'MSME Loan / Project Report', link: '/contact?service=MSME Loan', type: 'inquiry' },
  { name: 'Factory License', link: '/contact?service=Factory License', type: 'inquiry' },
  { name: 'Import Export Code (IEC)', link: '/contact?service=IEC Code', type: 'inquiry' },
  { name: 'Digital Signature (DSC)', link: '/contact?service=DSC', type: 'inquiry' },
  { name: 'Accounting Services', link: '/accounting-services', type: 'page' },
];

const HomePage = () => {
  // --- STATE ---
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activeMobileCategory, setActiveMobileCategory] = useState(null);
  const [isServicesHovered, setIsServicesHovered] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [suggestions, setSuggestions] = useState([]); // Search Suggestions
  const [activeAccordion, setActiveAccordion] = useState(null); // For FAQs
  const [capsules, setCapsules] = useState([]);
  const [isItrPopupOpen, setIsItrPopupOpen] = useState(false);

  // --- EFFECTS ---
  useEffect(() => {
    const shown = sessionStorage.getItem('itrPromoShown');
    if (!shown) {
      const timer = setTimeout(() => {
        setIsItrPopupOpen(true);
        sessionStorage.setItem('itrPromoShown', 'true');
      }, 3000);
      return () => clearTimeout(timer);
    }
  }, []);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
      if (isServicesHovered) setIsServicesHovered(false);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, [isServicesHovered]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('focusSearch') === '1') {
      const searchSection = document.getElementById('hero-search');
      const searchInput = document.getElementById('hero-search-input');
      if (searchSection) searchSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
      setTimeout(() => searchInput?.focus(), 450);
    }
  }, []);

  useEffect(() => {
    const fetchCapsules = async () => {
      try {
        const { data } = await axios.get('/api/services/header-config');
        if (data && Array.isArray(data.capsules)) {
          setCapsules(data.capsules);
        }
      } catch (error) {
        console.error('Failed to load dynamic capsules', error);
      }
    };
    fetchCapsules();
  }, []);

  // --- ACTIONS ---

  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: ''
  });

  const handleConsultationBook = () => {
    setSelectedPlan(PACKAGES[0]);
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
      serviceName: 'Expert Consultation',
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

  const toggleAccordion = (index) => {
    setActiveAccordion(activeAccordion === index ? null : index);
  };

  // --- COMPONENTS ---

  // Header removed (using SharedHeader)

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
        title={selectedPlan?.buttonText || 'Book Consultation'}
        initialTermsAccepted={false}
      />

      {/* HERO SECTION - RED/DARK THEME */}
      <section className="relative bg-[#0f172a] pb-32 pt-20 lg:pt-32 overflow-hidden -mt-[0px]">
        {/* Physics Capsules Layer */}
        <PhysicsCapsules capsules={capsules} />

        {/* Background Elements */}
        <div className="absolute inset-0 z-0">
          <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-red-600 rounded-full blur-[120px] translate-x-1/2 -translate-y-1/2 blob-anim opacity-50"></div>
          <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-blue-600 rounded-full blur-[120px] -translate-x-1/2 translate-y-1/2 blob-anim delay-2000 opacity-50"></div>
          <div className="absolute top-1/2 left-1/2 w-[600px] h-[600px] bg-purple-600 rounded-full blur-[120px] -translate-x-1/2 -translate-y-1/2 blob-anim delay-4000 opacity-50"></div>
        </div>

        <div className="relative z-10 max-w-5xl mx-auto px-4 text-center">
          <div className="inline-flex flex-wrap justify-center gap-3 mb-8 animate-fade-in">
            <div className="px-4 py-1.5 rounded-full bg-white/10 backdrop-blur-md border border-white/20 text-white/80 text-[10px] sm:text-xs font-bold uppercase tracking-widest">
              <span className="text-red-500 mr-2">●</span> Trusted by 1000+ Businesses
            </div>
            <div className="px-4 py-1.5 rounded-full bg-white/10 backdrop-blur-md border border-white/20 text-white/80 text-[10px] sm:text-xs font-bold uppercase tracking-widest">
              <span className="text-emerald-500 mr-2">●</span> ISO 9001:2015, ISO 27001:2022 Certified
            </div>
            <div className="px-4 py-1.5 rounded-full bg-white/10 backdrop-blur-md border border-white/20 text-white/80 text-[10px] sm:text-xs font-bold uppercase tracking-widest">
              <span className="text-blue-500 mr-2">●</span> DPDP Compliant
            </div>
          </div>
          <h1 className="text-4xl md:text-6xl lg:text-7xl font-black text-white tracking-tight leading-[1.1] mb-8">
            Build Your Business.<br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-orange-500">Run It Smarter.</span>
          </h1>
          <p className="text-xl text-slate-400 mb-12 max-w-2xl mx-auto leading-relaxed">
            India's only platform combining <span className="text-white font-bold">Legal Compliance</span> with <span className="text-white font-bold">Industrial Setup</span> & <span className="text-white font-bold">Funding</span>.
          </p>


          {/* SEARCH BAR */}
          <div id="hero-search" className="max-w-3xl mx-auto relative z-50">
            <div className="absolute -inset-1 bg-gradient-to-r from-red-600 to-orange-600 rounded-2xl blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>
            <div className="relative bg-white rounded-xl shadow-2xl p-2 flex items-center">
              <div className="pl-4 pr-2 text-slate-400">
                <Search className="w-6 h-6" />
              </div>
              <input
                id="hero-search-input"
                type="text"
                placeholder="Search for 'Private Limited', 'GST', 'Loans'..."
                className="flex-1 p-3 text-lg font-medium text-slate-900 placeholder:text-slate-400 outline-none bg-transparent"
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  if (e.target.value.length > 1) {
                    const filtered = ALL_SERVICES.filter(s => s.name.toLowerCase().includes(e.target.value.toLowerCase()));
                    setSuggestions(filtered);
                  } else {
                    setSuggestions([]);
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    if (suggestions.length > 0) {
                      window.location.href = suggestions[0].link;
                    } else {
                      window.location.href = `/contact?service=${searchTerm}`;
                    }
                  }
                }}
              />
              <button
                onClick={() => {
                  if (suggestions.length > 0) {
                    window.location.href = suggestions[0].link;
                  } else {
                    window.location.href = `/contact?service=${searchTerm}`;
                  }
                }}
                className="hidden sm:block bg-black text-white px-8 py-3 rounded-lg font-bold text-sm hover:bg-slate-800 transition transform hover:-translate-y-0.5"
              >
                Search
              </button>
            </div>

            {/* SEARCH SUGGESTIONS DROPDOWN */}
            {searchTerm.length > 1 && (
              <div className="absolute top-full left-0 right-0 mt-2 bg-white rounded-xl shadow-2xl border border-slate-100 overflow-hidden text-left animate-fade-in max-h-60 overflow-y-auto z-50">
                {suggestions.length > 0 ? (
                  suggestions.map((s, i) => (
                    <a href={s.link} key={i} className="flex items-center justify-between px-6 py-3 hover:bg-slate-50 transition-colors group">
                      <span className="font-bold text-slate-700 group-hover:text-red-600">{s.name}</span>
                      <span className="text-xs text-slate-400 uppercase tracking-wider group-hover:text-red-400">
                        {s.type === 'page' ? 'View Page' : 'Inquire'}
                      </span>
                    </a>
                  ))
                ) : (
                  <a href={`/contact?service=${searchTerm}`} className="flex items-center justify-between px-6 py-4 hover:bg-slate-50 transition-colors group bg-red-50/30">
                    <div>
                      <span className="font-bold text-slate-700 group-hover:text-red-600">Not listed? Request '{searchTerm}'</span>
                      <p className="text-xs text-slate-500 mt-0.5">We will arrange a custom solution for you.</p>
                    </div>
                    <span className="text-xs font-bold text-red-500 uppercase tracking-wider border border-red-200 px-2 py-1 rounded bg-white">
                      Contact Us
                    </span>
                  </a>
                )}
              </div>
            )}
          </div>

          {/* SEARCH FALLBACK LINK */}
          <div className="mt-6 animate-fade-in delay-500">
            <p className="text-slate-400 text-sm">
              Can't find what you're looking for?{' '}
              <button onClick={handleConsultationBook} className="text-white hover:text-red-400 font-bold underline underline-offset-4 decoration-red-500 hover:decoration-red-400 transition-colors">
                Talk to an Expert
              </button>
            </p>
          </div>
        </div>
      </section>

      {/* STATS STRIP */}
      <div className="bg-black border-y border-slate-800 relative z-20">
        <div className="max-w-7xl mx-auto px-4 grid grid-cols-2 md:grid-cols-4 divide-x divide-slate-800 text-center">
          <div className="py-6">
            <div className="text-red-500 text-3xl font-black">1000+</div>
            <div className="text-slate-500 text-xs font-bold uppercase tracking-wider mt-1">Clients Served</div>
          </div>
          <div className="py-6">
            <div className="text-red-500 text-3xl font-black">₹10Cr+</div>
            <div className="text-slate-500 text-xs font-bold uppercase tracking-wider mt-1">Loans Facilitated</div>
          </div>
          <div className="py-6">
            <div className="text-red-500 text-3xl font-black">30+</div>
            <div className="text-slate-500 text-xs font-bold uppercase tracking-wider mt-1">Experts Team</div>
          </div>
          <div className="py-6">
            <div className="text-red-500 text-3xl font-black">4.9/5</div>
            <div className="text-slate-500 text-xs font-bold uppercase tracking-wider mt-1">Google Rating</div>
          </div>
        </div>
      </div>

      {/* TRUSTED PARTNER LOGOS */}
      <section className="py-8 bg-slate-50 border-b border-slate-100 overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 flex items-center justify-center space-x-12 opacity-50 grayscale hover:grayscale-0 transition-all duration-500">
          {/* Placeholder text for partners as icons might not be available */}
          <span className="font-bold text-xl text-slate-400">Google Cloud</span>
          <span className="font-bold text-xl text-slate-400">AWS Partner</span>
          <span className="font-bold text-xl text-slate-400">Zoho Books</span>
          <span className="font-bold text-xl text-slate-400">Razorpay</span>
          <span className="font-bold text-xl text-slate-400">Digital India</span>
        </div>
      </section>

      {/* 🚀 INCOME TAX FILING HOME STRIP BANNER */}
      <section className="py-12 bg-white relative overflow-hidden border-b border-slate-100 animate-fade-in">
        <div className="max-w-7xl mx-auto px-4">
          <div className="relative bg-gradient-to-r from-slate-900 via-slate-950 to-slate-900 text-white rounded-3xl p-8 md:p-12 shadow-2xl border border-slate-800 overflow-hidden flex flex-col lg:flex-row items-center justify-between gap-8 group">
            {/* Ambient gradients */}
            <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-red-600/10 rounded-full blur-[100px] pointer-events-none translate-x-1/4 -translate-y-1/4"></div>
            <div className="absolute bottom-0 left-0 w-[400px] h-[400px] bg-blue-600/10 rounded-full blur-[80px] pointer-events-none -translate-x-1/4 translate-y-1/4"></div>

            {/* Left Content */}
            <div className="relative z-10 max-w-2xl text-center lg:text-left">
              <div className="inline-flex items-center gap-2 rounded-full border border-red-500/30 bg-red-500/10 px-3.5 py-1 text-[10px] font-black uppercase tracking-wider text-red-400 mb-5 animate-pulse">
                <span>●</span> AY 2026-27 (FY 2025-26) Filing is Live
              </div>
              <h3 className="text-2xl md:text-4xl font-black tracking-tight leading-tight mb-4">
                Hassle-Free Income Tax filing <br className="hidden md:inline"/> by Chartered Accountants.
              </h3>
              <p className="text-sm md:text-base text-slate-400 leading-relaxed mb-6 font-medium max-w-xl mx-auto lg:mx-0">
                Ensure zero discrepancies and maximum refunds. Direct matching of Form 16, AIS, and TIS to secure zero-rejection peace of mind.
              </p>
              
              {/* Feature Tags */}
              <div className="flex flex-wrap items-center justify-center lg:justify-start gap-4">
                <span className="flex items-center gap-1.5 text-xs text-slate-300 font-semibold"><CheckCircle className="w-4 h-4 text-emerald-500" /> Max Deductions Claimed</span>
                <span className="flex items-center gap-1.5 text-xs text-slate-300 font-semibold"><CheckCircle className="w-4 h-4 text-emerald-500" /> Expert CA Verification</span>
                <span className="flex items-center gap-1.5 text-xs text-slate-300 font-semibold"><CheckCircle className="w-4 h-4 text-emerald-500" /> Starts from just ₹999</span>
              </div>
            </div>

            {/* Right Action */}
            <div className="relative z-10 shrink-0 text-center lg:text-right flex flex-col items-center lg:items-end gap-3 w-full lg:w-auto">
              <div className="bg-white/5 backdrop-blur border border-white/10 rounded-2xl px-5 py-3 text-center w-full max-w-xs lg:w-auto">
                <div className="text-[10px] text-slate-400 font-black uppercase tracking-widest">Early Bird Special</div>
                <div className="text-3xl font-black text-orange-400 mt-1">Starts from ₹999!</div>
                <div className="text-[10px] text-slate-500 mt-0.5">Adjustable booking fee applies</div>
              </div>
              <a 
                href="/income-tax-return" 
                className="w-full max-w-xs lg:w-auto text-center bg-red-600 hover:bg-red-700 text-white font-bold px-8 py-4 rounded-xl transition transform active:scale-95 flex items-center justify-center gap-2 shadow-xl shadow-red-600/30 whitespace-nowrap"
              >
                <span>File Your ITR Now</span>
                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* 🎁 ITR EARLY BIRD PROMO POPUP MODAL */}
      {isItrPopupOpen && (
        <div className="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-slate-900 border border-slate-700/60 rounded-3xl p-8 max-w-lg w-full relative shadow-2xl text-white overflow-hidden transform transition-all duration-300">
            {/* Visual background accents */}
            <div className="absolute -top-12 -right-12 w-32 h-32 bg-red-600/30 rounded-full blur-2xl"></div>
            <div className="absolute -bottom-12 -left-12 w-32 h-32 bg-orange-500/20 rounded-full blur-2xl"></div>

            {/* Close button */}
            <button 
              onClick={() => setIsItrPopupOpen(false)}
              className="absolute top-4 right-4 p-2 rounded-full bg-slate-800 text-slate-400 hover:text-white transition"
            >
              <X className="w-5 h-5" />
            </button>

            {/* Content */}
            <div className="text-center relative z-10">
              <div className="inline-flex items-center gap-1.5 px-3 py-1 bg-red-600/20 text-red-400 border border-red-500/30 rounded-full text-[10px] font-black uppercase tracking-wider mb-4">
                <Clock className="w-3.5 h-3.5" /> Early Bird filing LIVE
              </div>

              <h3 className="text-2xl sm:text-3xl font-black mb-3">
                Early Bird Offer: Flat 10% Off on ITR Filings!
              </h3>
              
              <p className="text-slate-300 text-sm leading-relaxed mb-6">
                Avoid last-minute rush and notice discrepancies. File your Income Tax Return accurately with certified CAs for maximum savings.
              </p>

              <div className="bg-slate-800/80 border border-slate-700/50 rounded-2xl p-4 mb-6">
                <div className="text-[10px] text-slate-400 uppercase font-black tracking-widest">Apply Code at Checkout</div>
                <div className="text-2xl font-black text-orange-400 tracking-wider mt-1 select-all">ITR10</div>
                <div className="text-xs text-slate-400 mt-1 font-semibold">Valid for first 250 users • AY 2026-27 (FY 2025-26)</div>
              </div>

              <div className="flex flex-col sm:flex-row gap-3">
                <button 
                  onClick={() => setIsItrPopupOpen(false)}
                  className="flex-1 bg-slate-800 hover:bg-slate-700 font-bold py-3.5 rounded-xl transition text-sm"
                >
                  Maybe Later
                </button>
                <a 
                  href="/income-tax-return"
                  className="flex-1 bg-red-600 hover:bg-red-700 text-white font-bold py-3.5 rounded-xl transition text-sm flex items-center justify-center gap-1.5 shadow-lg shadow-red-600/30"
                >
                  <span>Start Filing Now</span>
                  <ArrowRight className="w-4 h-4" />
                </a>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 1. SERVICE CATEGORIES BENTO GRID */}
      <section id="services" className="py-24 bg-gradient-to-b from-white via-slate-50 to-slate-100/60 relative overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 relative z-10">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <span className="text-xs font-black uppercase tracking-widest text-red-600 bg-red-50 border border-red-200/80 px-3.5 py-1.5 rounded-full">
              Full Spectrum Capabilities
            </span>
            <h2 className="text-3xl sm:text-5xl font-black text-slate-900 mt-4 tracking-tight">
              Everything Your Business Needs
            </h2>
            <p className="text-base text-slate-600 mt-3 font-medium leading-relaxed">
              From day-one incorporation and statutory licenses to factory machinery setup and bank project loans.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {SERVICES_GRID_DATA.map((service) => {
              const Icon = service.icon;
              return (
                <a
                  href={service.link || '#'}
                  key={service.id}
                  className="bg-white rounded-3xl p-7 border border-slate-200/90 hover:border-red-400 shadow-xs hover:shadow-xl hover:shadow-red-600/10 transition-all duration-300 group flex flex-col justify-between relative overflow-hidden transform hover:-translate-y-1.5"
                >
                  <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-bl from-red-500/5 via-orange-500/5 to-transparent rounded-bl-full pointer-events-none group-hover:scale-125 transition-transform duration-500"></div>

                  <div>
                    <div className="flex items-center justify-between mb-5">
                      <div className={`w-12 h-12 ${service.color} rounded-2xl flex items-center justify-center border shadow-xs group-hover:scale-110 transition-transform duration-300`}>
                        <Icon className="w-6 h-6" />
                      </div>
                      <span className="text-[10px] font-black uppercase tracking-wider text-slate-500 bg-slate-100 px-2.5 py-1 rounded-full group-hover:bg-red-50 group-hover:text-red-600 transition-colors">
                        {service.badge}
                      </span>
                    </div>

                    <h3 className="text-lg font-black text-slate-900 mb-2 group-hover:text-red-600 transition-colors leading-snug">
                      {service.title}
                    </h3>
                    <p className="text-xs text-slate-600 font-medium leading-relaxed mb-5">
                      {service.description}
                    </p>
                  </div>

                  <div>
                    <div className="flex flex-wrap gap-1.5 mb-5">
                      {service.tags.map((tag, tIdx) => (
                        <span key={tIdx} className="text-[10px] font-semibold text-slate-600 bg-slate-50 border border-slate-200/80 px-2 py-0.5 rounded-md">
                          {tag}
                        </span>
                      ))}
                    </div>

                    <div className="pt-4 border-t border-slate-100 flex items-center justify-between text-xs font-black text-slate-900 group-hover:text-red-600 transition-colors">
                      <span>Explore Services</span>
                      <div className="w-7 h-7 rounded-full bg-slate-100 group-hover:bg-red-600 group-hover:text-white flex items-center justify-center transition-all duration-300">
                        <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                      </div>
                    </div>
                  </div>
                </a>
              );
            })}
          </div>
        </div>
      </section>

      {/* 2. HOW IT WORKS WORKFLOW */}
      <section className="py-24 bg-slate-900 text-white relative overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(#ffffff_1px,transparent_1px)] opacity-10 [background-size:24px_24px]"></div>
        <div className="max-w-7xl mx-auto px-4 relative z-10">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <span className="text-xs font-black uppercase tracking-widest text-red-400 bg-white/5 border border-white/10 px-3.5 py-1.5 rounded-full">
              Frictionless 3-Step Execution
            </span>
            <h2 className="text-3xl sm:text-5xl font-black mt-4 tracking-tight">
              How It Works
            </h2>
            <p className="text-base text-slate-400 mt-2 font-medium">
              Get your company incorporated, compliant, or financed in 3 effortless steps.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 relative">
            {/* Connecting line on desktop */}
            <div className="hidden md:block absolute top-[52px] left-[15%] right-[15%] h-[2px] bg-gradient-to-r from-red-600 via-orange-500 to-emerald-500 z-0"></div>

            {[
              {
                step: "01",
                badge: "Discovery & CA Call",
                title: "Book Quick Consultation",
                desc: "Pay ₹499 to speak with our licensed CA/CS specialist. We analyze your requirements, check naming feasibility, and structure your package.",
                time: "⚡ 30 Mins Advisory Call",
                credit: "100% Fee Credited on Order",
                color: "from-red-600 to-rose-600"
              },
              {
                step: "02",
                badge: "100% Digital Vault",
                title: "Upload Documents",
                desc: "Securely upload basic KYC proofs and information to your private client portal. No paperwork, zero physical queues, and real-time validation.",
                time: "⚡ Instant Checklist",
                credit: "256-Bit SSL Encrypted Vault",
                color: "from-orange-500 to-amber-500"
              },
              {
                step: "03",
                badge: "Official Certification",
                title: "Government Delivery",
                desc: "Our senior compliance partners file statutory documents with MCA/Govt authorities. Receive official certificates and lifelong advisory support.",
                time: "⚡ Fast-Track 5-7 Days",
                credit: "Digital Delivery & Support",
                color: "from-emerald-500 to-teal-600"
              }
            ].map((item, i) => (
              <div
                key={i}
                className="bg-slate-800/80 backdrop-blur-xl border border-slate-700/80 rounded-3xl p-8 hover:border-slate-500 transition-all duration-300 flex flex-col justify-between relative z-10 group hover:-translate-y-2 hover:shadow-2xl hover:shadow-red-600/10"
              >
                <div>
                  <div className="flex items-center justify-between mb-6">
                    <div className={`w-14 h-14 rounded-2xl bg-gradient-to-br ${item.color} text-white font-black text-xl flex items-center justify-center shadow-lg shadow-black/40 border-2 border-white/20 group-hover:scale-110 transition-transform`}>
                      {item.step}
                    </div>
                    <span className="text-[10px] font-black uppercase tracking-wider text-slate-300 bg-white/5 border border-white/10 px-3 py-1 rounded-full">
                      {item.badge}
                    </span>
                  </div>

                  <h3 className="text-xl font-bold text-white mb-3 tracking-tight group-hover:text-red-400 transition-colors">
                    {item.title}
                  </h3>
                  <p className="text-slate-300 text-xs font-medium leading-relaxed mb-6">
                    {item.desc}
                  </p>
                </div>

                <div className="pt-4 border-t border-slate-700/60 space-y-2">
                  <div className="flex items-center text-[11px] font-bold text-slate-200">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mr-2 shrink-0" />
                    <span>{item.time}</span>
                  </div>
                  <div className="flex items-center text-[11px] font-bold text-slate-300">
                    <CheckCircle2 className="w-3.5 h-3.5 text-red-400 mr-2 shrink-0" />
                    <span>{item.credit}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* WHY CHOOSE US */}
      <section className="py-24 bg-slate-900 relative overflow-hidden text-white border-t border-slate-800">
        <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-10"></div>
        <div className="max-w-7xl mx-auto px-4 flex flex-col md:flex-row items-center gap-16 relative z-10">
          <div className="md:w-1/2">
            <div className="inline-block px-3 py-1 bg-red-600 rounded text-xs font-bold mb-4 uppercase tracking-wider">Why VR HERE?</div>
            <h2 className="text-4xl font-black mb-6">We bridge the gap between <span className="text-red-500">Office</span> and <span className="text-blue-500">Factory</span>.</h2>
            <p className="text-lg text-slate-400 mb-8 max-w-lg leading-relaxed">
              Most consultants only handle paper. We handle paper AND metal. From incorporating your company to sourcing your first machine, VR HERE is your end-to-end partner.
            </p>
            <div className="space-y-4">
              {[
                "Single Point of Contact for 100+ Services",
                "Transparent Pricing - No Hidden Costs",
                "Real-time Status Tracking Dashboard",
                "Expert Team of CAs, CSs, and Engineers"
              ].map((item, i) => (
                <div key={i} className="flex items-center">
                  <CheckCircle2 className="w-5 h-5 text-green-500 mr-3" />
                  <span className="font-medium text-slate-200">{item}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="md:w-1/2 relative">
            <div className="bg-slate-800 p-8 rounded-3xl border border-slate-700 shadow-2xl">
              <div className="flex items-start mb-6">
                <Quote className="w-10 h-10 text-red-600 opacity-50" />
              </div>
              <p className="text-xl font-medium italic mb-6 text-slate-300">"We were struggling with factory licenses for months. VR HERE stepped in and got everything cleared in 2 weeks. Their industrial knowledge is unmatched."</p>
              <div className="flex items-center">
                <div className="w-12 h-12 bg-gray-500 rounded-full mr-4 overflow-hidden">
                  <img src="https://ui-avatars.com/api/?name=Suresh+R&background=random" alt="Client" />
                </div>
                <div>
                  <div className="font-bold text-white">Suresh Reddy</div>
                  <div className="text-sm text-slate-400">Director, InfraTech Pvt Ltd</div>
                </div>
              </div>
            </div>
            {/* Decorative dots */}
            <div className="absolute -bottom-6 -right-6 w-24 h-24 bg-red-600/20 rounded-full blur-xl"></div>
          </div>
        </div>
      </section>

      {/* SUCCESS STORIES (TESTIMONIALS) */}
      <section className="py-24 bg-slate-50 overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 mb-12 flex flex-col items-center">
          <h2 className="text-3xl font-black text-center text-slate-900 mb-2">Success Stories</h2>
          <p className="text-slate-500 text-center max-w-2xl">Trusted by emerging businesses and ambitious founders across industries.</p>
        </div>
        
        {/* Marquee Wrapper */}
        <div className="relative flex overflow-x-hidden group">
          <div className="flex animate-[tickerScroll_40s_linear_infinite] group-hover:[animation-play-state:paused] whitespace-nowrap will-change-transform">
            {/* Duplicate list for seamless infinite scroll */}
            {[...TESTIMONIALS, ...TESTIMONIALS].map((t, i) => (
              <div key={i} className="inline-block w-[320px] whitespace-normal bg-white p-6 mx-4 rounded-2xl shadow-sm border border-slate-100 hover:shadow-lg transition-all flex-shrink-0">
                <div className="flex text-yellow-400 mb-4">
                  {[...Array(5)].map((_, idx) => <Star key={idx} className="w-4 h-4 fill-current" />)}
                </div>
                <div>
                  <div className="font-bold text-lg text-slate-900">{t.business}</div>
                  <div className="text-sm font-semibold text-slate-700 mt-1">{t.name}</div>
                  <div className="text-xs text-slate-500 mt-0.5">{t.role}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 3. FREQUENTLY ASKED QUESTIONS (2-COLUMN SPLIT WITH IMAGE) */}
      <section className="py-24 bg-white border-t border-slate-100 relative overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 relative z-10">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <span className="text-xs font-black uppercase tracking-widest text-red-600 bg-red-50 border border-red-200/80 px-3.5 py-1.5 rounded-full">
              Clear & Transparent
            </span>
            <h2 className="text-3xl sm:text-5xl font-black text-slate-900 mt-4 tracking-tight">
              Frequently Asked Questions
            </h2>
            <p className="text-base text-slate-600 mt-2 font-medium">
              Everything you need to know about registration, compliance, and our process.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-start">
            {/* Left Column: Visual Showcase & Direct Contact */}
            <div className="lg:col-span-5 space-y-6">
              <div className="bg-slate-900 rounded-3xl p-6 text-white relative overflow-hidden shadow-2xl border border-slate-800 group">
                <div className="relative rounded-2xl overflow-hidden mb-6 aspect-square max-h-[320px] w-full">
                  <img
                    src="/faq-advisor.jpg"
                    alt="VR HERE CA Advisory Specialist"
                    className="w-full h-full object-cover object-top group-hover:scale-105 transition-transform duration-500"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-slate-950 via-transparent to-transparent opacity-80"></div>
                  
                  {/* Floating Trust Pills */}
                  <div className="absolute bottom-3 left-3 right-3 flex items-center justify-between gap-2">
                    <div className="bg-slate-900/90 backdrop-blur-md border border-white/10 px-3 py-1.5 rounded-xl text-[10px] font-black text-emerald-400 flex items-center gap-1.5 shadow-lg">
                      <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
                      <span>Avg. Reply &lt; 15 Mins</span>
                    </div>
                    <div className="bg-slate-900/90 backdrop-blur-md border border-white/10 px-3 py-1.5 rounded-xl text-[10px] font-black text-amber-300 flex items-center gap-1 shadow-lg">
                      <Star className="w-3 h-3 fill-amber-400 text-amber-400" />
                      <span>4.9 / 5 Rating</span>
                    </div>
                  </div>
                </div>

                <h3 className="text-xl font-black text-white mb-2 tracking-tight">
                  Still Have Questions?
                </h3>
                <p className="text-xs text-slate-300 font-medium leading-relaxed mb-6">
                  Speak directly with our practicing Chartered Accountants and Company Secretaries. We provide clear roadmap clarity for your business.
                </p>

                <div className="space-y-3">
                  <button
                    onClick={handleConsultationBook}
                    className="w-full bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 text-white font-black text-xs uppercase tracking-wider py-4 px-6 rounded-2xl transition-all shadow-lg shadow-red-600/30 flex items-center justify-center gap-2"
                  >
                    <Phone className="w-4 h-4" />
                    <span>Book 1-on-1 Consultation @ ₹499</span>
                  </button>

                  <a
                    href="https://wa.me/918008530606?text=Hi%20VR%20HERE%20Team,%20I%20have%20a%20question%20regarding%20business%20registration%20and%20compliance."
                    target="_blank"
                    rel="noreferrer"
                    className="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs uppercase tracking-wider py-3.5 px-6 rounded-2xl transition-all flex items-center justify-center gap-2 border border-slate-700"
                  >
                    <MessageSquare className="w-4 h-4 text-emerald-400" />
                    <span>WhatsApp Advisory Hotline</span>
                  </a>
                </div>
              </div>
            </div>

            {/* Right Column: Interactive FAQ Accordion */}
            <div className="lg:col-span-7 space-y-4">
              {FAQS.map((faq, i) => (
                <div
                  key={i}
                  className={`rounded-2xl border transition-all duration-300 overflow-hidden ${
                    activeAccordion === i
                      ? 'border-red-500 bg-red-50/20 shadow-lg ring-1 ring-red-500/20'
                      : 'border-slate-200/90 hover:border-slate-300 bg-white shadow-2xs'
                  }`}
                >
                  <button
                    onClick={() => toggleAccordion(i)}
                    className="w-full flex items-start justify-between p-6 text-left gap-4"
                  >
                    <div className="flex-1">
                      {faq.category && (
                        <span className="text-[10px] font-black uppercase tracking-wider text-red-600 bg-red-50 border border-red-200 px-2 py-0.5 rounded-md mb-2 inline-block">
                          {faq.category}
                        </span>
                      )}
                      <h4 className={`font-bold text-base sm:text-lg leading-snug ${activeAccordion === i ? 'text-red-700 font-black' : 'text-slate-900'}`}>
                        {faq.question}
                      </h4>
                    </div>
                    <div className={`p-2 rounded-xl shrink-0 transition-colors ${activeAccordion === i ? 'bg-red-600 text-white shadow-sm' : 'bg-slate-100 text-slate-500'}`}>
                      {activeAccordion === i ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </div>
                  </button>

                  <div
                    className={`px-6 text-slate-600 text-sm leading-relaxed overflow-hidden transition-all duration-300 ease-in-out ${
                      activeAccordion === i ? 'max-h-60 pb-6 opacity-100' : 'max-h-0 opacity-0'
                    }`}
                  >
                    <p className="pt-2 border-t border-slate-100/80 font-medium">
                      {faq.answer}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* CTA SECTION - READY TO START */}
      <section className="relative py-24 md:py-32 bg-slate-900 text-white overflow-hidden">
        {/* Background Gradients */}
        <div className="absolute inset-0">
          <div className="absolute top-0 right-0 w-[800px] h-[800px] bg-red-600/20 rounded-full blur-[120px] translate-x-1/3 -translate-y-1/2"></div>
          <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-blue-600/20 rounded-full blur-[100px] -translate-x-1/3 translate-y-1/3"></div>
          <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20"></div>
        </div>

        <div className="max-w-7xl mx-auto px-4 relative z-10">
          <div className="flex flex-col lg:flex-row items-center gap-12 lg:gap-20">

            {/* Left Content */}
            <div className="lg:w-1/2 text-center lg:text-left">
              <div className="inline-block px-4 py-2 bg-red-500/10 border border-red-500/20 rounded-full text-red-400 text-sm font-bold uppercase tracking-widest mb-6">
                Limitless Growth
              </div>
              <h2 className="text-4xl md:text-5xl lg:text-6xl font-black mb-6 leading-tight">
                Ready to <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-orange-500">Scale Up?</span>
              </h2>
              <p className="text-xl text-slate-400 mb-8 leading-relaxed max-w-xl mx-auto lg:mx-0">
                Don't let compliance slow you down. Talk to our experts today, get a roadmap, and pay only when you're 100% satisfied.
              </p>

              <div className="flex flex-col sm:flex-row items-center gap-4 justify-center lg:justify-start">
                <div className="flex items-center gap-2 text-slate-300 bg-white/5 py-2 px-4 rounded-lg border border-white/10">
                  <CheckCircle className="w-5 h-5 text-green-500" />
                  <span className="font-medium">Free 1st Call Adjustment</span>
                </div>
                <div className="flex items-center gap-2 text-slate-300 bg-white/5 py-2 px-4 rounded-lg border border-white/10">
                  <ShieldCheck className="w-5 h-5 text-blue-500" />
                  <span className="font-medium">Secure Process</span>
                </div>
              </div>
            </div>

            {/* Right Pricing Card */}
            <div className="lg:w-1/2 w-full max-w-md mx-auto lg:mr-0">
              <div className="bg-white/10 backdrop-blur-xl p-8 rounded-3xl border border-white/20 shadow-2xl relative overflow-hidden group hover:border-red-500/50 transition-colors duration-500">
                <div className="absolute top-0 right-0 bg-red-600 text-white text-xs font-bold px-4 py-2 rounded-bl-xl shadow-lg">
                  POPULAR
                </div>

                <div className="text-sm font-bold text-red-400 uppercase tracking-widest mb-2">Consultation Offer</div>
                <div className="flex items-baseline mb-2">
                  <span className="text-6xl font-black text-white">₹499</span>
                  <span className="ml-2 text-slate-400 font-medium line-through">₹999</span>
                </div>
                <p className="text-slate-300 text-sm mb-8 border-b border-white/10 pb-6">
                  Fully adjustable against any registration service fees. Use it as credit.
                </p>

                <ul className="space-y-4 mb-8">
                  <li className="flex items-start">
                    <CheckCircle2 className="w-5 h-5 text-green-400 mr-3 mt-0.5" />
                    <span className="text-slate-200 text-sm">30 Mins Expert Call (CA/CS)</span>
                  </li>
                  <li className="flex items-start">
                    <CheckCircle2 className="w-5 h-5 text-green-400 mr-3 mt-0.5" />
                    <span className="text-slate-200 text-sm">Business Structure Analysis</span>
                  </li>
                  <li className="flex items-start">
                    <CheckCircle2 className="w-5 h-5 text-green-400 mr-3 mt-0.5" />
                    <span className="text-slate-200 text-sm">Actionable Roadmap PDF</span>
                  </li>
                </ul>

                <button
                  onClick={handleConsultationBook}
                  className="w-full bg-gradient-to-r from-red-600 to-red-500 text-white font-bold py-4 rounded-xl hover:from-red-500 hover:to-red-400 transition-all transform active:scale-95 shadow-lg shadow-red-600/30 flex items-center justify-center group-hover:shadow-red-600/50"
                >
                  Book Consultation Now <ArrowRight className="ml-2 w-5 h-5 group-hover:translate-x-1 transition-transform" />
                </button>

                <p className="text-center text-xs text-slate-500 mt-4">No hidden charges. 100% Secure.</p>
              </div>
            </div>

          </div>
        </div>
      </section>

      <ProfessionalsModule sectionId="managed-by-professionals" />

      <SharedFooter />

    </div >
  );
};

export default HomePage;
