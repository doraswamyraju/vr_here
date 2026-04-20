// Force verify build update
import React, { useState, useEffect } from 'react';
import {
  Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
  Phone, Menu, X, ChevronDown, Clock, Award, Search, ArrowRight, CheckCircle2,
  Building2, Mail, MapPin, CheckCircle, Smartphone, ShieldCheck, RefreshCw,
  CreditCard, Loader2, MessageSquare, Users as UsersIcon, Star, Quote, HelpCircle, ChevronUp
} from 'lucide-react';
import { SharedHeader, SharedFooter } from './components/SharedComponents';
import ConsultationPaymentModal from './components/ConsultationPaymentModal';
import ProfessionalsModule from './components/OurTeamModule';
import { launchRazorpayCheckout } from './utils/razorpayCheckout';
import { showPaymentSuccessPopup } from './utils/paymentSuccessPopup';

// MENU_DATA removed (moved to SharedComponents)

/* --- DATA FOR HOMEPAGE SERVICE GRID --- */
const SERVICES_GRID_DATA = [
  {
    id: 'accounting-compliance-taxation',
    title: 'Accounting, Compliance & Taxation',
    icon: Calculator,
    color: 'bg-red-50 text-red-600',
    description: 'AaaS, GST, ITR, TDS/TCS, Audit services',
    link: '/all-services?category=accounting-compliance-taxation'
  },
  {
    id: 'certification-quality-management',
    title: 'Certification & Quality Management',
    icon: Stamp,
    color: 'bg-blue-50 text-blue-600',
    description: 'ISO, GMP/HACCP, CE, BIS, Halal and more',
    link: '/all-services?category=certification-quality-management'
  },
  {
    id: 'business-registration-licensing-corporate',
    title: 'Business Registrations & Corporate',
    icon: Briefcase,
    color: 'bg-red-50 text-red-600',
    description: 'Company setup, licenses, ROC and secretarial',
    link: '/all-services?category=business-registration-licensing-corporate'
  },
  {
    id: 'government-portal-registrations',
    title: 'Government Portal Registrations',
    icon: Globe,
    color: 'bg-slate-100 text-slate-700',
    description: 'GeM, TReDS, RERA, AP/TS single-window',
    link: '/all-services?category=government-portal-registrations'
  },
  {
    id: 'industrial-msme-consultancy',
    title: 'Industrial & MSME Consultancy',
    icon: IndianRupee,
    color: 'bg-slate-100 text-slate-700',
    description: 'DPR, CMA, loans, subsidy and scheme guidance',
    link: '/all-services?category=industrial-msme-consultancy'
  },
  {
    id: 'branding-documentation-startup-support',
    title: 'Branding & Startup Support',
    icon: Lightbulb,
    color: 'bg-slate-100 text-slate-700',
    description: 'Business plans, branding, SOPs, documentation',
    link: '/all-services?category=branding-documentation-startup-support'
  },
  {
    id: 'machinery-industrial-support',
    title: 'Machinery & Industrial Support',
    icon: Factory,
    color: 'bg-slate-100 text-slate-700',
    description: 'Sourcing, verification, turnkey setup, feasibility',
    link: '/all-services?category=machinery-industrial-support'
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
    question: "Do I need to visit your office?",
    answer: "Not at all. VR HERE is a 100% digital platform. We collect documents online, file applications on your behalf, and deliver certificates via email/courier. You can focus on your business while we handle the paperwork."
  },
  {
    question: "How long does company registration take?",
    answer: "Typically, a Private Limited Company is registered in 7-10 working days, subject to ROC processing time. We ensure all documents are perfect to avoid rejections and delays."
  },
  {
    question: "Can you help with Industrial Loans?",
    answer: "Yes, we specialize in MSME and Industrial loans. We prepare detailed Project Reports (DPR) and guide you through schemes like CGTMSE and PMEGP for collateral-free loans."
  },
  {
    question: "What is the 'Consultation Fee Adjustment'?",
    answer: "If you book a consultation for ₹499, this amount is credited to your wallet. When you purchase any major service (like Company Registration) within 30 days, we deduct ₹499 from the final bill."
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

  // --- EFFECTS ---
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
        {/* Background Elements */}
        <div className="absolute inset-0 z-0">
          <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-red-600 rounded-full blur-[120px] translate-x-1/2 -translate-y-1/2 blob-anim opacity-50"></div>
          <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-blue-600 rounded-full blur-[120px] -translate-x-1/2 translate-y-1/2 blob-anim delay-2000 opacity-50"></div>
          <div className="absolute top-1/2 left-1/2 w-[600px] h-[600px] bg-purple-600 rounded-full blur-[120px] -translate-x-1/2 -translate-y-1/2 blob-anim delay-4000 opacity-50"></div>
        </div>

        <div className="relative z-10 max-w-5xl mx-auto px-4 text-center">
          <div className="inline-block px-4 py-1.5 rounded-full bg-white/10 backdrop-blur-md border border-white/20 text-white/80 text-xs font-bold mb-8 uppercase tracking-widest animate-fade-in">
            <span className="text-red-500 mr-2">●</span> Trusted by 1000+ Businesses
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

      {/* SERVICE CATEGORIES GRID */}
      <section id="services" className="py-24 bg-gradient-to-b from-white to-slate-50">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-black text-slate-900">Everything Your Business Needs</h2>
            <p className="text-slate-500 mt-4">Built on our latest category structure. Click a category to explore all included services.</p>
          </div>

          <div className="grid md:grid-cols-2 xl:grid-cols-4 gap-6">
            {SERVICES_GRID_DATA.map((service) => (
              <a href={service.link || '#'} key={service.id} className="bg-white/90 backdrop-blur-sm p-6 rounded-2xl border border-slate-200 hover:border-red-200 shadow-sm hover:shadow-xl hover:shadow-red-600/10 transition-all duration-300 group relative overflow-hidden">
                <div className={`absolute -top-10 -right-10 w-28 h-28 rounded-full ${service.color.replace('text-', 'bg-').replace('600', '100')} opacity-50 blur-2xl`} />
                <div className={`w-12 h-12 ${service.color} rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform`}>
                  <service.icon className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-slate-900 mb-2 group-hover:text-red-600 transition-colors leading-tight">{service.title}</h3>
                <p className="text-slate-500 text-sm mb-5 leading-relaxed min-h-[44px]">{service.description}</p>
                <div className="flex items-center text-sm font-bold text-slate-900 group-hover:text-red-600 transition-colors">
                  Explore <ArrowRight className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" />
                </div>
              </a>
            ))}
          </div>
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section className="py-20 bg-slate-50">
        <div className="max-w-6xl mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-black text-slate-900 mb-4">How It Works</h2>
            <p className="text-lg text-slate-600">Get your business sorted in 3 simple steps.</p>
          </div>
          <div className="grid md:grid-cols-3 gap-8 relative">
            <div className="hidden md:block absolute top-12 left-0 w-full h-0.5 bg-slate-200 -z-10"></div>
            {[
              { title: "Book Consultation", desc: "Pay ₹499 to speak with our expert. We analyze your needs and explain the process." },
              { title: "Submit Documents", desc: "Upload basic documents securely on our 100% digital dashboard." },
              { title: "Service Delivered", desc: "We file everything. You receive your Certificates or Approvals via email." }
            ].map((step, i) => (
              <div key={i} className="bg-white p-8 rounded-2xl shadow-lg border border-slate-100 text-center hover:-translate-y-2 transition-transform duration-300">
                <div className="w-16 h-16 bg-red-600 text-white rounded-full flex items-center justify-center text-2xl font-black mx-auto mb-6 shadow-md border-4 border-white">{i + 1}</div>
                <h3 className="font-bold text-xl text-slate-900 mb-3">{step.title}</h3>
                <p className="text-slate-600 text-sm leading-relaxed">{step.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* WHY CHOOSE US */}
      <section className="py-24 bg-slate-900 relative overflow-hidden text-white">
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

      {/* FAQ SECTION */}
      <section className="py-24 bg-white border-t border-slate-100 relative overflow-hidden">
        {/* Decorative Grid */}
        <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 pointer-events-none"></div>

        <div className="max-w-4xl mx-auto px-4 relative z-10">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-black text-slate-900 mb-4">Frequently Asked Questions</h2>
            <p className="text-slate-500">Everything you need to know about the process.</p>
          </div>

          <div className="space-y-4">
            {FAQS.map((faq, i) => (
              <div
                key={i}
                className={`border rounded-2xl overflow-hidden transition-all duration-300 ${activeAccordion === i ? 'border-red-200 shadow-lg bg-red-50/30' : 'border-slate-200 hover:border-red-100 hover:shadow-md bg-white'}`}
              >
                <button
                  onClick={() => toggleAccordion(i)}
                  className="w-full flex justify-between items-center p-6 text-left"
                >
                  <span className={`font-bold text-lg ${activeAccordion === i ? 'text-red-700' : 'text-slate-800'}`}>{faq.question}</span>
                  {activeAccordion === i ?
                    <div className="bg-red-100 p-1 rounded-full"><ChevronUp className="w-5 h-5 text-red-600" /></div> :
                    <div className="bg-slate-100 p-1 rounded-full group-hover:bg-slate-200"><ChevronDown className="w-5 h-5 text-slate-500" /></div>
                  }
                </button>
                <div
                  className={`px-6 text-slate-600 text-[15px] leading-relaxed overflow-hidden transition-all duration-300 ease-in-out ${activeAccordion === i ? 'max-h-48 pb-6 opacity-100' : 'max-h-0 opacity-0'}`}
                >
                  {faq.answer}
                </div>
              </div>
            ))}
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
