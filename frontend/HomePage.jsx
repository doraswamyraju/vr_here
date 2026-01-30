// Force verify build update
import React, { useState, useEffect } from 'react';
import {
  Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
  Phone, Menu, X, ChevronDown, Clock, Award, Search, ArrowRight, CheckCircle2,
  Building2, Mail, MapPin, CheckCircle, Smartphone, ShieldCheck, RefreshCw,
  CreditCard, Loader2, MessageSquare, Users, Star, Quote, HelpCircle, ChevronUp
} from 'lucide-react';

/* --- DATA FOR HEADER MENU (From PrivateLimitedPage) --- */
const MENU_DATA = [
  {
    id: 'machinery',
    title: 'Machinery & Industrial',
    icon: Factory,
    items: ['Machinery Sourcing', 'Vendor Verification', 'Turnkey Factory Setup', 'Technology Upgradation']
  },
  {
    id: 'iso',
    title: 'Certification & ISO',
    icon: Stamp,
    items: ['ISO 9001, 14001, 45001', 'ISO 27001 (Info Sec)', 'CE Marking & FDA', 'GMP / HACCP / Halal']
  },
  {
    id: 'accounting',
    title: 'Accounting & Tax',
    icon: Calculator,
    items: ['Cloud Accounting', 'GST Reg & Returns', 'Income Tax Filing', 'Statutory & Tax Audits']
  },
  {
    id: 'registration',
    title: 'Business Registration',
    icon: Briefcase,
    items: ['Pvt Ltd / LLP / OPC', 'Section 8 (NGO)', 'Start-up India Reg', 'FSSAI & Trade License']
  },
  {
    id: 'govt',
    title: 'Govt. Portals',
    icon: Globe,
    items: ['GeM Seller/OEM Reg', 'GeM Product Listing', 'TReDS', 'RERA Registration']
  },
  {
    id: 'msme',
    title: 'Ind. & MSME Loans',
    icon: IndianRupee,
    items: ['Project Reports (DPR)', 'Term Loans', 'CGTMSE & PMEGP', 'Subsidy Guidance']
  },
  {
    id: 'branding',
    title: 'Branding & Startup',
    icon: Lightbulb,
    items: ['Business Plans', 'Website & Branding', 'Vendor Empanelment', 'HR Policy & SOPs']
  },
  {
    id: 'utility',
    title: 'Utility Services',
    icon: MoreHorizontal,
    items: ['Trademark & IP', 'PAN / TAN Apps', 'Digital Marketing', 'Digital Signatures']
  }
];

/* --- DATA FOR HOMEPAGE SERVICE GRID --- */
const SERVICES_GRID_DATA = [
  {
    id: 'registration',
    title: 'Start Business',
    icon: Briefcase,
    color: 'bg-red-50 text-red-600',
    description: 'Pvt Ltd, LLP, OPC, Section 8, Partnership',
    link: '/pvt-ltd-registration'
  },
  {
    id: 'accounting',
    title: 'Tax & Compliance',
    icon: Calculator,
    color: 'bg-slate-100 text-slate-700',
    description: 'GST, Income Tax, Audits, RoC Filings'
  },
  {
    id: 'machinery',
    title: 'Industrial Setup',
    icon: Factory,
    color: 'bg-slate-100 text-slate-700',
    description: 'Machinery Sourcing, Factory Licenses, Turnkey Projects'
  },
  {
    id: 'msme',
    title: 'Loans & Funding',
    icon: IndianRupee,
    color: 'bg-slate-100 text-slate-700',
    description: 'Project Reports, MSME Loans, Subsidies'
  },
  {
    id: 'iso',
    title: 'Certifications',
    icon: Stamp,
    color: 'bg-slate-100 text-slate-700',
    description: 'ISO 9001, FDA, CE, BIS, Halal'
  },
  {
    id: 'govt',
    title: 'Govt Portals',
    icon: Globe,
    color: 'bg-slate-100 text-slate-700',
    description: 'GeM Registration, TReDS, Import Export Code'
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
  {
    name: "Rajesh Kumar",
    role: "MD, TechnoPlast Industries",
    content: "VR HERE helped us setup our manufacturing unit in Jeedimetla. From company registration to machinery sourcing and bank loan, they handled everything. A true single-window solution.",
    rating: 5
  },
  {
    name: "Sneha Reddy",
    role: "Founder, GreenEarth Organics",
    content: "I didn't know anything about compliances. The team at VR HERE explained everything clearly and got my Pvt Ltd registered in just 8 days. Highly recommended for new entrepreneurs!",
    rating: 5
  },
  {
    name: "Anil Gupta",
    role: "Director, Gupta Logistics",
    content: "Their knowledge of Industrial Subsidies is excellent. They helped us get a significant subsidy on our new warehouse project. Professional and transparent service.",
    rating: 5
  }
];

/* --- SEARCH DATA --- */
const ALL_SERVICES = [
  { name: 'Private Limited Registration', link: '/pvt-ltd-registration', type: 'page' },
  { name: 'Partnership Firm Registration', link: '/partnership-firm', type: 'page' },
  { name: 'GST Registration', link: '/gst-registration', type: 'page' },
  { name: 'LLP Registration', link: '/contact?service=LLP Registration', type: 'inquiry' },
  { name: 'One Person Company (OPC)', link: '/contact?service=OPC Registration', type: 'inquiry' },
  { name: 'Section 8 Company (NGO)', link: '/contact?service=Section 8 NGO', type: 'inquiry' },
  { name: 'GST Filing', link: '/contact?service=GST Filing', type: 'inquiry' },
  { name: 'Trademark Registration', link: '/contact?service=Trademark', type: 'inquiry' },
  { name: 'ISO Certification', link: '/contact?service=ISO Certification', type: 'inquiry' },
  { name: 'MSME Loan / Project Report', link: '/contact?service=MSME Loan', type: 'inquiry' },
  { name: 'Factory License', link: '/contact?service=Factory License', type: 'inquiry' },
  { name: 'Import Export Code (IEC)', link: '/contact?service=IEC Code', type: 'inquiry' },
  { name: 'Digital Signature (DSC)', link: '/contact?service=DSC', type: 'inquiry' },
  { name: 'Accounting Services', link: '/contact?service=Accounting', type: 'inquiry' },
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

  // --- ACTIONS ---
  const handleConsultationBook = () => {
    setSelectedPlan(PACKAGES[0]);
    setIsModalOpen(true);
  };

  const handleFormSubmit = (e) => {
    e.preventDefault();
    setIsSubmitting(true);

    const options = {
      key: "rzp_test_YourKeyHere",
      amount: (selectedPlan.price || 499) * 100,
      currency: "INR",
      name: "VR HERE Business Solutions",
      description: `Payment for ${selectedPlan.name}`,
      image: "https://vrhere.in/logo.png",
      handler: function (response) {
        alert(`Payment Successful! Payment ID: ${response.razorpay_payment_id}`);
        setIsSubmitting(false);
        setIsModalOpen(false);
      },
      prefill: {
        name: "Customer Name",
        email: "email@example.com",
        contact: "9999999999"
      },
      theme: {
        color: "#DC2626"
      }
    };

    const rzp1 = new window.Razorpay(options);
    rzp1.on('payment.failed', function (response) {
      alert(`Payment Failed: ${response.error.description}`);
      setIsSubmitting(false);
    });

    rzp1.open();
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(amount);
  };

  const toggleAccordion = (index) => {
    setActiveAccordion(activeAccordion === index ? null : index);
  };

  // --- COMPONENTS ---

  const Header = () => (
    <>
      <div className="bg-slate-900 text-slate-400 text-xs py-2 px-4 hidden lg:block border-b border-slate-800">
        <div className="max-w-[1400px] mx-auto flex justify-between items-center">
          <div className="flex space-x-6">
            <span className="flex items-center hover:text-white transition cursor-default"><MapPin className="w-3 h-3 mr-2 text-red-600" /> Hyderabad, India</span>
            <span className="flex items-center hover:text-white transition cursor-default"><Clock className="w-3 h-3 mr-2 text-red-600" /> Mon - Sat: 10AM - 7PM</span>
            <span className="flex items-center hover:text-white transition cursor-default"><Award className="w-3 h-3 mr-2 text-red-600" /> ISO 9001:2015 Certified</span>
          </div>
          <div className="flex items-center space-x-6">
            <a href="mailto:vrherebms@gmail.com" className="flex items-center hover:text-red-500 transition"><Mail className="w-3 h-3 mr-2" /> vrherebms@gmail.com</a>
            <a href="tel:+918008530606" className="flex items-center hover:text-red-500 font-bold transition"><Phone className="w-3 h-3 mr-2" /> +91 80085 30606</a>
          </div>
        </div>
      </div>

      <header className={`sticky top-0 z-50 transition-all duration-300 w-full ${isScrolled ? 'bg-white/95 backdrop-blur-md shadow-lg py-2' : 'bg-white border-b border-slate-100 py-4'}`}>
        <div className="max-w-[1400px] mx-auto px-4 sm:px-6">
          <div className="flex justify-between items-center relative">
            {/* LOGO: Points to / (Home) */}
            <a href="/" className="flex items-center flex-shrink-0 group cursor-pointer">
              <div className="w-10 h-10 bg-black rounded-lg flex items-center justify-center mr-3 shadow-lg group-hover:bg-red-600 transition duration-300 relative overflow-hidden transform group-hover:scale-105">
                <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition duration-300"></div>
                <span className="text-white font-black text-xl tracking-tighter">VR</span>
              </div>
              <div className="flex flex-col">
                <span className="text-2xl font-extrabold text-black leading-none tracking-tight group-hover:text-red-600 transition-colors">VR HERE</span>
                <span className="text-[10px] font-bold text-red-600 uppercase tracking-widest mt-0.5">Business Solutions</span>
              </div>
            </a>

            <nav className="hidden lg:flex items-center space-x-1">
              <a href="/" className="px-4 py-2 text-sm font-bold text-slate-700 hover:text-red-600 rounded-full hover:bg-red-50 transition-all duration-300 hover:scale-105">Home</a>
              <div className="relative px-2 py-4" onMouseEnter={() => setIsServicesHovered(true)} onMouseLeave={() => setIsServicesHovered(false)}>
                <button className={`flex items-center px-4 py-2 text-sm font-bold rounded-full transition-all duration-300 hover:scale-105 group ${isServicesHovered ? 'bg-red-600 text-white shadow-lg shadow-red-600/30' : 'text-slate-700 hover:text-red-600 hover:bg-red-50'}`}>
                  Services <ChevronDown className={`ml-1 w-4 h-4 transition-transform duration-300 ${isServicesHovered ? 'rotate-180' : ''}`} />
                </button>
                <div className={`absolute top-full left-1/2 -translate-x-1/2 w-[90vw] max-w-[1200px] bg-white rounded-2xl shadow-2xl border-t-4 border-red-600 overflow-hidden transition-all duration-300 origin-top z-50 ${isServicesHovered ? 'opacity-100 translate-y-0 visible' : 'opacity-0 translate-y-4 invisible pointer-events-none'}`}>
                  <div className="flex">
                    <div className="w-64 bg-slate-50 p-8 flex flex-col justify-between border-r border-slate-100">
                      <div>
                        <h3 className="text-xl font-extrabold text-slate-900 mb-2">Our Expertise</h3>
                        <p className="text-sm text-slate-500 mb-6">From registration to expansion, we handle all your business needs under one roof.</p>
                        <div className="space-y-3">
                          <div className="flex items-center text-xs font-semibold text-slate-600"><CheckCircle2 className="w-4 h-4 text-green-500 mr-2" /> 100% Online Process</div>
                          <div className="flex items-center text-xs font-semibold text-slate-600"><CheckCircle2 className="w-4 h-4 text-green-500 mr-2" /> Expert CA/CS Team</div>
                        </div>
                      </div>
                      <button onClick={handleConsultationBook} className="block w-full py-3 bg-black text-white text-center text-sm font-bold rounded-lg hover:bg-slate-800 transition transform hover:-translate-y-1 shadow-lg">Get Custom Quote</button>
                    </div>
                    <div className="flex-1 p-8 bg-white">
                      <div className="grid grid-cols-4 gap-6">
                        {MENU_DATA.map((service) => (
                          <div key={service.id} className="group/item cursor-pointer hover:bg-slate-50 p-3 rounded-lg transition-colors">
                            <div className="flex items-center space-x-3 mb-2">
                              <div className="p-2 bg-red-50 text-red-600 rounded-lg group-hover/item:bg-red-600 group-hover/item:text-white transition-colors duration-300 shadow-sm">
                                <service.icon className="w-6 h-6" />
                              </div>
                              <h4 className="font-bold text-slate-900 text-sm leading-tight group-hover/item:text-red-600 transition-colors">{service.title}</h4>
                            </div>
                            <ul className="space-y-1 ml-11 border-l-2 border-slate-100 pl-3 group-hover/item:border-red-200 transition-colors">
                              {service.items.slice(0, 3).map((item, i) => (
                                <li key={i} className="text-xs font-medium text-slate-500 hover:text-red-600 transition-colors truncate">{item}</li>
                              ))}
                            </ul>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <button className="px-4 py-2 text-sm font-bold text-slate-700 hover:text-red-600 rounded-full hover:bg-red-50 transition-all duration-300 hover:scale-105">Pricing</button>
            </nav>

            <div className="hidden lg:flex items-center space-x-4">
              <button className="p-2 text-slate-600 hover:text-red-600 transition transform hover:scale-110"><Search className="w-5 h-5" /></button>
              <button onClick={handleConsultationBook} className="bg-red-600 text-white px-6 py-2.5 rounded-lg font-bold text-sm hover:bg-red-700 transition shadow-lg shadow-red-600/20 flex items-center transform hover:-translate-y-1 active:scale-95 group">
                <Phone className="w-4 h-4 mr-2 group-hover:rotate-12 transition-transform" /> Talk to Expert
              </button>
            </div>
            <button className="lg:hidden p-2 text-slate-800 hover:bg-slate-100 rounded-lg transition" onClick={() => setIsMobileMenuOpen(true)}>
              <Menu className="w-7 h-7" />
            </button>
          </div>
        </div>
      </header>

      {/* MOBILE MENU */}
      <div className={`fixed inset-0 bg-white z-[60] transform transition-transform duration-300 lg:hidden overflow-y-auto ${isMobileMenuOpen ? 'translate-x-0' : 'translate-x-full'}`}>
        <div className="p-4 border-b border-slate-100 flex justify-between items-center sticky top-0 bg-white z-10">
          <div className="flex items-center">
            <div className="w-8 h-8 bg-black rounded flex items-center justify-center mr-2"><span className="text-white font-bold">VR</span></div>
            <span className="font-bold text-lg">Menu</span>
          </div>
          <button onClick={() => setIsMobileMenuOpen(false)} className="p-2 bg-slate-100 rounded-full hover:bg-red-100 hover:text-red-600 transition"><X className="w-6 h-6" /></button>
        </div>
        <div className="p-4 space-y-1">
          <a href="/" className="block w-full text-left px-4 py-3 text-lg font-bold text-slate-800 hover:bg-slate-50 rounded-xl">Home</a>
          <div className="border rounded-xl overflow-hidden border-slate-100 my-2">
            <div className="bg-slate-50 px-4 py-3 font-bold text-lg flex justify-between items-center text-slate-900">Services <span className="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded-full">8 Cats</span></div>
            <div className="divide-y divide-slate-100">
              {MENU_DATA.map((service) => (
                <div key={service.id} className="bg-white">
                  <button onClick={() => setActiveMobileCategory(activeMobileCategory === service.id ? null : service.id)} className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-slate-50 transition">
                    <div className="flex items-center space-x-3">
                      <div className={`p-1.5 rounded-lg ${activeMobileCategory === service.id ? 'bg-red-600 text-white' : 'bg-slate-100 text-slate-600'}`}>
                        <service.icon className="w-5 h-5" />
                      </div>
                      <span className={`text-sm font-bold ${activeMobileCategory === service.id ? 'text-red-600' : 'text-slate-700'}`}>{service.title}</span>
                    </div>
                    <ChevronDown className={`w-4 h-4 transition-transform ${activeMobileCategory === service.id ? 'rotate-180 text-red-600' : 'text-slate-400'}`} />
                  </button>
                  {activeMobileCategory === service.id && (
                    <div className="bg-slate-50 px-4 pb-4 pt-2 space-y-2 pl-14 animate-fade-in">
                      {service.items.map((item, i) => (
                        <div key={i} className="block text-sm text-slate-600 border-l-2 border-slate-200 pl-3 py-1 active:text-red-600">{item}</div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );

  const QuoteModal = () => (
    isModalOpen && (
      <div className="fixed inset-0 z-[70] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
        <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md relative overflow-hidden animate-slide-up">
          <button onClick={() => setIsModalOpen(false)} className="absolute top-4 right-4 text-gray-400 hover:text-red-600 transition bg-white rounded-full p-1"><X className="w-6 h-6" /></button>
          <div className="bg-slate-900 p-6 text-center border-b-4 border-red-600">
            <h3 className="text-white font-bold text-xl">
              {selectedPlan?.buttonText || 'Book Consultation'}
            </h3>
            <p className="text-slate-400 text-sm mt-1">{selectedPlan?.name || "Expert Guidance"}</p>
          </div>
          <div className="p-6">
            <div className="mb-6 bg-red-50 border border-red-100 p-4 rounded-xl flex items-start">
              <CreditCard className="w-5 h-5 text-red-600 mt-0.5 mr-3 flex-shrink-0" />
              <div>
                <div className="font-bold text-slate-900 text-sm">Payment Amount: {selectedPlan ? formatCurrency(selectedPlan.price) : '...'}</div>
                {selectedPlan?.isAdjustable ? (
                  <p className="text-xs text-green-700 font-bold mt-1 flex items-center"><RefreshCw className="w-3 h-3 mr-1" /> Fully adjustable against final package</p>
                ) : (
                  <p className="text-xs text-slate-500 mt-1">+ Government Fees as applicable</p>
                )}
              </div>
            </div>
            <form onSubmit={handleFormSubmit} className="space-y-4">
              <input required type="text" className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-red-600 outline-none transition-shadow hover:shadow-inner" placeholder="Full Name" />
              <input required type="tel" className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-red-600 outline-none transition-shadow hover:shadow-inner" placeholder="Mobile Number" />
              <input required type="email" className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-red-600 outline-none transition-shadow hover:shadow-inner" placeholder="Email Address" />
              <button disabled={isSubmitting} type="submit" className="w-full bg-red-600 text-white font-bold py-3.5 rounded-lg hover:bg-red-700 transition transform active:scale-95 flex items-center justify-center shadow-lg shadow-red-600/20">
                {isSubmitting ? <Loader2 className="w-5 h-5 animate-spin" /> : `Pay ${selectedPlan ? formatCurrency(selectedPlan.price) : ''} & Proceed`}
              </button>
            </form>
            <p className="text-center text-xs text-slate-400 mt-4 flex items-center justify-center"><ShieldCheck className="w-3 h-3 mr-1" /> Secure Payment Gateway</p>
          </div>
        </div>
      </div>
    )
  );

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

  return (
    <div className="font-sans text-slate-800 bg-white min-h-screen selection:bg-red-100 selection:text-red-900 overflow-x-hidden">
      <Header />
      <QuoteModal />
      <FloatingButtons />

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
            <span className="text-red-500 mr-2">●</span> Trusted by 5000+ Businesses
          </div>
          <h1 className="text-4xl md:text-6xl lg:text-7xl font-black text-white tracking-tight leading-[1.1] mb-8">
            Build Your Business.<br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-orange-500">Run It Smarter.</span>
          </h1>
          <p className="text-xl text-slate-400 mb-12 max-w-2xl mx-auto leading-relaxed">
            India's only platform combining <span className="text-white font-bold">Legal Compliance</span> with <span className="text-white font-bold">Industrial Setup</span> & <span className="text-white font-bold">Funding</span>.
          </p>


          {/* SEARCH BAR */}
          <div className="max-w-3xl mx-auto relative z-50">
            <div className="absolute -inset-1 bg-gradient-to-r from-red-600 to-orange-600 rounded-2xl blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>
            <div className="relative bg-white rounded-xl shadow-2xl p-2 flex items-center">
              <div className="pl-4 pr-2 text-slate-400">
                <Search className="w-6 h-6" />
              </div>
              <input
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
            {suggestions.length > 0 && (
              <div className="absolute top-full left-0 right-0 mt-2 bg-white rounded-xl shadow-2xl border border-slate-100 overflow-hidden text-left animate-fade-in max-h-60 overflow-y-auto z-50">
                {suggestions.map((s, i) => (
                  <a href={s.link} key={i} className="flex items-center justify-between px-6 py-3 hover:bg-slate-50 transition-colors group">
                    <span className="font-bold text-slate-700 group-hover:text-red-600">{s.name}</span>
                    <span className="text-xs text-slate-400 uppercase tracking-wider group-hover:text-red-400">
                      {s.type === 'page' ? 'View Page' : 'Inquire'}
                    </span>
                  </a>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* STATS STRIP */}
      <div className="bg-black border-y border-slate-800 relative z-20">
        <div className="max-w-7xl mx-auto px-4 grid grid-cols-2 md:grid-cols-4 divide-x divide-slate-800 text-center">
          <div className="py-6">
            <div className="text-red-500 text-3xl font-black">5000+</div>
            <div className="text-slate-500 text-xs font-bold uppercase tracking-wider mt-1">Clients Served</div>
          </div>
          <div className="py-6">
            <div className="text-red-500 text-3xl font-black">₹100Cr+</div>
            <div className="text-slate-500 text-xs font-bold uppercase tracking-wider mt-1">Loans Facilitated</div>
          </div>
          <div className="py-6">
            <div className="text-red-500 text-3xl font-black">150+</div>
            <div className="text-slate-500 text-xs font-bold uppercase tracking-wider mt-1">Experts Team</div>
          </div>
          <div className="py-6">
            <div className="text-red-500 text-3xl font-black">4.9/5</div>
            <div className="text-slate-500 text-xs font-bold uppercase tracking-wider mt-1">Google Rating</div>
          </div>
        </div>
      </div>

      {/* SERVICE CATEGORIES GRID */}
      <section id="services" className="py-24 bg-slate-50">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-black text-slate-900">Everything Your Business Needs</h2>
            <p className="text-slate-500 mt-4">Categorized for simplicity. Executed with expertise.</p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {SERVICES_GRID_DATA.map((service) => (
              <a href={service.link || '#'} key={service.id} className="bg-white p-8 rounded-2xl border border-slate-100 hover:border-red-200 shadow-sm hover:shadow-xl hover:shadow-red-600/5 transition-all duration-300 group relative overflow-hidden">
                <div className={`absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity transform group-hover:scale-110`}>
                  <service.icon className="w-24 h-24 text-slate-900" />
                </div>
                <div className={`w-14 h-14 ${service.color} rounded-xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform`}>
                  <service.icon className="w-7 h-7" />
                </div>
                <h3 className="text-xl font-bold text-slate-900 mb-2 group-hover:text-red-600 transition-colors">{service.title}</h3>
                <p className="text-slate-500 text-sm mb-6 leading-relaxed">{service.description}</p>
                <div className="flex items-center text-sm font-bold text-slate-900 group-hover:text-red-600 transition-colors">
                  Explore <ArrowRight className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" />
                </div>
              </a>
            ))}
          </div>
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section className="py-20 bg-white">
        <div className="max-w-6xl mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-black text-slate-900 mb-4">How It Works</h2>
            <p className="text-lg text-slate-600">Get your business sorted in 3 simple steps.</p>
          </div>
          <div className="grid md:grid-cols-3 gap-8 relative">
            <div className="hidden md:block absolute top-12 left-0 w-full h-0.5 bg-slate-100 -z-10"></div>
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

      {/* TESTIMONIALS */}
      <section className="py-24 bg-slate-50">
        <div className="max-w-7xl mx-auto px-4">
          <h2 className="text-3xl font-black text-center text-slate-900 mb-12">Success Stories</h2>
          <div className="grid md:grid-cols-3 gap-8">
            {TESTIMONIALS.map((t, i) => (
              <div key={i} className="bg-white p-8 rounded-2xl shadow-sm border border-slate-100 hover:shadow-lg transition-all">
                <div className="flex text-yellow-400 mb-4">
                  {[...Array(t.rating)].map((_, i) => <Star key={i} className="w-4 h-4 fill-current" />)}
                </div>
                <p className="text-slate-600 mb-6 text-sm leading-relaxed">"{t.content}"</p>
                <div>
                  <div className="font-bold text-slate-900">{t.name}</div>
                  <div className="text-xs text-slate-500">{t.role}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FAQ SECTION */}
      <section className="py-20 bg-white border-t border-slate-100">
        <div className="max-w-3xl mx-auto px-4">
          <h2 className="text-3xl font-black text-center text-slate-900 mb-12">Frequently Asked Questions</h2>
          <div className="space-y-4">
            {FAQS.map((faq, i) => (
              <div key={i} className="border border-slate-200 rounded-xl overflow-hidden transition-all hover:border-red-200">
                <button onClick={() => toggleAccordion(i)} className="w-full flex justify-between items-center p-5 text-left bg-slate-50 hover:bg-white transition-colors">
                  <span className="font-bold text-slate-800">{faq.question}</span>
                  {activeAccordion === i ? <ChevronUp className="w-5 h-5 text-red-600" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </button>
                {activeAccordion === i && (
                  <div className="p-5 bg-white text-slate-600 text-sm leading-relaxed border-t border-slate-100 animate-fade-in">
                    {faq.answer}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA SECTION */}
      <section className="py-24 bg-slate-900 text-white relative overflow-hidden">
        <div className="max-w-4xl mx-auto px-4 text-center relative z-10">
          <h2 className="text-3xl lg:text-5xl font-black mb-6">Ready to Start?</h2>
          <p className="text-xl text-slate-400 mb-10">
            Talk to our experts before you commit. Pay a small booking fee now, and we will deduct it from your final bill.
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

      {/* RICH FOOTER SECTION (FROM PRIVATELIMITEDPAGE) */}
      <footer className="bg-[#0f172a] text-slate-300 pt-16 pb-8 border-t border-slate-800 font-sans">
        <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 mb-16">

            {/* Column 1: Brand & Contact */}
            <div className="lg:col-span-3 space-y-8">
              <div className="flex items-center space-x-3 group cursor-pointer" onClick={() => window.scrollTo(0, 0)}>
                <div className="w-10 h-10 bg-white rounded-lg flex items-center justify-center transform group-hover:rotate-12 transition-transform duration-300">
                  <span className="text-black font-black text-xl">VR</span>
                </div>
                <div>
                  <h2 className="text-2xl font-extrabold text-white leading-none group-hover:text-red-500 transition-colors">VR HERE</h2>
                  <p className="text-[10px] text-red-500 font-bold tracking-widest uppercase mt-1">Business Solutions</p>
                </div>
              </div>
              <p className="text-sm leading-relaxed text-slate-400">
                #31, Dwarawati, Subodaya Colony,<br />
                Kukatpally, Hyderabad - 500072<br />
                Telangana, India.
              </p>
              <div className="space-y-2">
                <a href="tel:+918008530606" className="flex items-center text-slate-400 hover:text-white transition"><Phone className="w-4 h-4 mr-2" /> +91 80085 30606</a>
                <a href="mailto:vrherebms@gmail.com" className="flex items-center text-slate-400 hover:text-white transition"><Mail className="w-4 h-4 mr-2" /> vrherebms@gmail.com</a>
              </div>
              <a href="https://goo.gl/maps/placeholder" target="_blank" rel="noreferrer" className="inline-flex items-center text-red-500 hover:text-red-400 text-sm font-bold transition transform hover:translate-x-1">
                Open on Google Maps <ArrowRight className="w-4 h-4 ml-1" />
              </a>
              <div className="flex space-x-4">
                <a href="#" className="p-2 bg-slate-800 rounded-full hover:bg-red-600 hover:text-white transition transform hover:scale-110 hover:-translate-y-1">
                  <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.791-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z" /></svg>
                </a>
                <a href="#" className="p-2 bg-slate-800 rounded-full hover:bg-red-600 hover:text-white transition transform hover:scale-110 hover:-translate-y-1">
                  <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24"><path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z" /></svg>
                </a>
                <a href="#" className="p-2 bg-slate-800 rounded-full hover:bg-red-600 hover:text-white transition transform hover:scale-110 hover:-translate-y-1">
                  <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" /></svg>
                </a>
              </div>
            </div>

            {/* Columns 2-4: Links Grid */}
            <div className="lg:col-span-9 grid md:grid-cols-3 gap-8">
              <div>
                <h3 className="text-red-500 font-bold text-sm uppercase tracking-wider mb-6">Start a Business</h3>
                <ul className="space-y-3 text-sm">
                  <li><a href="/pvt-ltd-registration" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Private Limited Company</a></li>
                  <li><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Limited Liability Partnership</a></li>
                  <li><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">One Person Company</a></li>
                  <li><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Section 8 Company</a></li>
                  <li><a href="/partnership-firm" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Partnership Firm</a></li>
                  <li><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Proprietorship</a></li>
                  <li><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Nidhi Company</a></li>
                  <li><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Producer Company</a></li>
                </ul>
              </div>
              <div>
                <h3 className="text-red-500 font-bold text-sm uppercase tracking-wider mb-6">Grow & Manage</h3>
                <ul className="space-y-3 text-sm">
                  <li><a href="/gst-registration" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">GST Registration</a></li>
                  <li><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">Accounting Services</a></li>
                  <li><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">MSME Loans</a></li>
                  <li><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">GeM Registration</a></li>
                  <li><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">ISO Certification</a></li>
                </ul>
              </div>
              <div>
                <h3 className="text-red-500 font-bold text-sm uppercase tracking-wider mb-6">Industrial</h3>
                <ul className="space-y-3 text-sm">
                  {['Machinery Sourcing', 'Factory License', 'Pollution Control NOC', 'Turnkey Setup', 'Import Export Code'].map(item => (
                    <li key={item}><a href="#" className="hover:text-white transition-colors block py-1">{item}</a></li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
          <div className="pt-8 border-t border-slate-800 flex flex-col md:flex-row justify-between items-center gap-4 text-xs text-slate-500">
            <p>&copy; {new Date().getFullYear()} VR HERE Business Management Solutions. All rights reserved.</p>
            <div className="flex space-x-6">
              <a href="#" className="hover:text-white transition">Privacy Policy</a>
              <a href="#" className="hover:text-white transition">Terms & Conditions</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default HomePage;