import React, { useState, useEffect } from 'react';
import {
  Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
  Phone, Menu, X, ChevronDown, Clock, Award, Search, ArrowRight, CheckCircle2,
  Building2, Mail, MapPin, CheckCircle, Smartphone, ShieldCheck, RefreshCw,
  CreditCard, Loader2, MessageSquare, Users
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
    color: 'bg-blue-50 text-blue-600',
    description: 'Pvt Ltd, LLP, OPC, Section 8, Partnership',
    link: '/pvt-ltd-registration'
  },
  {
    id: 'accounting',
    title: 'Tax & Compliance',
    icon: Calculator,
    color: 'bg-green-50 text-green-600',
    description: 'GST, Income Tax, Audits, RoC Filings'
  },
  {
    id: 'machinery',
    title: 'Industrial Setup',
    icon: Factory,
    color: 'bg-orange-50 text-orange-600',
    description: 'Machinery Sourcing, Factory Licenses, Turnkey Projects'
  },
  {
    id: 'msme',
    title: 'Loans & Funding',
    icon: IndianRupee,
    color: 'bg-indigo-50 text-indigo-600',
    description: 'Project Reports, MSME Loans, Subsidies'
  },
  {
    id: 'iso',
    title: 'Certifications',
    icon: Stamp,
    color: 'bg-purple-50 text-purple-600',
    description: 'ISO 9001, FDA, CE, BIS, Halal'
  },
  {
    id: 'govt',
    title: 'Govt Portals',
    icon: Globe,
    color: 'bg-red-50 text-red-600',
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
    setTimeout(() => {
      setIsSubmitting(false);
      setIsModalOpen(false);
      alert(`Proceeding to payment for ${selectedPlan?.name}`);
    }, 1500);
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(amount);
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
            {/* UPDATED LOGO LINK: Points to / (Home) */}
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

      {/* HERO SECTION (PRESERVED FROM HOMEPAGE) */}
      <section className="relative bg-slate-900 pb-32 pt-20 lg:pt-32 overflow-hidden -mt-[90px]">
        {/* Abstract Background */}
        <div className="absolute inset-0 z-0">
          <div className="absolute top-0 right-0 w-[60%] h-[80%] bg-blue-600/20 rounded-full blur-[120px] translate-x-1/4 -translate-y-1/4"></div>
          <div className="absolute bottom-0 left-0 w-[40%] h-[60%] bg-red-600/10 rounded-full blur-[100px] -translate-x-1/4 translate-y-1/4"></div>
          <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20"></div>
        </div>

        <div className="relative z-10 max-w-5xl mx-auto px-4 text-center">
          <div className="inline-block px-4 py-1.5 rounded-full bg-white/10 backdrop-blur-md border border-white/20 text-white/80 text-xs font-bold mb-8 uppercase tracking-widest">
            Trusted by 5000+ Businesses
          </div>
          <h1 className="text-4xl md:text-6xl lg:text-7xl font-black text-white tracking-tight leading-[1.1] mb-8">
            Build Your Business.<br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-purple-400 to-red-400">Run It Smarter.</span>
          </h1>
          <p className="text-xl text-slate-400 mb-12 max-w-2xl mx-auto leading-relaxed">
            India's only platform combining <span className="text-white font-bold">Legal Compliance</span> with <span className="text-white font-bold">Industrial Setup</span> & <span className="text-white font-bold">Funding</span>.
          </p>

          {/* SEARCH BAR */}
          <div className="max-w-3xl mx-auto relative group">
            <div className="absolute -inset-1 bg-gradient-to-r from-blue-600 to-red-600 rounded-2xl blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>
            <div className="relative bg-white rounded-xl shadow-2xl p-2 flex items-center">
              <div className="pl-4 pr-2 text-slate-400">
                <Search className="w-6 h-6" />
              </div>
              <input
                type="text"
                placeholder="Try 'Private Limited', 'ISO Certification', 'Factory Loan'..."
                className="flex-1 p-3 text-lg font-medium text-slate-900 placeholder:text-slate-400 outline-none bg-transparent"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
              <button className="hidden sm:block bg-black text-white px-8 py-3 rounded-lg font-bold text-sm hover:bg-slate-800 transition transform hover:-translate-y-0.5">
                Get Started
              </button>
            </div>
            {/* Popular Searches */}
            <div className="mt-4 flex flex-wrap justify-center gap-2 text-sm text-slate-400 font-medium">
              <span>Popular:</span>
              {['Pvt Ltd Registration', 'Trademark', 'GST Filing', 'Project Report'].map(tag => (
                <span key={tag} className="px-3 py-1 bg-white/5 rounded-full hover:bg-white/10 hover:text-white cursor-pointer transition border border-white/5">{tag}</span>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* TRUST SIGNALS */}
      <div className="bg-white border-b border-slate-100">
        <div className="max-w-7xl mx-auto px-4 py-8 flex flex-wrap justify-center md:justify-between items-center gap-8 grayscale opacity-70 hover:grayscale-0 hover:opacity-100 transition duration-500">
          <div className="font-black text-xl text-slate-300">HDFC BANK</div>
          <div className="font-black text-xl text-slate-300">ICICI Verified</div>
          <div className="font-black text-xl text-slate-300">ISO 9001</div>
          <div className="font-black text-xl text-slate-300">Startup India</div>
          <div className="font-black text-xl text-slate-300">MSME Databank</div>
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
              <a href={service.link || '#'} key={service.id} className="bg-white p-8 rounded-2xl border border-slate-100 hover:border-red-100 shadow-sm hover:shadow-2xl hover:shadow-red-600/10 transition-all duration-300 group relative overflow-hidden">
                <div className={`absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity transform group-hover:scale-110`}>
                  <service.icon className="w-24 h-24 text-slate-900" />
                </div>
                <div className={`w-14 h-14 ${service.color} rounded-xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform`}>
                  <service.icon className="w-7 h-7" />
                </div>
                <h3 className="text-xl font-bold text-slate-900 mb-2 group-hover:text-red-600 transition-colors">{service.title}</h3>
                <p className="text-slate-500 text-sm mb-6 leading-relaxed">{service.description}</p>
                <div className="flex items-center text-sm font-bold text-slate-900 group-hover:text-red-600 transition-colors">
                  Explore Services <ArrowRight className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" />
                </div>
              </a>
            ))}
          </div>
        </div>
      </section>

      {/* WHY CHOOSE US */}
      <section className="py-24 bg-white relative overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 flex flex-col md:flex-row items-center gap-16">
          <div className="md:w-1/2">
            <div className="relative">
              <div className="absolute -inset-4 bg-gradient-to-tr from-red-600 to-orange-600 rounded-3xl blur opacity-20"></div>
              <div className="relative bg-slate-900 p-8 rounded-3xl text-white">
                <div className="flex items-center space-x-4 mb-8">
                  <div className="p-3 bg-red-600 rounded-lg">
                    <ShieldCheck className="w-8 h-8 text-white" />
                  </div>
                  <div>
                    <div className="font-bold text-lg">One-Stop Solution</div>
                    <div className="text-slate-400 text-sm">No need to hire 10 different vendors.</div>
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="flex items-center p-3 bg-white/5 rounded-xl border border-white/10">
                    <CheckCircle2 className="w-5 h-5 text-green-400 mr-3" /> <span>Legal & Compliance</span>
                  </div>
                  <div className="flex items-center p-3 bg-white/5 rounded-xl border border-white/10">
                    <CheckCircle2 className="w-5 h-5 text-green-400 mr-3" /> <span>Industrial Machinery</span>
                  </div>
                  <div className="flex items-center p-3 bg-white/5 rounded-xl border border-white/10">
                    <CheckCircle2 className="w-5 h-5 text-green-400 mr-3" /> <span>Bank Loans & DPR</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="md:w-1/2">
            <h2 className="text-4xl font-black text-slate-900 mb-6">We bridge the gap between <span className="text-red-600">office</span> and <span className="text-red-600">factory</span>.</h2>
            <p className="text-lg text-slate-600 mb-8 max-w-lg leading-relaxed">
              Most consultants only handle paper. We handle paper AND metal. From incorporating your company to sourcing your first machine, VR HERE is your end-to-end partner.
            </p>
            <button className="bg-slate-900 text-white px-8 py-4 rounded-xl font-bold hover:bg-black transition shadow-xl hover:shadow-2xl transform hover:-translate-y-1">
              About Our Company
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
                <a href="#" className="p-2 bg-slate-800 rounded-full hover:bg-red-600 hover:text-white transition transform hover:scale-110 hover:-translate-y-1">
                  <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z" /></svg>
                </a>
              </div>
            </div>

            {/* Columns 2-4: Links Grid */}
            <div className="lg:col-span-9 grid md:grid-cols-3 gap-8">
              <div>
                <h3 className="text-red-500 font-bold text-sm uppercase tracking-wider mb-6">Start a Business</h3>
                <ul className="space-y-3 text-sm">
                  {['Private Limited Company', 'Limited Liability Partnership', 'One Person Company', 'Section 8 Company', 'Partnership Firm', 'Proprietorship', 'Nidhi Company', 'Producer Company'].map(item => (
                    <li key={item}><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">{item}</a></li>
                  ))}
                </ul>
              </div>
              <div>
                <h3 className="text-red-500 font-bold text-sm uppercase tracking-wider mb-6">Grow & Manage</h3>
                <ul className="space-y-3 text-sm">
                  {['GST Filing', 'Accounting Services', 'MSME Loans', 'GeM Registration', 'ISO Certification'].map(item => (
                    <li key={item}><a href="#" className="hover:text-white transition-colors block py-1 transform hover:translate-x-1 duration-200">{item}</a></li>
                  ))}
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