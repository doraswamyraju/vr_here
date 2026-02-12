// Force verify build update
import React, { useState, useEffect } from 'react';
import {
  Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
  Phone, Menu, X, ChevronDown, Clock, Award, Search, ArrowRight, CheckCircle2,
  Building2, Mail, MapPin, CheckCircle, Smartphone, ShieldCheck, RefreshCw,
  CreditCard, Loader2, MessageSquare, Users, Star, Quote, HelpCircle, ChevronUp
} from 'lucide-react';
import { RAZORPAY_KEY_ID } from './config';
import { SharedHeader, SharedFooter } from './components/SharedComponents';

// MENU_DATA removed (moved to SharedComponents)

/* --- DATA FOR HOMEPAGE SERVICE GRID --- */
const SERVICES_GRID_DATA = [
  {
    id: 'registration',
    title: 'Start Business',
    icon: Briefcase,
    color: 'bg-red-50 text-red-600',
    description: 'Pvt Ltd, LLP, Section 8, FSSAI, Trade License',
    link: '/pvt-ltd-registration'
  },
  {
    id: 'machinery',
    title: 'Machinery & Industrial',
    icon: Factory,
    color: 'bg-slate-100 text-slate-700',
    description: 'Sourcing, Vendor Verification, Turnkey Setup',
    link: '/contact?service=Machinery'
  },
  {
    id: 'iso',
    title: 'Certifications',
    icon: Stamp,
    color: 'bg-slate-100 text-slate-700',
    description: 'ISO 9001, FDA, CE, BIS, HACCP, Halal',
    link: '/contact?service=ISO'
  },
  {
    id: 'accounting',
    title: 'Accounting & Tax',
    icon: Calculator,
    color: 'bg-slate-100 text-slate-700',
    description: 'GST Returns, Income Tax, Audits, RoC Filings',
    link: '/gst-registration'
  },
  {
    id: 'govt',
    title: 'Govt Portals',
    icon: Globe,
    color: 'bg-slate-100 text-slate-700',
    description: 'GeM, TReDS, RERA, Import Export Code',
    link: '/contact?service=Govt Portals'
  },
  {
    id: 'msme',
    title: 'Industrial Consultancy',
    icon: IndianRupee,
    color: 'bg-slate-100 text-slate-700',
    description: 'Project Reports (DPR), Loans, Subsidies',
    link: '/contact?service=Loans'
  },
  {
    id: 'branding',
    title: 'Startup Support',
    icon: Lightbulb,
    color: 'bg-slate-100 text-slate-700',
    description: 'Business Plans, Pitch Decks, Branding, IP',
    link: '/contact?service=Startup Support'
  },
  {
    id: 'utility',
    title: 'Utility Services',
    icon: MoreHorizontal,
    color: 'bg-slate-100 text-slate-700',
    description: 'Trademark, PAN/TAN, Insurance, Digital Marketing',
    link: '/contact?service=Utility Services'
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
    setSelectedPlan(PACKAGES[0]);
    setIsModalOpen(true);
  };

  const handleFormSubmit = (e) => {
    e.preventDefault();
    setIsSubmitting(true);

    if (!window.Razorpay) {
      alert("Razorpay SDK failed to load. Please check your internet connection or disable ad-blockers.");
      setIsSubmitting(false);
      return;
    }

    const options = {
      key: RAZORPAY_KEY_ID,
      amount: (selectedPlan.price || 499) * 100,
      currency: "INR",
      name: "VR HERE Business Solutions",
      description: `Payment for ${selectedPlan.name}`,
      image: "https://vrhere.in/logo.png",
      handler: async function (response) {
        try {
          // 1. Payment Successful - Save Order to Backend
          const orderData = {
            clientName: formData.name,
            email: formData.email,
            phone: formData.phone,
            serviceName: selectedPlan.name,
            amount: selectedPlan.price,
            paymentStatus: 'Paid',
            razorpayPaymentId: response.razorpay_payment_id,
            razorpayOrderId: response.razorpay_order_id, // Might be undefined if not created via backend order
          };

          const res = await fetch('/api/orders', { // Use relative path for proxy
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(orderData),
          });

          if (res.ok) {
            alert(`Payment Successful! Booking Confirmed. Payment ID: ${response.razorpay_payment_id}`);
            setIsSubmitting(false);
            setIsModalOpen(false);
            // Optional: Reset form
            setFormData({ name: '', email: '', phone: '' });
          } else {
            console.error("Failed to save order to backend");
            alert(`Payment successful, but we failed to save the booking details. Please contact support with Payment ID: ${response.razorpay_payment_id}`);
            setIsSubmitting(false);
          }

        } catch (error) {
          console.error("Error saving order:", error);
          alert("An error occurred while confirming your booking. Please contact support.");
          setIsSubmitting(false);
        }
      },
      prefill: {
        name: formData.name,
        email: formData.email,
        contact: formData.phone
      },
      theme: {
        color: "#DC2626"
      }
    };

    try {
      const rzp1 = new window.Razorpay(options);
      rzp1.on('payment.failed', function (response) {
        alert(`Payment Failed: ${response.error.description}`);
        setIsSubmitting(false);
      });
      rzp1.open();
    } catch (error) {
      console.error("Razorpay Error:", error);
      alert("Something went wrong initializing payment. Please try again.");
      setIsSubmitting(false);
    }
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(amount);
  };

  const toggleAccordion = (index) => {
    setActiveAccordion(activeAccordion === index ? null : index);
  };

  // --- COMPONENTS ---

  // Header removed (using SharedHeader)

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
              <input
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                required
                type="text"
                className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-red-600 outline-none transition-shadow hover:shadow-inner"
                placeholder="Full Name"
              />
              <input
                name="phone"
                value={formData.phone}
                onChange={handleInputChange}
                required
                type="tel"
                className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-red-600 outline-none transition-shadow hover:shadow-inner"
                placeholder="Mobile Number"
              />
              <input
                name="email"
                value={formData.email}
                onChange={handleInputChange}
                required
                type="email"
                className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-red-600 outline-none transition-shadow hover:shadow-inner"
                placeholder="Email Address"
              />
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
      <SharedHeader isScrolled={isScrolled} />
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
      <section id="services" className="py-24 bg-white">
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

      <SharedFooter />

    </div >
  );
};

export default HomePage;