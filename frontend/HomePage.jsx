import React, { useState, useEffect } from 'react';
import {
  Factory, Stamp, Calculator, Briefcase, Globe, IndianRupee, Lightbulb, MoreHorizontal,
  Phone, Menu, X, ChevronDown, Clock, Award, Search, ArrowRight, CheckCircle2,
  Building2, Mail, MapPin, CheckCircle, Smartphone, ShieldCheck
} from 'lucide-react';

/* --- SHARED DATA --- */
const SERVICES_DATA = [
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

const HomePage = () => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const Header = () => (
    <>
      <div className="bg-slate-900 text-slate-400 text-xs py-2 px-4 hidden lg:block border-b border-slate-800">
        <div className="max-w-[1400px] mx-auto flex justify-between items-center">
          <div className="flex space-x-6">
            <span className="flex items-center"><MapPin className="w-3 h-3 mr-2 text-red-600" /> Hyderabad, India</span>
            <span className="flex items-center"><Award className="w-3 h-3 mr-2 text-red-600" /> ISO 9001:2015 Certified</span>
          </div>
          <div className="flex items-center space-x-6">
            <a href="tel:+918008530606" className="flex items-center hover:text-white transition"><Phone className="w-3 h-3 mr-2" /> +91 80085 30606</a>
          </div>
        </div>
      </div>

      <header className={`sticky top-0 z-50 transition-all duration-300 w-full ${isScrolled ? 'bg-white/95 backdrop-blur-md shadow-lg py-3' : 'bg-transparent py-5'}`}>
        <div className="max-w-[1400px] mx-auto px-4 sm:px-6">
          <div className="flex justify-between items-center">
            <a href="/" className="flex items-center group">
              <div className="w-10 h-10 bg-black rounded-lg flex items-center justify-center mr-3 shadow-lg group-hover:bg-red-600 transition duration-300">
                <span className="text-white font-black text-xl">VR</span>
              </div>
              <div className="flex flex-col">
                <span className={`text-2xl font-extrabold leading-none tracking-tight group-hover:text-red-600 transition-colors ${isScrolled ? 'text-black' : 'text-slate-900 lg:text-white'}`}>VR HERE</span>
                <span className="text-[10px] font-bold text-red-600 uppercase tracking-widest mt-0.5">Business Solutions</span>
              </div>
            </a>

            <nav className="hidden lg:flex items-center space-x-2">
              <a href="/" className={`px-4 py-2 text-sm font-bold rounded-full transition-all ${isScrolled ? 'text-slate-700 hover:bg-slate-100' : 'text-white hover:bg-white/10'}`}>Home</a>
              <a href="/pvt-ltd-registration" className={`px-4 py-2 text-sm font-bold rounded-full transition-all ${isScrolled ? 'text-slate-700 hover:bg-slate-100' : 'text-white hover:bg-white/10'}`}>Company Reg</a>
              <a href="#services" className={`px-4 py-2 text-sm font-bold rounded-full transition-all ${isScrolled ? 'text-slate-700 hover:bg-slate-100' : 'text-white hover:bg-white/10'}`}>All Services</a>
              <button className="ml-4 bg-red-600 hover:bg-red-700 text-white px-6 py-2.5 rounded-lg font-bold text-sm transition shadow-lg shadow-red-600/20 transform hover:-translate-y-1">
                Book Consultation
              </button>
            </nav>

            <button className="lg:hidden p-2 text-slate-800 bg-white rounded-lg" onClick={() => setIsMobileMenuOpen(true)}>
              <Menu className="w-6 h-6" />
            </button>
          </div>
        </div>
      </header>
      {/* MOBILE MENU */}
      <div className={`fixed inset-0 bg-white z-[60] transform transition-transform duration-300 lg:hidden overflow-y-auto ${isMobileMenuOpen ? 'translate-x-0' : 'translate-x-full'}`}>
        <div className="p-4 border-b border-slate-100 flex justify-between items-center sticky top-0 bg-white z-10">
          <span className="font-bold text-lg">Menu</span>
          <button onClick={() => setIsMobileMenuOpen(false)} className="p-2 bg-slate-100 rounded-full"><X className="w-6 h-6" /></button>
        </div>
        <div className="p-4 space-y-4">
          <a href="/" className="block text-lg font-bold">Home</a>
          <a href="/pvt-ltd-registration" className="block text-lg font-bold">Pvt Ltd Registration</a>
        </div>
      </div>
    </>
  );

  return (
    <div className="font-sans text-slate-800 bg-white min-h-screen">
      <Header />

      {/* HERO SECTION */}
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

          {/* SEARCH BAR (Vakilsearch Style) */}
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
          {/* Placeholders for logos (Text for now) */}
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
            {SERVICES_DATA.map((service) => (
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

      <footer className="bg-slate-900 border-t border-slate-800 py-12 text-center">
        <p className="text-slate-500 text-sm">&copy; {new Date().getFullYear()} VR HERE Business Solutions. All rights reserved.</p>
      </footer>
    </div>
  );
};

export default HomePage;