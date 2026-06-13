import React, { useState, useEffect } from 'react';
import {
  Calculator, CheckCircle2, ArrowRight, FileCheck, ShieldCheck, 
  HelpCircle, ChevronDown, Check, Star, User as UsersIcon, 
  RefreshCw, TrendingUp, Info, AlertCircle, FileText, CheckCircle,
  Briefcase, Landmark, ShieldAlert, Award, FileSpreadsheet, Building2,
  Paintbrush, Sparkles, LayoutDashboard, ChevronRight
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { SharedHeader, SharedFooter } from './components/SharedComponents';
import ConsultationPaymentModal from './components/ConsultationPaymentModal';
import { launchRazorpayCheckout } from './utils/razorpayCheckout';
import { showPaymentSuccessPopup } from './utils/paymentSuccessPopup';

/* --- PACKAGES / ITR FILING OPTIONS --- */
const PACKAGES = [
  {
    id: 'consultation',
    name: 'CA Consultation',
    price: 499,
    isAdjustable: true,
    description: 'Talk to an expert CA to plan taxes or clear notices. Fee 100% adjusted in final filing.',
    features: ['30 Mins Expert CA Call', 'Tax Planning & Deductions', 'Notice Clarification', 'Document Checklist Prep', 'Filing Plan Choice'],
    buttonText: 'Book CA Call'
  },
  {
    id: 'itr1',
    name: 'ITR-1 (Sahaj)',
    price: 999,
    customPriceLabel: 'Starts from ₹999',
    description: 'For Salaried Individuals, Single House Property & Interest Income (< ₹50 Lakhs total).',
    features: ['Salary Income & Form 16', 'Single House Property', 'Savings & FD Interest', 'Chapter VI-A Deductions', 'AIS / TIS Matching Check', 'E-Filing Acknowledgement'],
    buttonText: 'File ITR-1'
  },
  {
    id: 'itr4',
    name: 'ITR-4 (Sugam)',
    price: 1899,
    customPriceLabel: 'Starts from ₹1,899',
    description: 'For Resident Individuals/HUFs/Firms with Presumptive Business Income (Sec 44AD/44ADA).',
    features: ['Presumptive Taxation scheme', 'Total Income up to ₹50L', 'Small Business / Professionals', 'Deduction & Relief Review', 'Tax Liability Optimization', 'Secure Return Submission'],
    buttonText: 'File ITR-4'
  },
  {
    id: 'itr2',
    name: 'ITR-2 (Premium)',
    price: 1699,
    customPriceLabel: 'Starts from ₹1,699',
    description: 'For individuals with Capital Gains, Multiple Houses, Foreign Income, or holding Directorship.',
    features: ['Equity & Mutual Fund Profits', 'Crypto & VDAs Treatment', 'Multiple House Properties', 'Unlisted Share / Directorship', 'Foreign Asset Declarations', 'Relief under Section 90/91'],
    buttonText: 'File ITR-2'
  },
  {
    id: 'itr3',
    name: 'ITR-3 (Business)',
    price: 3499,
    customPriceLabel: 'Starts from ₹3,499',
    description: 'For Individuals & HUFs having business profits/profession income (without audited financials).',
    features: ['F&O and Intraday Trading', 'Sole Proprietorship Income', 'Depreciation & Expenses Claim', 'Set-off & Carry Forward Losses', 'Balance Sheet Drafting Assistance', 'Expert Audit-Ready Files'],
    buttonText: 'File ITR-3'
  },
  {
    id: 'itr5',
    name: 'ITR-5 (LLP & Firm)',
    price: 6999,
    customPriceLabel: 'Starts from ₹6,999',
    description: 'For Partnership Firms, LLPs, AOPs, BOIs, and Co-operative societies.',
    features: ['Partnership Deed Compliance', 'Partner Salary & Interest Calc', 'Business Income Audits support', 'Asset Depreciation schedules', 'Tax Computation Sheets', 'Corporate Compliance check'],
    buttonText: 'File ITR-5'
  },
  {
    id: 'itr6',
    name: 'ITR-6 (Corporate)',
    price: 7999,
    customPriceLabel: 'Starts from ₹7,999',
    description: 'For registered companies other than charitable/religious institutions (Non-Section 8).',
    features: ['MCA Financial Matching', 'Minimum Alternate Tax (MAT)', 'Deferred Tax Treatment', 'Director Compliances mapping', 'Audit Report Attachment', 'Complete Balance Sheet Filing'],
    buttonText: 'File ITR-6'
  },
  {
    id: 'itr7',
    name: 'ITR-7 (NGOs & Trusts)',
    price: 6999,
    customPriceLabel: 'Starts from ₹6,999',
    description: 'For Trusts, NGOs, Political Parties, and Charitable Institutions claiming tax exemption.',
    features: ['Section 11, 12A, 10(23C) claims', 'Foreign Contribution mapping', 'Income/Application of Funds', 'Audit Form 10B/10BB matching', 'Exemption verification', 'NGO Darpan compliance check'],
    buttonText: 'File ITR-7'
  }
];

const TRUST_LOGOS = [
  { name: 'Income Tax Certified CAs', icon: ShieldCheck, color: 'text-indigo-600' },
  { name: '100% Secure Uploads', icon: FileCheck, color: 'text-emerald-500' },
  { name: 'Expert CA Computation', icon: Calculator, color: 'text-orange-500' },
  { name: 'Govt Portal Integration', icon: Landmark, color: 'text-blue-500' },
  { name: 'Maximum Refund Guarantee', icon: TrendingUp, color: 'text-red-500' }
];

const CUSTOMER_REVIEWS = [
  {
    name: "Sunil Deshpande",
    occupation: "Senior Software Engineer",
    avatar: "SD",
    rating: 5,
    date: "May 2026",
    text: "Filing ITR-2 was always a pain with my equity trading and double house property. The CA at VR HERE matched everything with AIS/TIS flawlessly and claimed an extra refund of ₹12,000 which I missed last year!",
    verified: true
  },
  {
    name: "Dr. Kavitha Nair",
    occupation: "Consulting Pediatrician",
    avatar: "KN",
    rating: 5,
    date: "May 2026",
    text: "Highly recommended for professionals. I filed my presumptive ITR-4 under Section 44ADA. Excellent dashboard, quick secure upload, and very knowledgeable CAs. 10/10 service.",
    verified: true
  },
  {
    name: "Rahul & Associates LLP",
    occupation: "Partnership Firm",
    avatar: "RA",
    rating: 5,
    date: "April 2026",
    text: "We used their ITR-5 corporate return package. The speed, accuracy, and clear breakdown of partner interest and salary calculations were top tier. Perfect compliance at a great price.",
    verified: true
  }
];

const STEPS = [
  {
    number: "01",
    title: "Document Upload & Checklist",
    desc: "Provide basic details, Form 16, and bank statements in our secure portal. Our interface guides you through exactly what is required.",
    badge: "Takes 5 Mins"
  },
  {
    number: "02",
    title: "Draft Computation & Review",
    desc: "A dedicated chartered accountant reviews your assets, cross-checks AIS/TIS data, drafts the optimal tax computation, and sends it for your approval.",
    badge: "Done in 24 Hrs"
  },
  {
    number: "03",
    title: "Secure E-Filing & Receipt",
    desc: "After your final sign-off, we securely submit the return to the Income Tax Department and send the official ITR-V filing acknowledgement to your inbox.",
    badge: "Instant Acknowledgment"
  }
];

const FAQS = [
  {
    q: "What is AIS and TIS, and why is matching it crucial?",
    a: "Annual Information Statement (AIS) and Taxpayer Information Summary (TIS) are comprehensive government reports containing details of all financial transactions like mutual fund purchases, equity sales, credit card expenses, and salary. VR HERE CAs perform 100% matching against your files to avoid tax discrepancy notices."
  },
  {
    q: "Is the ₹499 consultation fee really refundable?",
    a: "Absolutely. If you pay ₹499 for a CA consultation to clarify a tax query, that entire amount is issued as a credit coupon. When you file any ITR with us, the ₹499 is automatically deducted from your final filing fee."
  },
  {
    q: "Can I switch between Old and New Tax Regimes?",
    a: "Yes! During our CA review process, we compute your liabilities under both regimes (Section 115BAC) side-by-side. We then recommend the regime that yields the maximum refund or lowest tax liability before filing."
  },
  {
    q: "What documents are required to file ITR-1?",
    a: "You simply need your PAN, Aadhaar, Form 16 from your employer, bank statement showing interest income, and proof of any deductions you wish to claim (like 80C, 80D, or home loan interest certificates)."
  },
  {
    q: "How safe is my financial data with VR HERE?",
    a: "We prioritize your privacy above all. All files uploaded to our document vault are protected by bank-grade SSL encryption and accessed solely by the assigned CA working on your compliance files."
  }
];

const RELATED_SERVICES = [
  {
    title: "Private Limited Registration",
    price: "₹6,499",
    desc: "Launch your startup with the most credible legal structure. Get Certificate of Incorporation, PAN, TAN & MOA/AOA.",
    link: "/pvt-ltd-registration"
  },
  {
    title: "Partnership Firm",
    price: "₹4,899",
    desc: "Form your partnership firm quickly with notary deed drafting, PAN & TAN, and firm registration.",
    link: "/partnership-firm"
  },
  {
    title: "GST Registration & Filing",
    price: "₹2,569",
    desc: "Get your GSTIN quickly and ensure smooth tax compliance. Highly recommended for e-commerce and vendors.",
    link: "/gst-registration"
  },
  {
    title: "Accounting & Bookkeeping",
    price: "₹3,999",
    desc: "Let professional CAs handle your day-to-day accounts, ledger entries, bank reconciliation and compliance.",
    link: "/accounting-services"
  }
];

const IncomeTaxPage = () => {
  const navigate = useNavigate();
  
  // Staff Authorization Banner Setup
  const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
  const isAuthorized = userInfo && (userInfo.role === 'admin' || userInfo.role === 'employee');

  const [isScrolled, setIsScrolled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [activeFaq, setActiveFaq] = useState(null);
  const [isSeoExpanded, setIsSeoExpanded] = useState(false);

  /* --- Interactive ITR Finder Tool State --- */
  const [incomeSalary, setIncomeSalary] = useState(false);
  const [incomeCapitalGains, setIncomeCapitalGains] = useState(false);
  const [incomeBusiness, setIncomeBusiness] = useState(false);
  const [businessPresumptive, setBusinessPresumptive] = useState(false);
  const [isCompanyOrLLP, setIsCompanyOrLLP] = useState('individual'); // 'individual', 'llp', 'company', 'ngo'
  const [recommendedItr, setRecommendedItr] = useState(null);

  useEffect(() => {
    const timer = setTimeout(() => setLoading(false), 1200);
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => {
      window.removeEventListener('scroll', handleScroll);
      clearTimeout(timer);
    };
  }, []);

  // Determine/Recommend ITR based on states
  useEffect(() => {
    if (isCompanyOrLLP === 'llp') {
      setRecommendedItr(PACKAGES.find(p => p.id === 'itr5'));
    } else if (isCompanyOrLLP === 'company') {
      setRecommendedItr(PACKAGES.find(p => p.id === 'itr6'));
    } else if (isCompanyOrLLP === 'ngo') {
      setRecommendedItr(PACKAGES.find(p => p.id === 'itr7'));
    } else {
      // Individual logic
      if (incomeBusiness) {
        if (businessPresumptive) {
          setRecommendedItr(PACKAGES.find(p => p.id === 'itr4'));
        } else {
          setRecommendedItr(PACKAGES.find(p => p.id === 'itr3'));
        }
      } else if (incomeCapitalGains) {
        setRecommendedItr(PACKAGES.find(p => p.id === 'itr2'));
      } else {
        setRecommendedItr(PACKAGES.find(p => p.id === 'itr1'));
      }
    }
  }, [incomeSalary, incomeCapitalGains, incomeBusiness, businessPresumptive, isCompanyOrLLP]);

  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: ''
  });

  const handleConsultationBook = () => {
    setSelectedPlan(PACKAGES[0]);
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
    const userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
    setFormData(submittedFormData);

    launchRazorpayCheckout({
      serviceName: `ITR Filing (${selectedPlan?.name})`,
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
        if (requiresEmailLogin) {
          navigate('/login');
        } else if (selectedPlan?.id !== 'consultation') {
          navigate(`/income-tax-assessment?orderId=${data?.order?._id}`);
        } else {
          navigate('/customer-dashboard');
        }
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
        <div className="w-20 h-20 bg-slate-900 rounded-2xl flex items-center justify-center mb-6 animate-bounce">
          <span className="text-white font-black text-3xl">VR</span>
        </div>
        <div className="flex items-center space-x-2 text-sm font-bold tracking-widest text-slate-400">
          LOADING SECURE TAX PORTAL...
        </div>
      </div>
    );
  }

  return (
    <div className={`font-sans text-slate-800 bg-white min-h-screen selection:bg-red-100 selection:text-red-900 overflow-x-hidden ${isAuthorized ? 'pt-14' : ''}`}>
      
      {/* Staff Panel Navigation Header */}
      {isAuthorized && (
        <div className="fixed top-0 left-0 right-0 z-[100] h-14 bg-slate-900 border-b border-indigo-500/20 text-white px-6 flex items-center justify-between shadow-lg font-sans animate-fade-in">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 bg-gradient-to-br from-indigo-600 to-blue-500 rounded-lg flex items-center justify-center text-white font-bold text-sm shadow">
              VR
            </div>
            <div className="flex flex-col">
              <span className="text-xs font-black uppercase tracking-wider text-slate-100">VR Here Staff Panel</span>
              <span className="text-[9px] font-bold uppercase tracking-widest text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-ping"></span>
                <span>Active Session ({userInfo?.role})</span>
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate(userInfo?.role === 'admin' ? '/admin' : '/employee')}
              className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-4 py-2 rounded-lg text-xs font-black uppercase tracking-wider transition flex items-center gap-1.5"
            >
              <LayoutDashboard className="w-3.5 h-3.5" />
              <span>Back to Dashboard</span>
            </button>
          </div>
        </div>
      )}

      <SharedHeader isScrolled={isScrolled} />
      
      <ConsultationPaymentModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        selectedPlan={selectedPlan}
        initialFormData={formData}
        onSubmit={handleFormSubmit}
        isSubmitting={isSubmitting}
        formatCurrency={formatCurrency}
        title={selectedPlan?.id === 'consultation' ? 'Book CA Consultation' : 'Start ITR Filing'}
        nonAdjustableNote="+ Professional Fees & Taxes"
        initialTermsAccepted={false}
      />

      <div className="animate-fade-in">
        
        {/* 1. HERO SECTION */}
        <div className="relative pt-20 pb-20 lg:pt-28 lg:pb-36 bg-slate-900 text-white overflow-hidden">
          <div className="absolute top-0 right-0 w-1/2 h-full bg-red-600/10 skew-x-12 opacity-80 z-0 translate-x-1/3"></div>
          <div className="absolute -top-10 left-10 h-72 w-72 rounded-full bg-orange-600/10 blur-3xl" />
          
          <div className="max-w-7xl mx-auto px-4 relative z-10 flex flex-col lg:flex-row items-center gap-12">
            <div className="lg:w-7/12">
              <div className="inline-flex items-center px-4 py-1.5 rounded-full bg-white/5 border border-white/10 shadow-sm text-xs font-bold text-orange-400 mb-6 uppercase tracking-wider">
                <span className="w-2 h-2 bg-emerald-500 rounded-full mr-2 animate-pulse"></span>
                FY 2025-26 (AY 2026-27) Filing is Live
              </div>
              <h1 className="text-4xl lg:text-6xl font-black tracking-tight leading-[1.1] mb-6">
                File Your <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-orange-400">Income Tax Return</span> Accurately with Expert CAs.
              </h1>
              <p className="text-lg lg:text-xl text-slate-300 leading-relaxed mb-8">
                From Salaried individuals to Corporates, get your ITR verified and e-filed securely. Claim your maximum refund, match AIS/TIS flawlessly, and secure zero-rejection peace of mind.
              </p>

              <div className="flex flex-col sm:flex-row gap-4 mb-8">
                <a href="#packages-section" className="bg-red-600 text-white px-8 py-4 rounded-xl font-bold text-lg hover:bg-red-700 transition shadow-xl shadow-red-600/20 transform hover:-translate-y-1 active:scale-95 text-center flex items-center justify-center">
                  Select ITR Plan <ArrowRight className="ml-2 w-5 h-5" />
                </a>
                <button onClick={handleConsultationBook} className="bg-white/10 border border-white/20 text-white px-8 py-4 rounded-xl font-bold text-lg hover:bg-white/20 transition flex items-center justify-center">
                  Book CA consultation @ ₹499
                </button>
              </div>
              
              <div className="flex items-center space-x-6 text-xs text-slate-400 font-medium">
                <span className="flex items-center gap-1.5"><ShieldCheck className="w-4 h-4 text-emerald-500" /> Government Registered</span>
                <span className="flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4 text-emerald-500" /> Fee Adjustable in Filing</span>
              </div>
            </div>

            {/* Hero Graphic Card */}
            <div className="lg:w-5/12 relative w-full">
              <div className="relative z-10 bg-slate-800 p-8 rounded-3xl shadow-2xl border border-slate-700/50 transform lg:rotate-2 hover:rotate-0 transition duration-500">
                <div className="flex justify-between items-start mb-6">
                  <div>
                    <h3 className="text-xl font-bold text-white">Guaranteed Accuracy</h3>
                    <p className="text-slate-400 text-xs">Direct API filing assistance</p>
                  </div>
                  <div className="bg-orange-500/20 text-orange-400 font-bold px-3 py-1 rounded text-[10px] tracking-widest uppercase">
                    100% Tax Compliant
                  </div>
                </div>
                
                <div className="space-y-4">
                  {[
                    { label: 'AIS & TIS Double-Check Verification', icon: CheckCircle },
                    { label: 'Maximum Deduction Claims (80C to 80U)', icon: TrendingUp },
                    { label: 'Expert CA review before final submit', icon: ShieldCheck },
                    { label: 'Full support for foreign assets & losses', icon: Award }
                  ].map((item, i) => (
                    <div key={i} className="flex items-center p-3.5 bg-slate-900/50 rounded-xl border border-slate-700/30">
                      <item.icon className="w-5 h-5 text-red-500 mr-3 flex-shrink-0" />
                      <span className="font-semibold text-slate-300 text-sm">{item.label}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[110%] h-[110%] bg-gradient-to-tr from-red-600/20 to-orange-500/10 rounded-full blur-3xl -z-10 opacity-70"></div>
            </div>
          </div>
        </div>

        {/* 2. DYNAMIC TRUST BAR */}
        <div className="bg-slate-100 py-10 border-b border-slate-200">
          <div className="max-w-7xl mx-auto px-4 text-center mb-6">
            <p className="text-xs uppercase font-black tracking-widest text-slate-500">Filing Platform Trust & Security Standard</p>
          </div>
          <div className="max-w-7xl mx-auto px-4 flex flex-wrap justify-center gap-6 lg:gap-12">
            {TRUST_LOGOS.map((logo, idx) => (
              <div key={idx} className="flex items-center gap-2.5 px-5 py-3 bg-white rounded-2xl border border-slate-200/60 shadow-sm">
                <logo.icon className={`w-5 h-5 ${logo.color}`} />
                <span className="text-xs font-black tracking-tight text-slate-700">{logo.name}</span>
              </div>
            ))}
          </div>
        </div>

        {/* 3. DYNAMIC INTERACTIVE ITR FINDER (CREATIVE & INTERACTIVE) */}
        <section className="py-20 bg-white">
          <div className="max-w-4xl mx-auto px-4">
            <div className="text-center mb-12">
              <span className="text-xs uppercase font-black tracking-widest text-red-600 bg-red-50 px-3 py-1.5 rounded-full font-bold">Interactive Tool</span>
              <h2 className="text-3xl lg:text-4xl font-black text-slate-900 mt-4 tracking-tight">Not Sure Which ITR to File?</h2>
              <p className="text-slate-600 font-medium mt-1">Answer 3 quick questions and let our dynamic finder choose for you.</p>
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-3xl p-8 shadow-sm">
              <div className="space-y-6">
                
                {/* Question 1 */}
                <div>
                  <label className="block text-sm font-black text-slate-900 uppercase tracking-wider mb-3">1. Select Entity Type:</label>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {[
                      { id: 'individual', label: 'Individual / HUF', desc: 'Salaried, Trader, etc' },
                      { id: 'llp', label: 'LLP / Firm', desc: 'Partnership business' },
                      { id: 'company', label: 'Company', desc: 'Pvt Ltd, Ltd Companies' },
                      { id: 'ngo', label: 'NGO / Trust', desc: 'Charitable Institution' }
                    ].map((opt) => (
                      <button
                        key={opt.id}
                        onClick={() => setIsCompanyOrLLP(opt.id)}
                        className={`p-4 rounded-xl border text-left transition ${isCompanyOrLLP === opt.id ? 'border-red-600 bg-red-50/50 shadow-md ring-2 ring-red-500/20' : 'border-slate-200 bg-white hover:border-slate-300'}`}
                      >
                        <div className="font-bold text-sm text-slate-900">{opt.label}</div>
                        <div className="text-[10px] text-slate-500 mt-1 font-semibold">{opt.desc}</div>
                      </button>
                    ))}
                  </div>
                </div>

                {isCompanyOrLLP === 'individual' && (
                  <>
                    {/* Question 2 */}
                    <div className="pt-4 border-t border-slate-200">
                      <label className="block text-sm font-black text-slate-900 uppercase tracking-wider mb-3">2. What are your income sources? (Select all that apply):</label>
                      <div className="grid md:grid-cols-3 gap-3">
                        <button
                          onClick={() => setIncomeSalary(!incomeSalary)}
                          className={`p-4 rounded-xl border text-left transition flex items-center justify-between ${incomeSalary ? 'border-red-600 bg-red-50/30' : 'border-slate-200 bg-white'}`}
                        >
                          <div>
                            <div className="font-bold text-sm text-slate-900">Salaried / Pensioner</div>
                            <div className="text-[10px] text-slate-500 mt-0.5 font-semibold">Form 16 / Single House</div>
                          </div>
                          <input type="checkbox" checked={incomeSalary} readOnly className="h-4 w-4 accent-red-600" />
                        </button>

                        <button
                          onClick={() => setIncomeCapitalGains(!incomeCapitalGains)}
                          className={`p-4 rounded-xl border text-left transition flex items-center justify-between ${incomeCapitalGains ? 'border-red-600 bg-red-50/30' : 'border-slate-200 bg-white'}`}
                        >
                          <div>
                            <div className="font-bold text-sm text-slate-900">Capital Gains / Shares</div>
                            <div className="text-[10px] text-slate-500 mt-0.5 font-semibold">Stocks, VDA, Property Gains</div>
                          </div>
                          <input type="checkbox" checked={incomeCapitalGains} readOnly className="h-4 w-4 accent-red-600" />
                        </button>

                        <button
                          onClick={() => setIncomeBusiness(!incomeBusiness)}
                          className={`p-4 rounded-xl border text-left transition flex items-center justify-between ${incomeBusiness ? 'border-red-600 bg-red-50/30' : 'border-slate-200 bg-white'}`}
                        >
                          <div>
                            <div className="font-bold text-sm text-slate-900">Business / Profession</div>
                            <div className="text-[10px] text-slate-500 mt-0.5 font-semibold">Proprietorship, Freelance, F&O</div>
                          </div>
                          <input type="checkbox" checked={incomeBusiness} readOnly className="h-4 w-4 accent-red-600" />
                        </button>
                      </div>
                    </div>

                    {/* Question 3 (Conditional) */}
                    {incomeBusiness && (
                      <div className="pt-4 border-t border-slate-200">
                        <label className="block text-sm font-black text-slate-900 uppercase tracking-wider mb-3">3. Do you wish to file under Presumptive Taxation (Sec 44AD / 44ADA)?</label>
                        <div className="grid grid-cols-2 gap-3 max-w-md">
                          <button
                            onClick={() => setBusinessPresumptive(true)}
                            className={`p-4 rounded-xl border text-left transition ${businessPresumptive ? 'border-red-600 bg-red-50/30' : 'border-slate-200 bg-white'}`}
                          >
                            <div className="font-bold text-sm text-slate-900">Yes (Sugam Scheme)</div>
                            <div className="text-[10px] text-slate-500 mt-0.5 font-semibold">No need to maintain full accounts</div>
                          </button>
                          <button
                            onClick={() => setBusinessPresumptive(false)}
                            className={`p-4 rounded-xl border text-left transition ${!businessPresumptive ? 'border-red-600 bg-red-50/30' : 'border-slate-200 bg-white'}`}
                          >
                            <div className="font-bold text-sm text-slate-900">No (ITR-3 Business)</div>
                            <div className="text-[10px] text-slate-500 mt-0.5 font-semibold">For F&O, full P&L balance sheet</div>
                          </button>
                        </div>
                      </div>
                    )}
                  </>
                )}

                {/* RECOMMENDATION RESULT */}
                {recommendedItr && (
                  <div className="mt-8 p-6 bg-gradient-to-r from-slate-900 to-slate-800 text-white rounded-2xl border border-slate-700/60 shadow-xl flex flex-col md:flex-row items-center justify-between gap-6">
                    <div className="flex items-start gap-4">
                      <div className="p-3 bg-red-600 rounded-xl text-white mt-1">
                        <FileText className="w-7 h-7" />
                      </div>
                      <div>
                        <div className="text-[10px] text-red-400 uppercase font-black tracking-widest mb-1">Recommended Plan</div>
                        <h4 className="text-xl font-bold">{recommendedItr.name} Filing</h4>
                        <p className="text-xs text-slate-300 mt-1 max-w-md">{recommendedItr.description}</p>
                        <div className="mt-2 text-lg font-black text-white">
                          Filing Fee: {recommendedItr.customPriceLabel || formatCurrency(recommendedItr.price)}
                        </div>
                      </div>
                    </div>
                    <button 
                      onClick={() => handleSelectPlan(recommendedItr)} 
                      className="bg-red-600 hover:bg-red-700 text-white font-bold px-6 py-3.5 rounded-xl transition transform active:scale-95 flex items-center justify-center gap-2 whitespace-nowrap shadow-lg shadow-red-600/30"
                    >
                      <span>Proceed with {recommendedItr.name}</span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>
                )}

              </div>
            </div>
          </div>
        </section>

        {/* 4. PRICING & PACKAGES SECTION */}
        <section id="packages-section" className="py-20 bg-slate-50 border-t border-slate-200">
          <div className="max-w-7xl mx-auto px-4">
            <div className="text-center mb-16">
              <span className="text-xs uppercase font-black tracking-widest text-red-600 bg-red-50 px-3 py-1.5 rounded-full font-bold">Standard Packages</span>
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mt-4 tracking-tight">Return Filing Fees & Categories</h2>
              <p className="text-slate-600 font-medium mt-1">Transparent professional pricing. Clear scope with expert Chartered Accountant allocation.</p>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-[1400px] mx-auto">
              {PACKAGES.map((pkg) => (
                <div 
                  key={pkg.id} 
                  className={`bg-white rounded-3xl p-7 border transition-all duration-300 flex flex-col relative transform hover:-translate-y-3 hover:shadow-2xl ${pkg.isAdjustable ? 'border-orange-500 shadow-lg' : 'border-slate-200 hover:border-red-300 shadow-sm'}`}
                >
                  {pkg.id === 'itr1' && <div className="absolute top-0 right-0 bg-red-600 text-white text-[9px] font-black uppercase tracking-wider px-3 py-1 rounded-bl-lg rounded-tr-3xl shadow-sm">MOST POPULAR</div>}
                  {pkg.isAdjustable && <div className="absolute top-0 right-0 bg-orange-600 text-white text-[9px] font-black uppercase tracking-wider px-3 py-1 rounded-bl-lg rounded-tr-3xl shadow-sm">RECOMMENDED</div>}

                  <h3 className="text-lg font-black text-slate-900 mb-1">{pkg.name}</h3>
                  <div className="text-3xl font-black text-slate-900 mb-4">
                    {pkg.customPriceLabel || formatCurrency(pkg.price)}
                    <span className="text-[9px] font-bold text-slate-400 ml-1 block mt-0.5">
                      {pkg.isAdjustable ? '(Fully Refundable / Adjustable)' : '+ Taxes & Portal Fees'}
                    </span>
                  </div>

                  {pkg.isAdjustable && (
                    <div className="bg-green-50 text-green-700 text-[10px] font-black p-2.5 rounded-xl mb-4 flex items-center">
                      <RefreshCw className="w-3.5 h-3.5 mr-1.5 animate-spin-slow" /> Adjusted in final filing bill
                    </div>
                  )}

                  <p className="text-xs text-slate-500 mb-5 leading-relaxed font-medium">{pkg.description}</p>

                  <div className="space-y-3.5 mb-6 flex-1 border-t border-slate-100 pt-5">
                    {pkg.features.map((feat, i) => (
                      <div key={i} className="flex items-start text-xs text-slate-700 font-semibold group">
                        <CheckCircle2 className="w-4 h-4 text-green-500 mr-2 mt-0.5 flex-shrink-0 group-hover:scale-125 transition-transform" />
                        <span>{feat}</span>
                      </div>
                    ))}
                  </div>
                  
                  <button 
                    onClick={() => handleSelectPlan(pkg)} 
                    className={`w-full py-3.5 rounded-xl font-bold transition transform active:scale-95 text-sm ${pkg.isAdjustable || pkg.id === 'itr1' ? 'bg-red-600 text-white hover:bg-red-700 shadow-md shadow-red-600/20' : 'bg-slate-100 text-slate-900 hover:bg-slate-200'}`}
                  >
                    {pkg.buttonText}
                  </button>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 5. REDESIGNED HOW IT WORKS TIMELINE */}
        <section className="py-24 bg-white">
          <div className="max-w-6xl mx-auto px-4">
            <div className="text-center mb-20">
              <span className="text-xs uppercase font-black tracking-widest text-red-600 bg-red-50 px-3 py-1.5 rounded-full font-bold">Process Flow</span>
              <h2 className="text-3xl lg:text-5xl font-black text-slate-900 mt-4 tracking-tight">3-Step Frictionless Return Filing</h2>
              <p className="text-lg text-slate-600 mt-2 font-medium">Save hours of filing stress. Enjoy compliance verification by dedicated CAs.</p>
            </div>
            
            <div className="grid md:grid-cols-3 gap-8 relative z-10">
              <div className="hidden md:block absolute top-[68px] left-0 w-full h-1 bg-gradient-to-r from-red-100 via-orange-200 to-red-100 -z-10"></div>
              {STEPS.map((step, i) => (
                <div key={i} className="bg-white p-8 rounded-3xl shadow-xl border border-slate-100 text-center hover:-translate-y-2 transition-all duration-300 relative group">
                  <div className="w-16 h-16 bg-gradient-to-br from-red-600 to-orange-600 text-white rounded-2xl flex items-center justify-center text-2xl font-black mx-auto mb-6 shadow-xl shadow-red-600/20 transform group-hover:rotate-6 transition-all border-4 border-white">{step.number}</div>
                  <div className="inline-block px-3 py-1 bg-slate-50 border border-slate-100 rounded-full text-[10px] font-black uppercase text-slate-500 mb-4">{step.badge}</div>
                  <h3 className="font-bold text-xl text-slate-900 mb-3 tracking-tight">{step.title}</h3>
                  <p className="text-slate-600 text-sm leading-relaxed font-medium">{step.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 6. SUCCESS STORIES (CUSTOMER REVIEWS) */}
        <section className="py-20 bg-slate-900 text-white border-y border-slate-800">
          <div className="max-w-7xl mx-auto px-4">
            <div className="text-center mb-16">
              <span className="text-xs uppercase font-black tracking-widest text-red-400 bg-white/5 px-3 py-1.5 rounded-full font-bold">User Testimonials</span>
              <h2 className="text-3xl lg:text-5xl font-black text-white mt-4 tracking-tight">Trusted by 15,000+ Assessees</h2>
              <p className="text-lg text-slate-400 mt-2 font-medium">Read feedback from our individual, professional, and corporate clients.</p>
            </div>
            
            <div className="grid md:grid-cols-3 gap-6">
              {CUSTOMER_REVIEWS.map((review, idx) => (
                <div key={idx} className="bg-slate-800/40 p-8 rounded-3xl border border-slate-700/30 shadow-sm hover:shadow-md transition flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-1 text-amber-400 mb-4">
                      {[...Array(review.rating)].map((_, i) => (
                        <Star key={i} className="w-4 h-4 fill-current" />
                      ))}
                    </div>
                    <p className="text-slate-300 text-sm leading-relaxed mb-6 font-medium italic">"{review.text}"</p>
                  </div>
                  <div className="flex items-center gap-4 border-t border-slate-800 pt-4 mt-auto">
                    <div className="w-10 h-10 bg-gradient-to-br from-red-500 to-orange-500 rounded-full flex items-center justify-center text-white font-black text-xs shadow-sm">
                      {review.avatar}
                    </div>
                    <div>
                      <div className="flex items-center gap-1.5">
                        <h4 className="font-bold text-slate-100 text-sm">{review.name}</h4>
                        {review.verified && <CheckCircle className="w-3.5 h-3.5 text-emerald-500" title="Verified Customer" />}
                      </div>
                      <p className="text-slate-400 text-[10px] font-black uppercase tracking-wider">{review.occupation}</p>
                      <p className="text-[9px] text-slate-500 font-bold mt-0.5">{review.date}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 7. EXPANDING SEO SECTION (DETAILED TAX GUIDE & FAQS FOR SEARCH DISCOVERY) */}
        <section className="py-12 bg-white">
          <div className="max-w-7xl mx-auto px-4 text-center">
            <button 
              onClick={() => setIsSeoExpanded(!isSeoExpanded)}
              className="inline-flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-white px-8 py-4 rounded-xl font-bold transition shadow-xl active:scale-95 text-sm"
            >
              <span>{isSeoExpanded ? 'Hide Comprehensive Filing Guide & FAQs' : 'View Comprehensive Filing Guide & FAQs'}</span>
              <ChevronDown className={`w-5 h-5 transition-transform duration-300 ${isSeoExpanded ? 'rotate-180' : ''}`} />
            </button>

            {isSeoExpanded && (
              <div className="mt-12 text-left bg-slate-50 p-8 md:p-12 rounded-3xl border border-slate-200 animate-in fade-in slide-in-from-top-4 duration-300 grid grid-cols-1 lg:grid-cols-3 gap-12">
                
                {/* Column A: Detailed Guide */}
                <div className="lg:col-span-1 space-y-6 max-h-[500px] overflow-y-auto pr-4 scrollbar-thin scrollbar-thumb-slate-300">
                  <h3 className="text-xl font-black text-slate-900 border-b-2 border-red-500 pb-2">Complete Guide to ITR Filing</h3>
                  
                  <div className="space-y-4">
                    <p className="text-xs text-slate-600 leading-relaxed font-semibold">
                      An <strong>Income Tax Return (ITR)</strong> is the structured document filed to the Income Tax Department containing disclosures of income, asset details, deductions claimed, and net tax liabilities under the <strong>Income-tax Act, 1961</strong>.
                    </p>

                    <div>
                      <h4 className="text-xs font-black uppercase text-slate-950 tracking-wide mb-1.5">Who Must File an ITR in India?</h4>
                      <p className="text-[11px] text-slate-500 leading-relaxed font-medium">
                        Filing return is statutory for individuals whose gross total income exceeds the basic exemption limit (₹2.5 Lakhs to ₹3 Lakhs depending on the chosen tax regime and age). Additionally, individuals holding foreign assets, earning from overseas, claiming double tax relief, or who have paid electricity bills exceeding ₹1 Lakh, or deposited more than ₹1 Crore in current accounts are legally bound to file.
                      </p>
                    </div>

                    <div>
                      <h4 className="text-xs font-black uppercase text-slate-950 tracking-wide mb-1.5">Detailed ITR Form Categorization</h4>
                      <ul className="text-[11px] text-slate-500 space-y-2 font-medium">
                        <li><strong>ITR-1 (Sahaj):</strong> For individuals having salary, single house, interest or other income, totaling less than ₹50 Lakhs.</li>
                        <li><strong>ITR-2:</strong> For those with capital gains from mutual funds or stocks, multiple houses, foreign assets, or company directorships.</li>
                        <li><strong>ITR-3:</strong> For individuals/HUFs with proprietary businesses, freelance business income, or F&O/trading.</li>
                        <li><strong>ITR-4 (Sugam):</strong> For presumptive business/profession schemes (Sec 44AD/44ADA) with income under ₹50 Lakhs.</li>
                        <li><strong>ITR-5:</strong> For Partnership firms, LLPs, AOPs, and societies.</li>
                        <li><strong>ITR-6:</strong> For registered companies excluding charitable organizations.</li>
                        <li><strong>ITR-7:</strong> For scientific research institutions, political parties, NGOs, and trusts.</li>
                      </ul>
                    </div>

                    <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-inner">
                      <h4 className="text-xs font-black uppercase text-slate-950 tracking-wide mb-2">Checklist of Documents Needed</h4>
                      <ul className="text-[10px] text-slate-600 space-y-1.5 font-bold">
                        <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-green-500" /> PAN & Aadhaar (linked correctly)</li>
                        <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-green-500" /> Form 16 & Form 12BA (from employer)</li>
                        <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-green-500" /> Interest Certificates & Bank Statements</li>
                        <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-green-500" /> Capital Gain Statements (from brokers)</li>
                        <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-green-500" /> Investment proofs (80C, 80D, 80G receipts)</li>
                      </ul>
                    </div>
                  </div>
                </div>

                {/* Column B: FAQs */}
                <div className="lg:col-span-1 space-y-4">
                  <h3 className="text-xl font-black text-slate-900 border-b-2 border-orange-500 pb-2 mb-6">Frequently Asked Questions</h3>
                  <div className="space-y-3">
                    {FAQS.map((faq, idx) => (
                      <div key={idx} className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                        <button 
                          onClick={() => setActiveFaq(activeFaq === idx ? null : idx)}
                          className="w-full p-4 flex items-center justify-between text-left font-bold text-sm text-slate-800 hover:bg-slate-50 transition"
                        >
                          <span>{faq.q}</span>
                          <ChevronDown className={`w-4 h-4 text-slate-400 transition-transform flex-shrink-0 ml-2 ${activeFaq === idx ? 'rotate-180' : ''}`} />
                        </button>
                        {activeFaq === idx && (
                          <div className="p-4 border-t border-slate-100 text-xs text-slate-600 leading-relaxed bg-slate-50/50 font-medium">
                            {faq.a}
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
                    {[
                      'ITR Filing Online India', 'Income Tax Return CA Service', 'ITR 1 Sahaj Filing Fee', 
                      'Capital Gains Tax ITR 2', 'Presumptive Taxation Sec 44ADA', 'F&O Losses Return ITR-3', 
                      'LLP Tax Return ITR 5', 'Private Limited ITR 6 Fee', 'Section 12A Trust Return ITR 7',
                      'Tax regime comparison tool', 'AIS TIS mismatch notice help', 'Income tax refund status CA',
                      'Deductions Section 80C 80D limit', 'Cheapest expert tax filing'
                    ].map((tag, idx) => (
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

        {/* 8. New Related Services */}
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

        {/* 9. Consultation CTA Area (Confused about the process?) */}
        <section className="py-24 bg-slate-900 text-white relative overflow-hidden">
          <div className="absolute inset-0 opacity-20 bg-[radial-gradient(#ffffff_1px,transparent_1px)] [background-size:16px_16px]"></div>
          <div className="max-w-4xl mx-auto px-4 text-center relative z-10">
            <h2 className="text-3xl lg:text-5xl font-black mb-6">Confused about the process?</h2>
            <p className="text-xl text-slate-400 mb-10 leading-relaxed font-medium">
              Talk to our experts before you commit. Pay a small booking fee now, and we will deduct it from your final bill.
            </p>
            <div className="bg-white/10 backdrop-blur-md p-8 rounded-3xl border border-white/10 inline-block w-full max-w-md">
              <div className="text-sm font-bold text-red-400 uppercase tracking-widest mb-2 font-black">Consultation Offer</div>
              <div className="text-5xl font-black mb-2">₹499</div>
              <p className="text-slate-300 text-sm mb-6 font-medium">Fully adjustable against filing fees</p>
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

export default IncomeTaxPage;
