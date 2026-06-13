import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';
import { 
  ArrowLeft, ArrowRight, CheckCircle, FileText, 
  Upload, Trash2, ShieldAlert, Award, FileCode, CheckSquare
} from 'lucide-react';

const SECTIONS = [
  { id: 1, name: 'Personal Details & Info', start: 1, end: 6 },
  { id: 2, name: 'Salary & Bank Details', start: 7, end: 14 },
  { id: 3, name: 'Investments & Crypto', start: 15, end: 23 },
  { id: 4, name: 'Property, Income & Deductions', start: 24, end: 37 },
  { id: 5, name: 'TDS, Login & Disclosures', start: 38, end: 51 }
];

const QUESTIONS = [
  // PERSONAL DETAILS
  { id: 1, section: 'PERSONAL DETAILS', text: 'PAN card' },
  { id: 2, section: 'PERSONAL DETAILS', text: 'Aadhaar (12-digit, linked to PAN)' },
  { id: 3, section: 'PERSONAL DETAILS', text: 'Latest residential address' },
  { id: 4, section: 'PERSONAL DETAILS', text: 'Current mobile number (for OTP)' },
  { id: 5, section: 'PERSONAL DETAILS', text: 'Current email ID' },
  { id: 6, section: 'PERSONAL DETAILS', text: 'Bank a/c for refund (IFSC + account no )' },

  // SALARY & EMPLOYMENT
  { id: 7, section: 'SALARY & EMPLOYMENT', text: 'Form 16 (Part A + B) – all employers' },
  { id: 8, section: 'SALARY & EMPLOYMENT', text: 'Salary slips Apr 2025 - Mar 2026' },
  { id: 9, section: 'SALARY & EMPLOYMENT', text: 'HRA / LTA / perquisites details' },

  // BANK STATEMENTS
  { id: 10, section: 'BANK STATEMENTS', text: 'All savings bank a/c statements (Apr 25 – Mar 26)' },
  { id: 11, section: 'BANK STATEMENTS', text: 'All current a/c statements (if any)' },
  { id: 12, section: 'BANK STATEMENTS', text: 'FD / RD interest certificates' },
  { id: 13, section: 'BANK STATEMENTS', text: 'Form 15G / 15H (if submitted)' },

  // DIVIDENDS
  { id: 14, section: 'DIVIDENDS', text: 'Dividend statement – stocks & mutual funds' },

  // STOCKS & SHARES
  { id: 15, section: 'STOCKS & SHARES', text: 'Broker P&L statement (listed shares)' },
  { id: 16, section: 'STOCKS & SHARES', text: 'Capital gains statement — CAMS / KFintech / Zerodha' },
  { id: 17, section: 'STOCKS & SHARES', text: 'Unlisted share details (cost + fair value as on 31-03-26)' },
  { id: 18, section: 'STOCKS & SHARES', text: 'ESOP / RSU details (if exercised or sold)' },

  // MUTUAL FUNDS
  { id: 19, section: 'MUTUAL FUNDS', text: 'Capital gains statement — all platforms' },
  { id: 20, section: 'MUTUAL FUNDS', text: 'ELSS investment proofs (for 80C)' },

  // CRYPTO / VIRTUAL DIGITAL ASSETS (VDA)
  { id: 21, section: 'CRYPTO / VIRTUAL DIGITAL ASSETS (VDA)', text: 'P&L report from all exchanges (WazirX, CoinDCX, Binance etc.)' },
  { id: 22, section: 'CRYPTO / VIRTUAL DIGITAL ASSETS (VDA)', text: 'TDS u/s 194S — verify in AIS / Form 26AS' },
  { id: 23, section: 'CRYPTO / VIRTUAL DIGITAL ASSETS (VDA)', text: 'VDA held at any point in FY (disclose even if not sold)' },

  // PROPERTY & ASSETS
  { id: 24, section: 'PROPERTY & ASSETS', text: 'Sale / purchase deed (if any transaction)' },
  { id: 25, section: 'PROPERTY & ASSETS', text: 'Rental agreements + municipal tax receipts' },
  { id: 26, section: 'PROPERTY & ASSETS', text: 'Gold / jewellery sale documents' },

  // OTHER INCOME
  { id: 27, section: 'OTHER INCOME', text: 'Agricultural income details' },
  { id: 28, section: 'OTHER INCOME', text: 'Freelance / professional receipts' },
  { id: 29, section: 'OTHER INCOME', text: 'Foreign income / remittances received' },
  { id: 30, section: 'OTHER INCOME', text: 'Lottery / winnings income' },

  // TAX SAVINGS — DEDUCTIONS
  { id: 31, section: 'TAX SAVINGS — DEDUCTIONS', text: '80C: PPF, LIC, EPF, school fees' },
  { id: 32, section: 'TAX SAVINGS — DEDUCTIONS', text: '80D: Health insurance premium' },
  { id: 33, section: 'TAX SAVINGS — DEDUCTIONS', text: '80F: Education loan interest certificate' },
  { id: 34, section: 'TAX SAVINGS — DEDUCTIONS', text: '80G: Donation receipts with 80G certificate' },
  { id: 35, section: 'TAX SAVINGS — DEDUCTIONS', text: 'Home loan interest certificate (Sec 24b)' },
  { id: 36, section: 'TAX SAVINGS — DEDUCTIONS', text: 'NPS contribution (80CCD(1B))' },
  { id: 37, section: 'TAX SAVINGS — DEDUCTIONS', text: 'HRA: Rent receipts + landlord PAN (rent > Rs.1 L/yr)' },

  // TDS & TAX PAID
  { id: 38, section: 'TDS & TAX PAID', text: 'AIS (Annual Information Statement) — downloaded & reconciled' },
  { id: 39, section: 'TDS & TAX PAID', text: 'Form 26AS — TDS, advance tax, self-assessment tax' },
  { id: 40, section: 'TDS & TAX PAID', text: 'Advance tax challans (if paid)' },

  // FOREIGN ASSETS (IF APPLICABLE)
  { id: 41, section: 'FOREIGN ASSETS (IF APPLICABLE)', text: 'Foreign shares / bank a/c / property as on 31-03-26' },

  // PORTAL & LOGIN
  { id: 42, section: 'PORTAL & LOGIN', text: 'Income tax e-filing login credentials (incometax.gov.in)' },

  // YES / NO DISCLOSURES
  { id: 43, section: 'YES / NO DISCLOSURES', text: 'Current a/c deposit > Rs.1 Cr during FY?' },
  { id: 44, section: 'YES / NO DISCLOSURES', text: 'Foreign travel expense > Rs.2 L?' },
  { id: 45, section: 'YES / NO DISCLOSURES', text: 'Electricity expense > Rs.1 L?' },
  { id: 46, section: 'YES / NO DISCLOSURES', text: 'Director in any company during FY?' },
  { id: 47, section: 'YES / NO DISCLOSURES', text: 'Unlisted shares held as on 31-03-26?' },
  { id: 48, section: 'YES / NO DISCLOSURES', text: 'Partner in any firm / LLP?' },
  { id: 49, section: 'YES / NO DISCLOSURES', text: 'Foreign shares / assets as on 31-03-26?' },
  { id: 50, section: 'YES / NO DISCLOSURES', text: 'TDS u/s 194N deducted (cash withdrawal)?' },
  { id: 51, section: 'YES / NO DISCLOSURES', text: 'Crypto / VDA held or traded anytime in FY?' }
];

export default function IncomeTaxAssessment() {
  const navigate = useNavigate();
  const orderId = new URLSearchParams(window.location.search).get('orderId') || null;
  const [currentStep, setCurrentStep] = useState(1);
  const [clientName, setClientName] = useState('');
  const [pan, setPan] = useState('');
  const [financialYear] = useState('2025-26');
  const [assessmentYear] = useState('2026-27');
  const [responses, setResponses] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [uploadingItem, setUploadingItem] = useState(null);

  // Authenticated user check
  const [token, setToken] = useState('');
  useEffect(() => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo') || '{}');
    if (userInfo?.token) {
      setToken(userInfo.token);
      setClientName(userInfo.name || '');
    }

    // Initialize responses
    const initialResponses = {};
    QUESTIONS.forEach(q => {
      initialResponses[q.id] = {
        itemId: q.id,
        description: q.text,
        section: q.section,
        value: 'N/A',
        remarks: '',
        documentUrl: null,
        originalFileName: null,
        documents: []
      };
    });
    setResponses(initialResponses);
  }, []);

  const handleResponseChange = (id, field, val) => {
    setResponses(prev => ({
      ...prev,
      [id]: {
        ...prev[id],
        [field]: val
      }
    }));
  };

  const handleFileUpload = async (id, e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploadingItem(id);
    const formData = new FormData();
    formData.append('document', file);

    try {
      const headers = {
        'Content-Type': 'multipart/form-data'
      };
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }
      const config = { headers };
      const { data } = await axios.post('/api/income-tax-assessment/upload', formData, config);
      
      setResponses(prev => {
        const item = prev[id] || {};
        const docs = item.documents || [];
        return {
          ...prev,
          [id]: {
            ...item,
            documents: [...docs, { documentUrl: data.documentUrl, originalFileName: data.originalFileName }]
          }
        };
      });
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to upload document');
    } finally {
      setUploadingItem(null);
    }
  };

  const handleRemoveFile = (id, idx) => {
    setResponses(prev => {
      const item = prev[id] || {};
      const docs = [...(item.documents || [])];
      docs.splice(idx, 1);
      return {
        ...prev,
        [id]: {
          ...item,
          documents: docs
        }
      };
    });
  };

  const validateStep = () => {
    if (currentStep === 1) {
      if (!clientName.trim()) {
        alert('Please enter client name');
        return false;
      }
      if (!pan.trim() || pan.trim().length !== 10) {
        alert('Please enter a valid 10-character PAN');
        return false;
      }
    }
    return true;
  };

  const handleNext = () => {
    if (validateStep()) {
      setCurrentStep(prev => prev + 1);
      window.scrollTo(0, 0);
    }
  };

  const handleBack = () => {
    setCurrentStep(prev => prev - 1);
    window.scrollTo(0, 0);
  };

  const handleSubmit = async () => {
    if (!validateStep()) return;
    setIsSubmitting(true);

    try {
      const headers = {
        'Content-Type': 'application/json'
      };
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }
      const config = { headers };

      const payload = {
        clientName,
        pan,
        financialYear,
        assessmentYear,
        responses: Object.values(responses),
        orderId
      };

      await axios.post('/api/income-tax-assessment', payload, config);
      alert('ITR Filing Checklist submitted successfully!');
      navigate('/dashboard');
    } catch (err) {
      alert(err.response?.data?.message || 'Submission failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const activeSection = SECTIONS.find(s => s.id === currentStep);
  const stepQuestions = QUESTIONS.filter(q => q.id >= activeSection.start && q.id <= activeSection.end);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 font-sans pb-24 selection:bg-indigo-500/10">
      {/* VR Here Brand Header */}
      <header className="bg-white border-b border-slate-100 py-4 shadow-sm mb-8">
        <div className="max-w-4xl mx-auto px-4 flex items-center justify-between">
          <Link to="/" className="flex items-center flex-shrink-0 group cursor-pointer decoration-transparent">
            <img src="/logo.png" alt="VR Here" className="h-12 w-auto object-contain mr-2 transition-transform duration-300 group-hover:scale-105" />
            <div className="flex flex-col">
              <span className="text-2xl font-extrabold text-black leading-none tracking-tight transition-colors group-hover:text-indigo-600">VR Here</span>
              <span className="text-[10px] font-bold text-red-650 uppercase tracking-widest mt-0.5">Business Management Solutions</span>
            </div>
          </Link>
          {token && (
            <Link 
              to="/dashboard" 
              className="text-xs font-black text-indigo-600 hover:text-indigo-800 uppercase tracking-widest flex items-center gap-1.5 transition"
            >
              <ArrowLeft size={14} /> Back to Dashboard
            </Link>
          )}
        </div>
      </header>

      <div className="max-w-4xl mx-auto px-4">
        
        {/* Page Title */}
        <div className="text-center mb-10">
          <span className="bg-indigo-50/60 text-indigo-600 border border-indigo-100 px-4 py-1.5 rounded-full text-[10px] font-black uppercase tracking-widest inline-flex items-center gap-1.5 mb-4">
            <CheckSquare size={12} /> Interactive CA Checklist
          </span>
          <h1 className="text-3xl md:text-4xl font-black text-slate-900 tracking-tight">
            ITR Filing Checklist <span className="text-indigo-600">FY {financialYear}</span>
          </h1>
          <p className="text-slate-500 text-xs md:text-sm font-medium mt-2 max-w-lg mx-auto">
            Assessment Year {assessmentYear}. Provide response for each item and attach supporting files.
          </p>
        </div>

        {/* Step Indicators */}
        <div className="bg-white border border-slate-100 p-6 rounded-3xl mb-8 flex flex-col md:flex-row items-center justify-between gap-4 shadow-sm">
          <div className="flex-1 w-full">
            <div className="flex justify-between text-[10px] font-black uppercase tracking-widest text-slate-400 mb-2">
              <span>Step {currentStep} of 5</span>
              <span className="text-indigo-600">{activeSection.name}</span>
            </div>
            <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-indigo-500 to-violet-500 transition-all duration-500 rounded-full"
                style={{ width: `${(currentStep / 5) * 100}%` }}
              ></div>
            </div>
          </div>
        </div>

        {/* Step Content */}
        <div className="bg-white border border-slate-100 rounded-3xl p-6 md:p-8 shadow-sm space-y-6">
          
          {/* Step 1 Profile Information */}
          {currentStep === 1 && (
            <div className="bg-slate-50 border border-slate-100 rounded-2xl p-6 space-y-4">
              <h3 className="text-sm font-black text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2">
                Personal Identification
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-1.5 block">
                    Client Name
                  </label>
                  <input 
                    type="text" 
                    placeholder="Enter your name" 
                    value={clientName}
                    onChange={e => setClientName(e.target.value)}
                    className="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm font-bold focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none text-slate-800 transition"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-1.5 block">
                    PAN Card Number
                  </label>
                  <input 
                    type="text" 
                    maxLength={10}
                    placeholder="ABCDE1234F" 
                    value={pan}
                    onChange={e => setPan(e.target.value.toUpperCase())}
                    className="w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-sm font-bold focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none text-slate-800 transition uppercase"
                  />
                </div>
              </div>
            </div>
          )}

          {/* Checklist questions */}
          <div className="space-y-6">
            <h4 className="text-xs font-black text-indigo-600 uppercase tracking-widest flex items-center gap-2 border-b border-slate-100 pb-3">
              <FileText size={16} /> Section Checklist Items
            </h4>

            <div className="space-y-6 divide-y divide-slate-100">
              {stepQuestions.map((q) => {
                const itemRes = responses[q.id] || {};
                return (
                  <div key={q.id} className={`pt-6 first:pt-0 space-y-3 transition`}>
                    
                    <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                      <div className="max-w-xl">
                        <div className="flex items-center gap-2">
                          <span className="w-5 h-5 bg-slate-100 text-[10px] text-slate-500 font-black rounded flex items-center justify-center">
                            {q.id}
                          </span>
                          <span className="text-[9px] font-black uppercase tracking-wider bg-slate-50 text-slate-400 px-2 py-0.5 rounded border border-slate-100">
                            {q.section}
                          </span>
                        </div>
                        <p className="text-xs font-bold text-slate-700 mt-2 leading-relaxed">
                          {q.text}
                        </p>
                      </div>

                      {/* Yes / No / NA Controls */}
                      <div className="flex items-center gap-1.5 bg-slate-50 p-1.5 rounded-xl border border-slate-200 self-start">
                        {['Yes', 'No', 'N/A'].map(opt => (
                          <button
                            key={opt}
                            type="button"
                            onClick={() => handleResponseChange(q.id, 'value', opt)}
                            className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${
                              itemRes.value === opt
                                ? opt === 'Yes' 
                                  ? 'bg-emerald-600 text-white shadow-md' 
                                  : opt === 'No'
                                    ? 'bg-rose-600 text-white shadow-md'
                                    : 'bg-indigo-600 text-white shadow-md'
                                : 'text-slate-450 hover:text-slate-700'
                            }`}
                          >
                            {opt}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Conditional Remarks & File Upload when "Yes" is checked */}
                    {itemRes.value === 'Yes' && (
                      <div className="bg-slate-50 rounded-2xl p-4 border border-slate-100 space-y-3 animate-in fade-in duration-300">
                        <div className="flex flex-col md:flex-row items-center gap-3">
                          <div className="flex-1 w-full">
                            <input 
                              type="text"
                              placeholder="Add optional CA remarks / notes..."
                              value={itemRes.remarks || ''}
                              onChange={e => handleResponseChange(q.id, 'remarks', e.target.value)}
                              className="w-full bg-white border border-slate-250 rounded-xl px-3 py-2 text-xs font-medium focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 outline-none text-slate-800"
                            />
                          </div>

                          {/* File Uploader */}
                          <div className="flex flex-col gap-2 self-stretch md:self-auto w-full md:w-auto">
                            <label className={`h-9 px-4 bg-slate-100 text-slate-700 border border-slate-200 hover:bg-slate-200 active:scale-95 transition-all text-xs font-bold rounded-xl flex items-center justify-center gap-2 cursor-pointer ${uploadingItem === q.id ? 'opacity-50 pointer-events-none' : ''}`}>
                              <Upload size={14} />
                              {uploadingItem === q.id ? 'Uploading...' : 'Attach Proof'}
                              <input 
                                type="file" 
                                className="hidden" 
                                onChange={e => handleFileUpload(q.id, e)}
                                accept=".pdf,.png,.jpg,.jpeg,.doc,.docx"
                              />
                            </label>
                            
                            {(itemRes.documents || []).length > 0 && (
                              <div className="flex flex-wrap gap-2 mt-1">
                                {itemRes.documents.map((doc, idx) => (
                                  <div key={idx} className="flex items-center gap-2 bg-slate-105 border border-slate-200 pl-3 pr-2 py-1 rounded-xl">
                                    <span className="text-[10px] font-bold text-indigo-650 max-w-[120px] truncate">
                                      {doc.originalFileName}
                                    </span>
                                    <button
                                      type="button"
                                      onClick={() => handleRemoveFile(q.id, idx)}
                                      className="p-1 text-rose-500 hover:bg-rose-500/10 rounded-md transition"
                                    >
                                      <Trash2 size={13} />
                                    </button>
                                  </div>
                                ))}
                              </div>
                            )}

                            {itemRes.documentUrl && (
                              <div className="flex items-center gap-2 bg-slate-100 border border-slate-200 pl-3 pr-2 py-1 rounded-xl">
                                <span className="text-[10px] font-bold text-indigo-600 max-w-[120px] truncate">
                                  {itemRes.originalFileName} (Legacy)
                                </span>
                                <button
                                  type="button"
                                  onClick={() => {
                                    handleResponseChange(q.id, 'documentUrl', null);
                                    handleResponseChange(q.id, 'originalFileName', null);
                                  }}
                                  className="p-1 text-rose-500 hover:bg-rose-500/10 rounded-md transition"
                                >
                                  <Trash2 size={13} />
                                </button>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    )}

                  </div>
                );
              })}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-between border-t border-slate-100 pt-6 mt-8">
            {currentStep > 1 ? (
              <button
                type="button"
                onClick={handleBack}
                className="px-5 py-3 border border-slate-200 hover:border-slate-300 text-slate-600 rounded-xl text-xs font-black uppercase tracking-wider transition active:scale-[0.98] flex items-center gap-2"
              >
                <ArrowLeft size={14} /> Back
              </button>
            ) : (
              <div></div>
            )}

            {currentStep < 5 ? (
              <button
                type="button"
                onClick={handleNext}
                className="px-6 py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-black uppercase tracking-wider shadow-lg shadow-indigo-500/10 transition active:scale-[0.98] flex items-center gap-2 ml-auto"
              >
                Next Step <ArrowRight size={14} />
              </button>
            ) : (
              <button
                type="button"
                disabled={isSubmitting}
                onClick={handleSubmit}
                className="px-8 py-3 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white rounded-xl text-xs font-black uppercase tracking-wider shadow-lg shadow-emerald-500/10 transition active:scale-[0.98] flex items-center gap-2 ml-auto"
              >
                {isSubmitting ? 'Submitting...' : 'Submit Checklist'} <CheckCircle size={14} />
              </button>
            )}
          </div>

        </div>

        {/* Info Box */}
        <div className="bg-white border border-slate-100 p-5 rounded-3xl mt-6 flex gap-3 shadow-sm">
          <ShieldAlert className="text-amber-500 flex-shrink-0 mt-0.5" size={18} />
          <div>
            <p className="text-[10px] font-black text-amber-500 uppercase tracking-widest leading-none mb-1">Confidentiality Note</p>
            <p className="text-[11px] text-slate-500 font-medium leading-normal">
              All documents and identifiers collected (PAN, Aadhaar) are stored on secure isolated storage and are strictly used for your Income Tax Return filing under Section 139A guidelines.
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}
