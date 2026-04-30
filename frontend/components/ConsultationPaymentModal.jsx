import React, { useEffect, useRef, useState } from 'react';
import axios from 'axios';
import { X, CreditCard, RefreshCw, Loader2, ShieldCheck, Gift, CheckCircle2, AlertCircle } from 'lucide-react';

const ConsultationPaymentModal = ({
  isOpen,
  onClose,
  selectedPlan,
  initialFormData,
  initialTermsAccepted = false,
  onSubmit,
  isSubmitting,
  formatCurrency,
  title,
  nonAdjustableNote = '+ Government Fees as applicable'
}) => {
  const [formData, setFormData] = useState({
    name: '',
    phone: '',
    email: '',
    referralCode: ''
  });
  const [termsAccepted, setTermsAccepted] = useState(initialTermsAccepted);
  const [validationStatus, setValidationStatus] = useState({ loading: false, error: '', success: '', partnerName: '' });
  const hasInitializedForOpen = useRef(false);

  useEffect(() => {
    if (!isOpen) {
      hasInitializedForOpen.current = false;
      return;
    }

    // Initialize only once per open cycle so typing isn't reset by parent re-renders.
    if (!hasInitializedForOpen.current) {
      setFormData({
        name: initialFormData?.name || '',
        phone: initialFormData?.phone || '',
        email: initialFormData?.email || '',
        referralCode: ''
      });
      setTermsAccepted(Boolean(initialTermsAccepted));
      setValidationStatus({ loading: false, error: '', success: '', partnerName: '' });
      hasInitializedForOpen.current = true;
    }
  }, [isOpen, initialFormData, initialTermsAccepted]);

  if (!isOpen) return null;

  const handleInputChange = (event) => {
    const { name, value } = event.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value
    }));
    if (name === 'referralCode') {
      setValidationStatus({ loading: false, error: '', success: '', partnerName: '' });
    }
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    
    // Validate Referral Code if present
    if (formData.referralCode && formData.referralCode.length >= 10) {
      setValidationStatus({ ...validationStatus, loading: true, error: '' });
      try {
        const { data } = await axios.get(`/api/partner/validate/${formData.referralCode}`);
        setValidationStatus({ loading: false, error: '', success: 'Valid Partner!', partnerName: data.partnerName });
        
        // Brief delay to show success before proceeding
        setTimeout(() => {
          onSubmit({
            formData,
            termsAccepted
          });
        }, 800);
        return;
      } catch (err) {
        setValidationStatus({ 
          loading: false, 
          success: '', 
          error: err.response?.data?.message || 'Invalid referral code' 
        });
        return;
      }
    }

    onSubmit({
      formData,
      termsAccepted
    });
  };

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md relative overflow-hidden animate-slide-up">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-red-600 transition bg-white rounded-full p-1"
          aria-label="Close payment modal"
        >
          <X className="w-6 h-6" />
        </button>

        <div className="bg-slate-900 p-6 text-center border-b-4 border-red-600">
          <h3 className="text-white font-bold text-xl">{title}</h3>
          <p className="text-slate-400 text-sm mt-1">{selectedPlan?.name || 'Expert Guidance'}</p>
        </div>

        <div className="p-6">
          <div className="mb-6 bg-red-50 border border-red-100 p-4 rounded-xl flex items-start">
            <CreditCard className="w-5 h-5 text-red-600 mt-0.5 mr-3 flex-shrink-0" />
            <div>
              <div className="font-bold text-slate-900 text-sm">
                Payment Amount: {selectedPlan ? formatCurrency(selectedPlan.price) : '...'}
              </div>
              {selectedPlan?.isAdjustable ? (
                <p className="text-xs text-green-700 font-bold mt-1 flex items-center">
                  <RefreshCw className="w-3 h-3 mr-1" /> Fully adjustable against final package
                </p>
              ) : (
                <p className="text-xs text-slate-500 mt-1">{nonAdjustableNote}</p>
              )}
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <input
              name="name"
              value={formData.name}
              onChange={handleInputChange}
              autoComplete="name"
              required
              type="text"
              className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-red-600 outline-none transition-shadow hover:shadow-inner"
              placeholder="Full Name"
            />
            <input
              name="phone"
              value={formData.phone}
              onChange={handleInputChange}
              autoComplete="tel"
              required
              type="tel"
              className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-red-600 outline-none transition-shadow hover:shadow-inner"
              placeholder="Mobile Number"
            />
            <input
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              autoComplete="email"
              required
              type="email"
              className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-red-600 outline-none transition-shadow hover:shadow-inner"
              placeholder="Email Address"
            />

            {/* Referral Code Field */}
            <div className="relative">
              <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                <Gift className="w-4 h-4 text-slate-400" />
              </div>
              <input
                name="referralCode"
                value={formData.referralCode}
                onChange={handleInputChange}
                type="tel"
                className={`w-full pl-10 pr-4 py-3 rounded-lg border border-dashed focus:ring-2 outline-none transition-shadow hover:shadow-inner text-sm ${
                  validationStatus.error 
                    ? 'border-red-500 bg-red-50 focus:ring-red-200' 
                    : validationStatus.success 
                      ? 'border-green-500 bg-green-50 focus:ring-green-200' 
                      : 'border-gray-300 focus:ring-indigo-400 focus:border-indigo-400'
                }`}
                placeholder="Referral Code (Partner Mobile No.) — Optional"
              />
              {validationStatus.loading && (
                <div className="absolute right-3 top-1/2 -translate-y-1/2">
                  <Loader2 className="w-4 h-4 animate-spin text-slate-400" />
                </div>
              )}
            </div>

            {validationStatus.error && (
              <p className="text-[10px] text-red-600 font-bold flex items-center px-1 animate-shake">
                <AlertCircle className="w-3 h-3 mr-1" /> {validationStatus.error}
              </p>
            )}

            {validationStatus.success && (
              <p className="text-[10px] text-green-700 font-bold flex items-center px-1 animate-in fade-in">
                <CheckCircle2 className="w-3 h-3 mr-1" /> Verified Partner: {validationStatus.partnerName}
              </p>
            )}

            <label className="flex items-start gap-2 text-xs text-slate-600">
              <input
                type="checkbox"
                checked={termsAccepted}
                onChange={(e) => setTermsAccepted(e.target.checked)}
                className="mt-0.5"
              />
              <span>
                I agree to the <a href="/terms-and-conditions" target="_blank" rel="noreferrer" className="text-red-600 font-bold hover:underline">Terms &amp; Conditions</a>.
              </span>
            </label>

            <button
              disabled={isSubmitting || !termsAccepted}
              type="submit"
              className="w-full bg-red-600 text-white font-bold py-3.5 rounded-lg hover:bg-red-700 transition transform active:scale-95 flex items-center justify-center shadow-lg shadow-red-600/20 disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {isSubmitting ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                `Pay ${selectedPlan ? formatCurrency(selectedPlan.price) : ''} & Proceed`
              )}
            </button>
          </form>

          <p className="text-center text-xs text-slate-400 mt-4 flex items-center justify-center">
            <ShieldCheck className="w-3 h-3 mr-1" /> Secure Payment Gateway
          </p>
        </div>
      </div>
    </div>
  );
};

export default ConsultationPaymentModal;
