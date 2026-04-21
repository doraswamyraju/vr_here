import React, { useEffect, useRef, useState } from 'react';
import { X, CreditCard, RefreshCw, Loader2, ShieldCheck, Gift } from 'lucide-react';

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
  };

  const handleSubmit = (event) => {
    event.preventDefault();
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
                className="w-full pl-10 pr-4 py-3 rounded-lg border border-dashed border-gray-300 focus:ring-2 focus:ring-indigo-400 focus:border-indigo-400 outline-none transition-shadow hover:shadow-inner text-sm"
                placeholder="Referral Code (Partner Mobile No.) — Optional"
              />
            </div>

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
