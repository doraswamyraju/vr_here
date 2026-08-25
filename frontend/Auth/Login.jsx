import React, { useState, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { Loader2, Mail, Lock, ArrowRight } from 'lucide-react';
import GoogleAuthButton, { getDashboardRouteForRole } from '../components/GoogleAuthButton';
import ConsultationPaymentModal from '../components/ConsultationPaymentModal';
import { launchRazorpayCheckout } from '../utils/razorpayCheckout';
import { showPaymentSuccessPopup } from '../utils/paymentSuccessPopup';

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

const LoginPage = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const [isModalOpen, setIsModalOpen] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [selectedPlan, setSelectedPlan] = useState(null);
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        phone: ''
    });

    const { login } = useContext(AuthContext);
    const navigate = useNavigate();

    const handleConsultationBook = (e) => {
        e?.preventDefault();
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

    // Standard Email + Password Login Flow
    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        try {
            const user = await login(email, password);
            const targetUrl = getDashboardRouteForRole(user.role);
            navigate(targetUrl);
        } catch (err) {
            setError(err.response?.data?.message || 'Login failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-slate-50 flex">
            <ConsultationPaymentModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                selectedPlan={selectedPlan}
                initialFormData={formData}
                onSubmit={handleFormSubmit}
                isSubmitting={isSubmitting}
                formatCurrency={formatCurrency}
                title={selectedPlan?.buttonText || 'Sign Up'}
                initialTermsAccepted={false}
            />
            {/* Left Side - Hero Visual */}
            <div className="hidden lg:flex w-1/2 bg-slate-900 relative overflow-hidden items-center justify-center">
                <div className="absolute inset-0 bg-gradient-to-br from-red-600/20 to-slate-900/40 z-10" />
                <div className="relative z-20 text-center px-12">
                    <h2 className="text-5xl font-bold text-white mb-6">Welcome Back.</h2>
                    <p className="text-slate-300 text-lg leading-relaxed max-w-lg mx-auto">
                        Access your dashboard to manage registrations, track progress, and grow your business with VR HERE.
                    </p>
                </div>
                {/* Decorative Blobs */}
                <div className="absolute top-[-20%] left-[-20%] w-[600px] h-[600px] bg-red-600/10 rounded-full blur-[100px]" />
                <div className="absolute bottom-[-10%] right-[-10%] w-[500px] h-[500px] bg-indigo-600/10 rounded-full blur-[100px]" />
            </div>

            {/* Right Side - Form */}
            <div className="w-full lg:w-1/2 flex items-center justify-center p-8 bg-white">
                <div className="max-w-md w-full">
                    <div className="mb-10">
                        <Link to="/" className="inline-block mb-8">
                            <span className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-red-600 to-slate-800">
                                VR HERE
                            </span>
                        </Link>
                        <h1 className="text-4xl font-bold text-slate-900 mb-3">Sign In</h1>
                        <p className="text-slate-500">Please enter your details to continue.</p>
                    </div>

                    {error && (
                        <div className="mb-6 p-4 bg-red-50 text-red-600 text-sm rounded-xl flex items-center shadow-sm border border-red-100">
                            <span className="mr-3 text-lg">⚠️</span> {error}
                        </div>
                    )}

                    {/* Standard Email & Password Login */}
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 mb-2">Email Address</label>
                            <div className="relative group">
                                <Mail className="absolute left-4 top-4 h-5 w-5 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                <input
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    className="w-full pl-12 pr-4 py-3.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-red-100 focus:border-red-500 outline-none transition-all font-medium"
                                    placeholder="name@company.com"
                                    required
                                />
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-slate-700 mb-2">Password</label>
                            <div className="relative group">
                                <Lock className="absolute left-4 top-4 h-5 w-5 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                <input
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    className="w-full pl-12 pr-4 py-3.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-red-100 focus:border-red-500 outline-none transition-all font-medium"
                                    placeholder="••••••••"
                                    required
                                />
                            </div>
                        </div>

                        <div className="flex justify-end">
                            <Link to="/forgot-password" className="text-sm text-red-600 hover:text-red-700 font-semibold hover:underline decoration-2 underline-offset-4">
                                Forgot Password?
                            </Link>
                        </div>

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white font-bold py-4 rounded-xl shadow-lg shadow-red-500/30 transition-all transform hover:-translate-y-0.5 active:translate-y-0 flex items-center justify-center"
                        >
                            {loading ? <Loader2 className="w-6 h-6 animate-spin" /> : <span className="flex items-center">Sign In <ArrowRight className="ml-2 w-5 h-5" /></span>}
                        </button>
                    </form>

                    <div className="relative my-6 flex items-center justify-center">
                        <div className="border-t border-slate-200 w-full" />
                        <span className="bg-white px-3 text-xs text-slate-400 font-semibold uppercase tracking-wider absolute">or</span>
                    </div>

                    {/* Standalone Google Auth Module */}
                    <GoogleAuthButton
                        onError={setError}
                        text="continue_with"
                    />

                    <div className="mt-8 text-center text-slate-500">
                        Don't have an account? <button type="button" onClick={handleConsultationBook} className="text-red-600 font-bold hover:underline decoration-2 underline-offset-4 ml-1">Sign Up</button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LoginPage;
