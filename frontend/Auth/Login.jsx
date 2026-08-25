import React, { useState, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { Loader2, Mail, Lock, ArrowRight } from 'lucide-react';
import { GoogleOAuthProvider, useGoogleLogin } from '@react-oauth/google';
import ConsultationPaymentModal from '../components/ConsultationPaymentModal';
import { launchRazorpayCheckout } from '../utils/razorpayCheckout';
import { showPaymentSuccessPopup } from '../utils/paymentSuccessPopup';

const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || '167766774028-hirpf3e2hkpf1ci1s6oq1koa5dr6p2gd.apps.googleusercontent.com';

const CustomGoogleButton = ({ onSuccess, onError, loading }) => {
    const loginWithGoogle = useGoogleLogin({
        onSuccess: (tokenResponse) => {
            console.log('useGoogleLogin tokenResponse:', tokenResponse);
            if (tokenResponse?.access_token) {
                onSuccess({ access_token: tokenResponse.access_token });
            } else {
                onSuccess(tokenResponse);
            }
        },
        onError: (errorResponse) => {
            console.error('Google Sign-In Error:', errorResponse);
            if (onError) onError(errorResponse);
            alert('Google Sign-In failed: ' + (errorResponse?.error_description || errorResponse?.error || 'User cancelled or popup blocked'));
        },
    });

    return (
        <button
            type="button"
            onClick={() => loginWithGoogle()}
            disabled={loading}
            className="w-full bg-white hover:bg-slate-50 text-slate-700 font-semibold py-3.5 px-4 rounded-xl border border-slate-200 hover:border-slate-300 shadow-sm hover:shadow-md transition-all duration-200 transform hover:-translate-y-0.5 active:translate-y-0 flex items-center justify-center space-x-3 group cursor-pointer"
        >
            {loading ? (
                <Loader2 className="w-5 h-5 animate-spin text-red-600" />
            ) : (
                <>
                    <svg className="w-5 h-5 transition-transform group-hover:scale-110 duration-200" viewBox="0 0 24 24">
                        <path
                            fill="#4285F4"
                            d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                        />
                        <path
                            fill="#34A853"
                            d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                        />
                        <path
                            fill="#FBBC05"
                            d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                        />
                        <path
                            fill="#EA4335"
                            d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                        />
                    </svg>
                    <span className="text-slate-800 font-semibold text-sm">Continue with Google</span>
                </>
            )}
        </button>
    );
};

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

    const { login, googleLogin } = useContext(AuthContext);
    const navigate = useNavigate();

    React.useEffect(() => {
        if (window.location.hash && window.location.hash.includes('access_token=')) {
            const params = new URLSearchParams(window.location.hash.substring(1));
            const accessToken = params.get('access_token');
            if (accessToken) {
                handleGoogleSuccess({ access_token: accessToken });
            }
        }
    }, []);

    const handleGoogleSuccess = async (credentialResponse) => {
        console.log('Google Success Callback Payload:', credentialResponse);
        setLoading(true);
        setError('');
        try {
            const user = await googleLogin(credentialResponse);
            console.log('Logged in user from backend:', user);
            const targetUrl = user.role === 'admin' ? '/admin' 
                : user.role === 'employee' ? '/employee' 
                : user.role === 'partner' ? '/partner-dashboard' 
                : user.role === 'freelancer' ? '/freelancer-dashboard' 
                : '/customer-dashboard';
            window.location.href = targetUrl;
        } catch (err) {
            console.error('Google Login Error:', err);
            const msg = err.response?.data?.message || err.message || 'Google Sign-In failed';
            setError(msg);
            alert('Google Login Error: ' + msg);
        } finally {
            setLoading(false);
        }
    };

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

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        try {
            const user = await login(email, password);
            if (user.role === 'admin') navigate('/admin');
            else if (user.role === 'employee') navigate('/employee');
            else if (user.role === 'partner') navigate('/partner-dashboard');
            else if (user.role === 'freelancer') navigate('/freelancer-dashboard');
            else navigate('/dashboard');
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

                    <CustomGoogleButton
                        onSuccess={handleGoogleSuccess}
                        onError={() => setError('Google Sign-In was unsuccessful')}
                        loading={loading}
                    />

                    <div className="mt-8 text-center text-slate-500">
                        Don't have an account? <button type="button" onClick={handleConsultationBook} className="text-red-600 font-bold hover:underline decoration-2 underline-offset-4 ml-1">Sign Up</button>
                    </div>
                </div>
            </div>
        </div>
    );
};

const LoginPageWrapper = () => (
    <GoogleOAuthProvider clientId={googleClientId}>
        <LoginPage />
    </GoogleOAuthProvider>
);

export default LoginPageWrapper;
