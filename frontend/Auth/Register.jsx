import React, { useState, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { Loader2, User, Mail, Lock, Phone, ArrowRight, Briefcase } from 'lucide-react';
import { GoogleOAuthProvider, GoogleLogin } from '@react-oauth/google';

const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || '167766774028-hirpf3e2hkpf1ci1s6oq1koa5dr6p2gd.apps.googleusercontent.com';



const RegisterPage = () => {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [phone, setPhone] = useState('');
    const [password, setPassword] = useState('');
    const [role, setRole] = useState('client');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const { register, googleLogin } = useContext(AuthContext);
    const navigate = useNavigate();

    const handleGoogleSuccess = async (credentialResponse) => {
        console.log('Google credential response received:', credentialResponse);
        setLoading(true);
        setError('');
        try {
            const user = await googleLogin(credentialResponse);
            console.log('Backend user:', user);
            const targetUrl = user.role === 'admin' ? '/admin'
                : user.role === 'employee' ? '/employee'
                : user.role === 'partner' ? '/partner-dashboard'
                : user.role === 'freelancer' ? '/freelancer-dashboard'
                : '/customer-dashboard';
            // Full page navigation ensures ProtectedRoute reads fresh auth state
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

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        try {
            await register(name, email, phone, password, role);
            navigate('/dashboard');
        } catch (err) {
            setError(err.response?.data?.message || 'Registration failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-slate-50 flex">
            {/* Left Side - Hero Visual */}
            <div className="hidden lg:flex w-1/2 bg-slate-900 relative overflow-hidden items-center justify-center">
                <div className="absolute inset-0 bg-gradient-to-br from-red-600/20 to-slate-900/40 z-10" />
                <div className="relative z-20 text-center px-12">
                    <h2 className="text-5xl font-bold text-white mb-6">Join the Future.</h2>
                    <p className="text-slate-300 text-lg leading-relaxed max-w-lg mx-auto">
                        Create your account to unlock expert legal, financial, and business support tailored for your growth.
                    </p>
                </div>
                {/* Decorative Blobs */}
                <div className="absolute top-[-20%] right-[-20%] w-[600px] h-[600px] bg-red-600/10 rounded-full blur-[100px]" />
                <div className="absolute bottom-[-10%] left-[-10%] w-[500px] h-[500px] bg-indigo-600/10 rounded-full blur-[100px]" />
            </div>

            {/* Right Side - Form */}
            <div className="w-full lg:w-1/2 flex items-center justify-center p-8 bg-white overflow-y-auto">
                <div className="max-w-md w-full py-10">
                    <div className="mb-10">
                        <Link to="/" className="inline-block mb-8">
                            <span className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-red-600 to-slate-800">
                                VR HERE
                            </span>
                        </Link>
                        <h1 className="text-4xl font-bold text-slate-900 mb-3">Create Account</h1>
                        <p className="text-slate-500">Get started with your free account today.</p>
                    </div>

                    {error && (
                        <div className="mb-6 p-4 bg-red-50 text-red-600 text-sm rounded-xl flex items-center shadow-sm border border-red-100">
                            <span className="mr-3 text-lg">⚠️</span> {error}
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 mb-2">Full Name</label>
                            <div className="relative group">
                                <User className="absolute left-4 top-4 h-5 w-5 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                <input
                                    type="text"
                                    value={name}
                                    onChange={(e) => setName(e.target.value)}
                                    className="w-full pl-12 pr-4 py-3.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-red-100 focus:border-red-500 outline-none transition-all font-medium"
                                    placeholder="John Doe"
                                    required
                                />
                            </div>
                        </div>

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
                            <label className="block text-sm font-medium text-slate-700 mb-2">Mobile Number</label>
                            <div className="relative group">
                                <Phone className="absolute left-4 top-4 h-5 w-5 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                <input
                                    type="tel"
                                    value={phone}
                                    onChange={(e) => setPhone(e.target.value)}
                                    className="w-full pl-12 pr-4 py-3.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-red-100 focus:border-red-500 outline-none transition-all font-medium"
                                    placeholder="91-9999999999"
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

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white font-bold py-4 rounded-xl shadow-lg shadow-red-500/30 transition-all transform hover:-translate-y-0.5 active:translate-y-0 flex items-center justify-center mt-8"
                        >
                            {loading ? <Loader2 className="w-6 h-6 animate-spin" /> : <span className="flex items-center">Create Account <ArrowRight className="ml-2 w-5 h-5" /></span>}
                        </button>
                    </form>

                    <div className="relative my-6 flex items-center justify-center">
                        <div className="border-t border-slate-200 w-full" />
                        <span className="bg-white px-3 text-xs text-slate-400 font-semibold uppercase tracking-wider absolute">or</span>
                    </div>

                    {/* Google Login - credential/id_token flow (most reliable) */}
                    <div className="w-full flex justify-center">
                        <GoogleLogin
                            onSuccess={handleGoogleSuccess}
                            onError={(err) => {
                                console.error('Google Login button error:', err);
                                setError('Google Sign-In failed. Please try again.');
                            }}
                            theme="outline"
                            size="large"
                            text="continue_with"
                            width="400"
                            shape="rectangular"
                            logo_alignment="center"
                        />
                    </div>

                    <div className="mt-8 text-center text-slate-500">
                        Already have an account? <Link to="/login" className="text-red-600 font-bold hover:underline decoration-2 underline-offset-4 ml-1">Sign In</Link>
                    </div>
                </div>
            </div>
        </div>
    );
};

const RegisterPageWrapper = () => (
    <GoogleOAuthProvider clientId={googleClientId}>
        <RegisterPage />
    </GoogleOAuthProvider>
);

export default RegisterPageWrapper;
