import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { 
    User, Phone, Mail, Lock, ShieldCheck, 
    ArrowRight, CheckCircle2, AlertCircle, Loader2,
    Users, Briefcase, TrendingUp
} from 'lucide-react';
import { SharedHeader, SharedFooter } from './components/SharedComponents';

const PartnerSignup = () => {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        phone: '',
        panCard: '',
        password: '',
        confirmPassword: ''
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
        if (error) setError('');
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (formData.password !== formData.confirmPassword) {
            return setError('Passwords do not match');
        }

        setLoading(true);
        try {
            const { data } = await axios.post('/api/auth/register-partner', {
                name: formData.name,
                email: formData.email,
                phone: formData.phone,
                panCard: formData.panCard.toUpperCase(),
                password: formData.password
            });

            setSuccess(true);
            setTimeout(() => {
                navigate('/login');
            }, 3000);
        } catch (err) {
            setError(err.response?.data?.message || 'Registration failed. Please check your details.');
        } finally {
            setLoading(false);
        }
    };

    if (success) {
        return (
            <div className="min-h-screen bg-slate-50 flex flex-col">
                <SharedHeader />
                <div className="flex-grow flex items-center justify-center p-6">
                    <div className="bg-white p-12 rounded-3xl shadow-2xl max-w-md w-full text-center animate-scale-in border border-slate-100">
                        <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-6">
                            <CheckCircle2 className="w-10 h-10 text-green-600" />
                        </div>
                        <h2 className="text-3xl font-black text-slate-900 mb-4 tracking-tight">Welcome Partner!</h2>
                        <p className="text-slate-600 mb-8 leading-relaxed">
                            Your referral partner account has been created successfully. 
                            Redirecting you to login...
                        </p>
                        <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                            <div className="bg-green-500 h-full animate-progress-fast"></div>
                        </div>
                    </div>
                </div>
                <SharedFooter />
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-slate-50 flex flex-col font-sans">
            <SharedHeader />
            
            <div className="flex-grow py-16 px-4 md:px-8 max-w-[1400px] mx-auto w-full grid lg:grid-cols-2 gap-16 items-center">
                
                {/* Left Side: Branding/Value Prop */}
                <div className="hidden lg:block space-y-12 animate-slide-in-left">
                    <div>
                        <div className="inline-flex items-center px-4 py-2 rounded-full bg-red-50 text-red-600 text-xs font-black uppercase tracking-widest mb-6">
                            Partner Program
                        </div>
                        <h1 className="text-5xl xl:text-6xl font-black text-slate-900 leading-[1.1] tracking-tight">
                            Grow with <span className="text-red-600 italic">VR HERE</span>
                        </h1>
                        <p className="text-xl text-slate-600 mt-6 leading-relaxed max-w-xl">
                            Join our premium referral network and earn high-yield commissions by connecting businesses with India's leading digital consultants.
                        </p>
                    </div>

                    <div className="grid gap-6">
                        <div className="flex items-start gap-5 p-6 bg-white rounded-2xl shadow-sm border border-slate-100 hover:shadow-md transition-shadow">
                            <div className="w-12 h-12 bg-indigo-50 rounded-xl flex items-center justify-center text-indigo-600 shrink-0">
                                <TrendingUp className="w-6 h-6" />
                            </div>
                            <div>
                                <h3 className="font-bold text-slate-900 leading-none">High Commissions</h3>
                                <p className="text-sm text-slate-500 mt-2">Earn up to 10% or more on every successful business registration referred by you.</p>
                            </div>
                        </div>

                        <div className="flex items-start gap-5 p-6 bg-white rounded-2xl shadow-sm border border-slate-100 hover:shadow-md transition-shadow">
                            <div className="w-12 h-12 bg-red-50 rounded-xl flex items-center justify-center text-red-600 shrink-0">
                                <ShieldCheck className="w-6 h-6" />
                            </div>
                            <div>
                                <h3 className="font-bold text-slate-900 leading-none">Transparent Tracking</h3>
                                <p className="text-sm text-slate-500 mt-2">Dedicated dashboard to track your referrals, order statuses, and earned payouts in real-time.</p>
                            </div>
                        </div>

                        <div className="flex items-start gap-5 p-6 bg-white rounded-2xl shadow-sm border border-slate-100 hover:shadow-md transition-shadow">
                            <div className="w-12 h-12 bg-green-50 rounded-xl flex items-center justify-center text-green-600 shrink-0">
                                <Briefcase className="w-6 h-6" />
                            </div>
                            <div>
                                <h3 className="font-bold text-slate-900 leading-none">Industry Support</h3>
                                <p className="text-sm text-slate-500 mt-2">Access to marketing materials and expert support to help you close more leads.</p>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Right Side: Form */}
                <div className="animate-slide-in-right">
                    <div className="bg-white rounded-[32px] shadow-2xl shadow-slate-200/50 p-8 md:p-12 border border-slate-100 relative overflow-hidden">
                        <div className="absolute top-0 right-0 w-32 h-32 bg-red-50 rounded-bl-[100px] -z-0 opacity-50"></div>
                        
                        <div className="relative z-10">
                            <h2 className="text-3xl font-black text-slate-900 mb-2">Partner Signup</h2>
                            <p className="text-slate-500 mb-8 font-medium">Register as a referral partner to start earning.</p>

                            {error && (
                                <div className="mb-6 p-4 bg-red-50 border-l-4 border-red-600 rounded-lg flex items-center text-red-700 text-sm animate-shake">
                                    <AlertCircle className="w-5 h-5 mr-3 shrink-0" />
                                    {error}
                                </div>
                            )}

                            <form onSubmit={handleSubmit} className="space-y-5">
                                <div className="grid md:grid-cols-2 gap-5">
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Name</label>
                                        <div className="relative group">
                                            <User className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="name" required placeholder="Full Name" value={formData.name} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold"
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Email</label>
                                        <div className="relative group">
                                            <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="email" type="email" required placeholder="Email Address" value={formData.email} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold"
                                            />
                                        </div>
                                    </div>
                                </div>

                                <div className="grid md:grid-cols-2 gap-5">
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Phone (Referral Code)</label>
                                        <div className="relative group">
                                            <Phone className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="phone" required placeholder="Mobile Number" value={formData.phone} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold"
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">PAN Card (KYC)</label>
                                        <div className="relative group">
                                            <Briefcase className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="panCard" required placeholder="ABCDE1234F" value={formData.panCard} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold uppercase"
                                            />
                                        </div>
                                    </div>
                                </div>

                                <div className="grid md:grid-cols-2 gap-5">
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Password</label>
                                        <div className="relative group">
                                            <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="password" type="password" required placeholder="••••••••" value={formData.password} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold"
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Confirm</label>
                                        <div className="relative group">
                                            <ShieldCheck className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="confirmPassword" type="password" required placeholder="••••••••" value={formData.confirmPassword} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold"
                                            />
                                        </div>
                                    </div>
                                </div>

                                <button 
                                    disabled={loading}
                                    className="w-full bg-slate-900 text-white font-black py-5 rounded-2xl flex items-center justify-center gap-3 hover:bg-slate-800 transition transform active:scale-[0.98] mt-8 shadow-xl shadow-slate-200"
                                >
                                    {loading ? (
                                        <Loader2 className="w-6 h-6 animate-spin" />
                                    ) : (
                                        <>Register Now <ArrowRight className="w-5 h-5 text-red-500" /></>
                                    )}
                                </button>

                                <p className="text-center text-sm font-bold text-slate-400 pt-6">
                                    Already have a partner account? <Link to="/login" className="text-red-600 hover:underline">Login here</Link>
                                </p>
                            </form>
                        </div>
                    </div>
                </div>

            </div>

            <SharedFooter />
        </div>
    );
};

export default PartnerSignup;
