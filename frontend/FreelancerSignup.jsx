import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { 
    User, Phone, Mail, Lock, ShieldCheck, 
    ArrowRight, CheckCircle2, AlertCircle, Loader2,
    Briefcase, FileText, Landmark, Key
} from 'lucide-react';
import { SharedHeader, SharedFooter } from './components/SharedComponents';

const FreelancerSignup = () => {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        phone: '',
        panCard: '',
        password: '',
        confirmPassword: '',
        yearsOfExperience: 0,
        resumeUrl: '',
        skills: [],
        bankName: '',
        accountName: '',
        accountNumber: '',
        ifscCode: ''
    });
    const [skillInput, setSkillInput] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
        if (error) setError('');
    };

    const handleAddSkill = (e) => {
        e.preventDefault();
        if (skillInput.trim() && !formData.skills.includes(skillInput.trim())) {
            setFormData({
                ...formData,
                skills: [...formData.skills, skillInput.trim()]
            });
            setSkillInput('');
        }
    };

    const handleRemoveSkill = (skillToRemove) => {
        setFormData({
            ...formData,
            skills: formData.skills.filter(s => s !== skillToRemove)
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (formData.password !== formData.confirmPassword) {
            return setError('Passwords do not match');
        }
        if (formData.skills.length === 0) {
            return setError('Please add at least one service specialization skill');
        }

        setLoading(true);
        try {
            await axios.post('/api/freelancer/register', {
                name: formData.name,
                email: formData.email,
                phone: formData.phone,
                panCard: formData.panCard.toUpperCase(),
                password: formData.password,
                yearsOfExperience: Number(formData.yearsOfExperience),
                resumeUrl: formData.resumeUrl,
                skills: formData.skills,
                bankDetails: {
                    bankName: formData.bankName,
                    accountName: formData.accountName,
                    accountNumber: formData.accountNumber,
                    ifscCode: formData.ifscCode
                }
            });

            setSuccess(true);
            setTimeout(() => {
                navigate('/login');
            }, 3500);
        } catch (err) {
            setError(err.response?.data?.message || 'Registration failed. Please check your details.');
        } finally {
            setLoading(false);
        }
    };

    if (success) {
        return (
            <div className="min-h-screen bg-slate-50 flex flex-col font-sans">
                <SharedHeader />
                <div className="flex-grow flex items-center justify-center p-6">
                    <div className="bg-white p-12 rounded-3xl shadow-2xl max-w-md w-full text-center animate-scale-in border border-slate-100">
                        <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-6">
                            <CheckCircle2 className="w-10 h-10 text-green-600" />
                        </div>
                        <h2 className="text-3xl font-black text-slate-900 mb-4 tracking-tight font-sans">Application Sent!</h2>
                        <p className="text-slate-600 mb-8 leading-relaxed">
                            Your freelancer account application has been submitted successfully. 
                            Our administrators will review your qualifications, resume link, and KYC before activating your account.
                            Redirecting to login...
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
            
            <div className="flex-grow py-16 px-4 md:px-8 max-w-[1200px] mx-auto w-full">
                <div className="bg-white rounded-[32px] shadow-2xl shadow-slate-200/50 p-8 md:p-12 border border-slate-100 relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-red-50 rounded-bl-[100px] -z-0 opacity-50"></div>
                    
                    <div className="relative z-10">
                        <div className="mb-8">
                            <span className="inline-flex items-center px-4 py-2 rounded-full bg-red-50 text-red-600 text-xs font-black uppercase tracking-widest mb-4">
                                Join as Freelancer
                            </span>
                            <h2 className="text-4xl font-black text-slate-900 tracking-tight">Freelancer Registration</h2>
                            <p className="text-slate-500 font-medium">Claim service orders on-demand and earn per project completion.</p>
                        </div>

                        {error && (
                            <div className="mb-6 p-4 bg-red-50 border-l-4 border-red-600 rounded-lg flex items-center text-red-700 text-sm animate-shake">
                                <AlertCircle className="w-5 h-5 mr-3 shrink-0" />
                                {error}
                            </div>
                        )}

                        <form onSubmit={handleSubmit} className="space-y-8">
                            {/* Section 1: Basic Information */}
                            <div>
                                <h3 className="text-lg font-bold text-slate-800 border-b border-slate-100 pb-2 mb-4">1. Personal Information</h3>
                                <div className="grid md:grid-cols-2 gap-5">
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Full Name</label>
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

                                <div className="grid md:grid-cols-2 gap-5 mt-5">
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Phone Number</label>
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
                            </div>

                            {/* Section 2: Experience & Specilizations */}
                            <div>
                                <h3 className="text-lg font-bold text-slate-800 border-b border-slate-100 pb-2 mb-4">2. Experience & Specializations</h3>
                                <div className="grid md:grid-cols-2 gap-5">
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Years of Experience</label>
                                        <div className="relative group">
                                            <Briefcase className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="yearsOfExperience" type="number" required placeholder="e.g., 5" value={formData.yearsOfExperience} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold"
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Resume / Portfolio Link</label>
                                        <div className="relative group">
                                            <FileText className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="resumeUrl" required placeholder="https://drive.google.com/..." value={formData.resumeUrl} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold"
                                            />
                                        </div>
                                    </div>
                                </div>

                                <div className="mt-5 space-y-2">
                                    <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Specialization Skills / Service Categories</label>
                                    <div className="flex gap-3">
                                        <input 
                                            placeholder="e.g., Income Tax Returns, GST Registration, TDS Filing" 
                                            value={skillInput} 
                                            onChange={(e) => setSkillInput(e.target.value)}
                                            className="flex-grow px-4 py-3 rounded-xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 outline-none transition-all font-semibold"
                                        />
                                        <button 
                                            onClick={handleAddSkill}
                                            className="px-6 py-3 bg-slate-900 text-white rounded-xl hover:bg-slate-800 font-bold transition"
                                        >
                                            Add Skill
                                        </button>
                                    </div>
                                    <div className="flex flex-wrap gap-2 mt-3">
                                        {formData.skills.map((skill, idx) => (
                                            <span 
                                                key={idx} 
                                                className="inline-flex items-center gap-2 bg-red-50 text-red-600 px-3 py-1.5 rounded-full text-xs font-black uppercase tracking-wider"
                                            >
                                                {skill}
                                                <button 
                                                    type="button" 
                                                    onClick={() => handleRemoveSkill(skill)}
                                                    className="w-4 h-4 flex items-center justify-center bg-red-100 rounded-full hover:bg-red-200 text-red-700 transition"
                                                >
                                                    ×
                                                </button>
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            {/* Section 3: Bank Account Info */}
                            <div>
                                <h3 className="text-lg font-bold text-slate-800 border-b border-slate-100 pb-2 mb-4">3. Bank Settlement Details</h3>
                                <div className="grid md:grid-cols-2 gap-5">
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Account Holder Name</label>
                                        <div className="relative group">
                                            <User className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="accountName" required placeholder="John Doe" value={formData.accountName} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold"
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Bank Name</label>
                                        <div className="relative group">
                                            <Landmark className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="bankName" required placeholder="HDFC Bank" value={formData.bankName} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold"
                                            />
                                        </div>
                                    </div>
                                </div>

                                <div className="grid md:grid-cols-2 gap-5 mt-5">
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Account Number</label>
                                        <div className="relative group">
                                            <Landmark className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="accountNumber" required placeholder="1234567890" value={formData.accountNumber} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold"
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-1.5">
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">IFSC Code</label>
                                        <div className="relative group">
                                            <Key className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="ifscCode" required placeholder="HDFC0000123" value={formData.ifscCode} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold uppercase"
                                            />
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Section 4: Security */}
                            <div>
                                <h3 className="text-lg font-bold text-slate-800 border-b border-slate-100 pb-2 mb-4">4. Password Security</h3>
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
                                        <label className="text-xs font-black text-slate-400 uppercase tracking-widest pl-1">Confirm Password</label>
                                        <div className="relative group">
                                            <ShieldCheck className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                            <input 
                                                name="confirmPassword" type="password" required placeholder="••••••••" value={formData.confirmPassword} onChange={handleChange}
                                                className="w-full pl-11 pr-4 py-4 rounded-2xl bg-slate-50 border-transparent focus:bg-white focus:border-red-500 focus:ring-4 focus:ring-red-500/10 outline-none transition-all font-semibold"
                                            />
                                        </div>
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
                                    <>Register Account <ArrowRight className="w-5 h-5 text-red-500" /></>
                                )}
                            </button>

                            <p className="text-center text-sm font-bold text-slate-400 pt-4">
                                Already have an account? <Link to="/login" className="text-red-600 hover:underline">Login here</Link>
                            </p>
                        </form>
                    </div>
                </div>
            </div>

            <SharedFooter />
        </div>
    );
};

export default FreelancerSignup;
