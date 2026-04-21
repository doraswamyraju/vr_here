import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    User, ShieldCheck, CreditCard, Building2, 
    AtSign, Phone, Loader2, Save, AlertCircle, 
    CheckCircle2, Info
} from 'lucide-react';

const PartnerSettingsView = ({ userInfo, onProfileUpdate }) => {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState({ type: '', text: '' });
    
    const [formData, setFormData] = useState({
        name: '',
        phone: '',
        panCard: '',
        bankDetails: {
            accountName: '',
            accountNumber: '',
            ifscCode: '',
            bankName: ''
        }
    });

    useEffect(() => {
        fetchProfile();
    }, []);

    const fetchProfile = async () => {
        try {
            const config = {
                headers: { Authorization: `Bearer ${userInfo.token}` }
            };
            const { data } = await axios.get('/api/partner/profile', config);
            setFormData({
                name: data.name || '',
                phone: data.phone || '',
                panCard: data.panCard || '',
                bankDetails: {
                    accountName: data.bankDetails?.accountName || '',
                    accountNumber: data.bankDetails?.accountNumber || '',
                    ifscCode: data.bankDetails?.ifscCode || '',
                    bankName: data.bankDetails?.bankName || ''
                }
            });
        } catch (err) {
            setMessage({ type: 'error', text: 'Failed to load profile details' });
        } finally {
            setLoading(false);
        }
    };

    const handleChange = (e) => {
        const { name, value } = e.target;
        if (name.includes('.')) {
            const [parent, child] = name.split('.');
            setFormData(prev => ({
                ...prev,
                [parent]: {
                    ...prev[parent],
                    [child]: value
                }
            }));
        } else {
            setFormData(prev => ({ ...prev, [name]: value }));
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setSaving(true);
        setMessage({ type: '', text: '' });

        try {
            const config = {
                headers: { 
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${userInfo.token}` 
                }
            };
            const { data } = await axios.put('/api/partner/profile', formData, config);
            
            // Update local storage and parent state if callback provided
            const updatedUserInfo = { ...userInfo, ...data };
            localStorage.setItem('userInfo', JSON.stringify(updatedUserInfo));
            if (onProfileUpdate) onProfileUpdate(updatedUserInfo);
            
            setMessage({ type: 'success', text: 'Profile updated successfully!' });
            
            // Clear message after 3 seconds
            setTimeout(() => setMessage({ type: '', text: '' }), 3000);
        } catch (err) {
            setMessage({ 
                type: 'error', 
                text: err.response?.data?.message || 'Failed to update profile' 
            });
        } finally {
            setSaving(false);
        }
    };

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center p-20 animate-pulse">
                <Loader2 className="w-10 h-10 text-slate-200 animate-spin mb-4" />
                <p className="text-slate-400 font-bold uppercase tracking-widest text-xs">Loading Settings...</p>
            </div>
        );
    }

    return (
        <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 pb-20">
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 px-2">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 tracking-tight">Account Settings</h1>
                    <p className="text-slate-500 text-sm mt-1">Manage your professional identity and payout preferences.</p>
                </div>
                <div className="flex items-center gap-2 group">
                    <div className="w-10 h-10 bg-indigo-50 rounded-xl flex items-center justify-center text-indigo-600 transition-transform group-hover:rotate-12">
                        <ShieldCheck className="w-5 h-5" />
                    </div>
                </div>
            </div>

            {message.text && (
                <div className={`p-4 rounded-2xl flex items-center gap-3 animate-in zoom-in duration-300 ${
                    message.type === 'success' 
                        ? 'bg-green-50 border border-green-100 text-green-700' 
                        : 'bg-red-50 border border-red-100 text-red-700'
                }`}>
                    {message.type === 'success' ? <CheckCircle2 className="w-5 h-5" /> : <AlertCircle className="w-5 h-5" />}
                    <span className="font-bold text-sm">{message.text}</span>
                </div>
            )}

            <form onSubmit={handleSubmit} className="grid gap-8">
                
                {/* Personal & KYC Section */}
                <div className="bg-white rounded-[32px] p-8 shadow-sm border border-slate-100 group">
                    <div className="flex items-center gap-3 mb-8">
                        <div className="w-10 h-10 bg-slate-900 rounded-xl flex items-center justify-center text-white shadow-lg shadow-slate-200 transition-transform group-hover:scale-110">
                            <User className="w-5 h-5" />
                        </div>
                        <h3 className="text-lg font-black text-slate-800">Professional Identity</h3>
                    </div>

                    <div className="grid md:grid-cols-2 gap-6">
                        <div className="space-y-2">
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Full Name</label>
                            <input 
                                name="name"
                                value={formData.name}
                                onChange={handleChange}
                                className="w-full px-5 py-4 rounded-2xl bg-slate-50 border-2 border-transparent focus:bg-white focus:border-slate-900 outline-none transition-all font-bold text-slate-800 shadow-inner"
                                placeholder="Display Name"
                            />
                        </div>
                        <div className="space-y-2">
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">PAN Card Number</label>
                            <input 
                                name="panCard"
                                value={formData.panCard}
                                onChange={handleChange}
                                className="w-full px-5 py-4 rounded-2xl bg-slate-50 border-2 border-transparent focus:bg-white focus:border-red-500 outline-none transition-all font-black text-red-600 shadow-inner uppercase tracking-widest"
                                placeholder="ABCDE1234F"
                            />
                        </div>
                        <div className="space-y-2 opacity-60">
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Registered Email</label>
                            <div className="w-full px-5 py-4 rounded-2xl bg-slate-100 flex items-center gap-3 text-slate-500 font-bold border-2 border-transparent cursor-not-allowed">
                                <AtSign className="w-4 h-4" /> {userInfo.email}
                            </div>
                        </div>
                        <div className="space-y-2 opacity-60">
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Referral Code (Phone)</label>
                            <div className="w-full px-5 py-4 rounded-2xl bg-slate-100 flex items-center gap-3 text-slate-500 font-bold border-2 border-transparent cursor-not-allowed">
                                <Phone className="w-4 h-4" /> {userInfo.phone}
                            </div>
                        </div>
                    </div>
                </div>

                {/* Bank Details Section */}
                <div className="bg-white rounded-[32px] p-8 shadow-sm border border-slate-100 group">
                    <div className="flex items-center gap-3 mb-8">
                        <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white shadow-lg shadow-indigo-100 transition-transform group-hover:scale-110">
                            <CreditCard className="w-5 h-5" />
                        </div>
                        <h3 className="text-lg font-black text-slate-800">Payout Destination</h3>
                    </div>

                    <div className="grid md:grid-cols-2 gap-6">
                        <div className="space-y-2 lg:col-span-1">
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Account Holder Name</label>
                            <input 
                                name="bankDetails.accountName"
                                value={formData.bankDetails.accountName}
                                onChange={handleChange}
                                className="w-full px-5 py-4 rounded-2xl bg-slate-50 border-2 border-transparent focus:bg-white focus:border-indigo-600 outline-none transition-all font-bold text-slate-800 shadow-inner"
                                placeholder="Name as per Passbook"
                            />
                        </div>
                        <div className="space-y-2">
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Bank Name</label>
                            <div className="relative">
                                <Building2 className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-300" />
                                <input 
                                    name="bankDetails.bankName"
                                    value={formData.bankDetails.bankName}
                                    onChange={handleChange}
                                    className="w-full pl-12 pr-5 py-4 rounded-2xl bg-slate-50 border-2 border-transparent focus:bg-white focus:border-indigo-600 outline-none transition-all font-bold text-slate-800 shadow-inner"
                                    placeholder="e.g. HDFC Bank"
                                />
                            </div>
                        </div>
                        <div className="space-y-2">
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Account Number</label>
                            <input 
                                name="bankDetails.accountNumber"
                                value={formData.bankDetails.accountNumber}
                                onChange={handleChange}
                                className="w-full px-5 py-4 rounded-2xl bg-slate-50 border-2 border-transparent focus:bg-white focus:border-indigo-600 outline-none transition-all font-black text-slate-800 shadow-inner"
                                placeholder="Account Number"
                            />
                        </div>
                        <div className="space-y-2">
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">IFSC Code</label>
                            <input 
                                name="bankDetails.ifscCode"
                                value={formData.bankDetails.ifscCode}
                                onChange={handleChange}
                                className="w-full px-5 py-4 rounded-2xl bg-slate-50 border-2 border-transparent focus:bg-white focus:border-indigo-600 outline-none transition-all font-black text-indigo-600 shadow-inner uppercase"
                                placeholder="IFSC0000XXX"
                            />
                        </div>
                    </div>

                    <div className="mt-8 p-5 rounded-2xl bg-amber-50 border border-amber-100 flex gap-4">
                        <Info className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
                        <p className="text-xs text-amber-800 font-medium leading-relaxed">
                            Please ensure your bank details are correct to avoid payout delays. 
                            Payments are generally processed to the account specified here by the 10th of every month.
                        </p>
                    </div>
                </div>

                {/* Footer / Submit */}
                <div className="flex items-center justify-between gap-4 px-2">
                    <p className="text-xs text-slate-400 font-medium hidden sm:block">
                        Last synced: {new Date().toLocaleTimeString()}
                    </p>
                    <button 
                        disabled={saving}
                        type="submit"
                        className="bg-slate-900 text-white font-black px-10 py-5 rounded-3xl shadow-2xl shadow-slate-200 hover:bg-slate-800 transition transform active:scale-95 flex items-center gap-3 disabled:opacity-50"
                    >
                        {saving ? (
                            <>Updating... <Loader2 className="w-5 h-5 animate-spin" /></>
                        ) : (
                            <>Save Changes <Save className="w-5 h-5 text-red-500" /></>
                        )}
                    </button>
                </div>

            </form>
        </div>
    );
};

export default PartnerSettingsView;
