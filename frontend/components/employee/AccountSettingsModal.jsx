import React, { useState } from 'react';
import axios from 'axios';
import { 
  X, User, Phone, Mail, Lock, Shield, Building, CreditCard, 
  Clock, Check, AlertCircle, Award, KeyRound
} from 'lucide-react';

const AccountSettingsModal = ({ isOpen, onClose, userInfo, onProfileUpdated }) => {
  if (!isOpen) return null;

  const [activeTab, setActiveTab] = useState('profile');
  const [formData, setFormData] = useState({
    name: userInfo?.name || '',
    email: userInfo?.email || '',
    phone: userInfo?.phone || '',
    profilePhoto: userInfo?.profilePhoto || '',
    companyName: userInfo?.companyName || '',
    address: userInfo?.address || '',
    panNumber: userInfo?.panNumber || '',
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  const [isSaving, setIsSaving] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });

  const token = userInfo?.token;
  const config = {
    headers: { Authorization: `Bearer ${token}` }
  };

  const handleSaveProfile = async (e) => {
    e.preventDefault();
    setIsSaving(true);
    setMessage({ type: '', text: '' });

    try {
      const payload = {
        name: formData.name,
        phone: formData.phone,
        profilePhoto: formData.profilePhoto,
        companyName: formData.companyName,
        address: formData.address,
        panNumber: formData.panNumber
      };

      if (formData.newPassword) {
        if (formData.newPassword !== formData.confirmPassword) {
          setMessage({ type: 'error', text: 'New passwords do not match.' });
          setIsSaving(false);
          return;
        }
        if (formData.newPassword.length < 6) {
          setMessage({ type: 'error', text: 'Password must be at least 6 characters.' });
          setIsSaving(false);
          return;
        }
        payload.password = formData.newPassword;
      }

      const { data } = await axios.put('/api/auth/profile', payload, config);

      const updated = {
        ...userInfo,
        ...data,
        token: data.token || userInfo.token
      };

      localStorage.setItem('userInfo', JSON.stringify(updated));
      if (onProfileUpdated) onProfileUpdated(updated);

      setMessage({ type: 'success', text: 'Account settings updated successfully!' });
      setFormData(prev => ({ ...prev, currentPassword: '', newPassword: '', confirmPassword: '' }));
      setTimeout(() => setMessage({ type: '', text: '' }), 4000);
    } catch (err) {
      setMessage({
        type: 'error',
        text: err.response?.data?.message || 'Failed to update account settings.'
      });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-md animate-fade-in">
      <div className="bg-white rounded-[32px] max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl border border-slate-100 overflow-hidden animate-in zoom-in-95 duration-200">
        
        {/* Header */}
        <div className="px-6 py-5 bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 text-white flex items-center justify-between border-b border-white/10">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-indigo-500 to-blue-500 text-white flex items-center justify-center font-black text-lg shadow-md shrink-0">
              {userInfo?.name?.charAt(0) || 'E'}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-extrabold text-base tracking-tight">{userInfo?.name || 'Staff Member'}</h3>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-indigo-500/30 text-indigo-300 border border-indigo-400/30">
                  {userInfo?.role || 'Employee'}
                </span>
              </div>
              <p className="text-xs text-slate-400">{userInfo?.email}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-9 h-9 rounded-xl bg-white/10 hover:bg-white/20 text-slate-300 hover:text-white flex items-center justify-center transition"
          >
            <X size={18} />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-200/80 bg-slate-50/70 px-6 gap-2 overflow-x-auto">
          {[
            { id: 'profile', label: 'My Profile', icon: User },
            { id: 'security', label: 'Security & Password', icon: KeyRound },
            { id: 'schedule', label: 'Shift & Policies', icon: Clock }
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3.5 text-xs font-bold border-b-2 transition-all whitespace-nowrap ${
                  isActive
                    ? 'border-indigo-600 text-indigo-700 bg-white shadow-xs rounded-t-xl'
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                }`}
              >
                <Icon size={14} />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {message.text && (
            <div className={`p-4 rounded-2xl text-xs font-bold flex items-center gap-2 ${
              message.type === 'success'
                ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                : 'bg-rose-50 text-rose-800 border border-rose-200'
            }`}>
              {message.type === 'success' ? <Check size={16} /> : <AlertCircle size={16} />}
              {message.text}
            </div>
          )}

          {activeTab === 'profile' && (
            <form onSubmit={handleSaveProfile} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-600">Full Name</label>
                  <div className="relative">
                    <User size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
                    <input
                      type="text"
                      required
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-600">Email Address (Fixed)</label>
                  <div className="relative">
                    <Mail size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
                    <input
                      type="email"
                      disabled
                      value={formData.email}
                      className="w-full pl-10 pr-4 py-2.5 bg-slate-100 border border-slate-200 rounded-xl text-xs font-semibold text-slate-500 cursor-not-allowed"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-600">Phone Number</label>
                  <div className="relative">
                    <Phone size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
                    <input
                      type="text"
                      placeholder="+91 9876543210"
                      value={formData.phone}
                      onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                      className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-600">PAN Number (Optional)</label>
                  <input
                    type="text"
                    placeholder="ABCDE1234F"
                    value={formData.panNumber}
                    onChange={(e) => setFormData({ ...formData, panNumber: e.target.value })}
                    className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 uppercase"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-600">Residential / Contact Address</label>
                <textarea
                  rows={2}
                  placeholder="Enter your address..."
                  value={formData.address}
                  onChange={(e) => setFormData({ ...formData, address: e.target.value })}
                  className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div className="p-4 bg-indigo-50/60 border border-indigo-100 rounded-2xl flex items-center justify-between">
                <div>
                  <p className="text-xs font-extrabold text-indigo-950">Staff Role & Category Access</p>
                  <p className="text-[11px] text-indigo-700 mt-0.5">Role: {userInfo?.role} • Assigned Tickets: {userInfo?.assignedTicketCategories?.join(', ') || 'General'}</p>
                </div>
                <Award size={22} className="text-indigo-600" />
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  type="submit"
                  disabled={isSaving}
                  className="px-6 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-extrabold shadow-md shadow-indigo-200 transition disabled:opacity-50"
                >
                  {isSaving ? 'Saving Changes...' : 'Save Profile Changes'}
                </button>
              </div>
            </form>
          )}

          {activeTab === 'security' && (
            <form onSubmit={handleSaveProfile} className="space-y-4">
              <div className="bg-amber-50/70 border border-amber-200/70 rounded-2xl p-4 text-xs text-amber-900 flex items-start gap-2.5">
                <Shield size={18} className="text-amber-600 shrink-0 mt-0.5" />
                <div>
                  <p className="font-extrabold">Change Account Password</p>
                  <p className="text-[11px] text-amber-800 mt-0.5">
                    Leave password fields empty if you do not wish to update your login password.
                  </p>
                </div>
              </div>

              <div className="space-y-3">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-600">New Password</label>
                  <div className="relative">
                    <Lock size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
                    <input
                      type="password"
                      placeholder="Enter minimum 6 characters..."
                      value={formData.newPassword}
                      onChange={(e) => setFormData({ ...formData, newPassword: e.target.value })}
                      className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-600">Confirm New Password</label>
                  <div className="relative">
                    <Lock size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
                    <input
                      type="password"
                      placeholder="Repeat new password..."
                      value={formData.confirmPassword}
                      onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                      className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                  </div>
                </div>
              </div>

              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100 text-xs text-slate-600 space-y-1">
                <p className="font-bold text-slate-800">Active Session Security</p>
                <p className="text-[11px] text-slate-500">
                  Auto clock-out will immediately trigger and log out your workplace session whenever you press Logout.
                </p>
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  type="submit"
                  disabled={isSaving || !formData.newPassword}
                  className="px-6 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-extrabold shadow-md shadow-indigo-200 transition disabled:opacity-50"
                >
                  {isSaving ? 'Updating Password...' : 'Update Password'}
                </button>
              </div>
            </form>
          )}

          {activeTab === 'schedule' && (
            <div className="space-y-4 text-xs">
              <div className="bg-slate-50 border border-slate-100 rounded-2xl p-4 space-y-3">
                <div className="flex items-center gap-2 text-slate-800 font-extrabold text-sm">
                  <Clock size={16} className="text-indigo-600" />
                  <span>Workplace Shift Timings & Guidelines</span>
                </div>
                <div className="space-y-2 text-slate-600">
                  <div className="flex justify-between py-1.5 border-b border-slate-200/60">
                    <span className="font-bold">Standard Shift Duration:</span>
                    <span className="text-slate-900 font-black">8 Hours / Day</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-200/60">
                    <span className="font-bold">Working Days:</span>
                    <span className="text-slate-900 font-black">Monday — Saturday</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-200/60">
                    <span className="font-bold">Lunch Break Allowance:</span>
                    <span className="text-slate-900 font-black">45 Minutes</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="font-bold">Tea / Snack Break Allowance:</span>
                    <span className="text-slate-900 font-black">15 Minutes</span>
                  </div>
                </div>
              </div>

              <div className="bg-indigo-50 border border-indigo-100 rounded-2xl p-4 space-y-2">
                <p className="font-extrabold text-indigo-900">⏱️ Automatic Attendance Tracking Notice</p>
                <p className="text-indigo-800 text-[11px] leading-relaxed">
                  Remember to Clock In when beginning your shift each morning and take appropriate Breaks from the top bar when stepping away. Any session left active when logging out will automatically record an Auto Clock-Out.
                </p>
              </div>
            </div>
          )}

        </div>

      </div>
    </div>
  );
};

export default AccountSettingsModal;
