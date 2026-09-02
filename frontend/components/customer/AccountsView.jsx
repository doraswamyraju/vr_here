import React, { useState, useMemo } from 'react';
import {
  User as UserIcon,
  Building2,
  FileText,
  CreditCard,
  ShieldCheck,
  RefreshCw,
  History,
  Download,
  Receipt,
  CheckCircle2,
  ArrowUpRight,
  Wallet,
  Mail,
  Phone,
  MapPin,
  Save,
  Clock,
  AlertTriangle,
  Send,
  IndianRupee,
  Lock,
  Award,
  Camera,
  Upload,
  Image as ImageIcon,
  Trash2,
  Loader2
} from 'lucide-react';
import axios from 'axios';
import ProfileDocumentsVault from './ProfileDocumentsVault';

const AccountsView = ({ orders = [], payments = [], userInfo, token }) => {
  const [activeSubTab, setActiveSubTab] = useState('profile'); // 'profile', 'vault', 'renewals', 'billing'
  const authToken = token || userInfo?.token;

  // Editable Profile Form State
  const [formData, setFormData] = useState({
    name: userInfo?.name || '',
    email: userInfo?.email || '',
    phone: userInfo?.phone || '',
    profilePhoto: userInfo?.profilePhoto || null,
    companyLogo: userInfo?.companyLogo || null,
    companyName: userInfo?.companyName || userInfo?.name || '',
    businessType: userInfo?.businessType || 'Private Limited',
    gstin: userInfo?.gstin || '',
    panNumber: userInfo?.panNumber || '',
    address: userInfo?.address || ''
  });

  const [savingProfile, setSavingProfile] = useState(false);
  const [uploadingPhoto, setUploadingPhoto] = useState(false);
  const [uploadingLogo, setUploadingLogo] = useState(false);

  // Upload Profile Photo Handler
  const handleUploadPhoto = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadingPhoto(true);
    try {
      const data = new FormData();
      data.append('image', file);
      data.append('type', 'profilePhoto');
      const config = {
        headers: {
          Authorization: `Bearer ${authToken}`,
          'Content-Type': 'multipart/form-data'
        }
      };
      const res = await axios.post('/api/auth/upload-avatar', data, config);
      const photoUrl = res.data.url;
      setFormData((prev) => ({ ...prev, profilePhoto: photoUrl }));

      // Update local storage
      const savedUser = JSON.parse(localStorage.getItem('userInfo') || '{}');
      const updatedUser = { ...savedUser, profilePhoto: photoUrl };
      localStorage.setItem('userInfo', JSON.stringify(updatedUser));
      alert('Person photo uploaded successfully!');
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to upload photo');
    } finally {
      setUploadingPhoto(false);
    }
  };

  // Upload Company Logo Handler
  const handleUploadLogo = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadingLogo(true);
    try {
      const data = new FormData();
      data.append('image', file);
      data.append('type', 'companyLogo');
      const config = {
        headers: {
          Authorization: `Bearer ${authToken}`,
          'Content-Type': 'multipart/form-data'
        }
      };
      const res = await axios.post('/api/auth/upload-logo', data, config);
      const logoUrl = res.data.url;
      setFormData((prev) => ({ ...prev, companyLogo: logoUrl }));

      // Update local storage
      const savedUser = JSON.parse(localStorage.getItem('userInfo') || '{}');
      const updatedUser = { ...savedUser, companyLogo: logoUrl };
      localStorage.setItem('userInfo', JSON.stringify(updatedUser));
      alert('Company logo uploaded successfully!');
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to upload company logo');
    } finally {
      setUploadingLogo(false);
    }
  };

  // Save Profile Handler
  const handleSaveProfile = async (e) => {
    e.preventDefault();
    setSavingProfile(true);
    try {
      const config = { headers: { Authorization: `Bearer ${authToken}` } };
      const res = await axios.put('/api/auth/profile', formData, config);
      alert('Profile & Business info updated successfully!');
      
      // Update local storage
      const savedUser = JSON.parse(localStorage.getItem('userInfo') || '{}');
      const updatedUser = { ...savedUser, ...res.data, ...formData };
      localStorage.setItem('userInfo', JSON.stringify(updatedUser));
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to update profile');
    } finally {
      setSavingProfile(false);
    }
  };

  // Compute Total Investment
  const totalSpent = useMemo(() => payments.reduce((acc, curr) => acc + (curr.amount || 0), 0), [payments]);

  // Compute Active Subscriptions/Renewals from Orders
  const recurringOrders = useMemo(() => {
    return orders.filter((o) => o.isRecurring || o.status === 'Completed');
  }, [orders]);

  const activeAvatarUrl = formData.profilePhoto || formData.companyLogo || userInfo?.profilePhoto || userInfo?.companyLogo;

  return (
    <div className="space-y-6 pb-20 md:pb-8 animate-in fade-in duration-300">
      
      {/* Account Hero Header */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 rounded-3xl p-6 text-white shadow-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-6 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-500/10 rounded-full blur-3xl -mr-32 -mt-32"></div>
        <div className="relative z-10 flex items-center gap-5">
          {activeAvatarUrl ? (
            <img
              src={activeAvatarUrl}
              alt={formData.name || 'Account'}
              className="w-16 h-16 rounded-2xl object-cover border-2 border-indigo-400/50 shadow-lg"
            />
          ) : (
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-indigo-500 to-cyan-400 flex items-center justify-center font-black text-2xl text-white shadow-lg">
              {(formData.name || userInfo?.name || 'C').charAt(0).toUpperCase()}
            </div>
          )}
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-black text-white tracking-tight">{formData.name || userInfo?.name || 'Customer Account'}</h1>
              <span className="px-2.5 py-0.5 bg-emerald-500/20 text-emerald-300 text-[10px] font-black uppercase tracking-wider rounded-full border border-emerald-500/30">
                Verified Account
              </span>
            </div>
            <p className="text-xs text-slate-300 font-medium mt-1 flex items-center gap-3">
              <span>{formData.email || userInfo?.email}</span>
              {(formData.phone || userInfo?.phone) && <span>• {formData.phone || userInfo?.phone}</span>}
              {formData.companyName && <span>• {formData.companyName}</span>}
            </p>
          </div>
        </div>

        {/* Quick Stats Pill */}
        <div className="relative z-10 flex items-center gap-4 bg-white/5 p-3 rounded-2xl border border-white/10 shrink-0">
          <div>
            <p className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Total Investment</p>
            <p className="text-xl font-black text-emerald-400">₹{totalSpent.toLocaleString()}</p>
          </div>
          <div className="h-8 w-px bg-white/10"></div>
          <div>
            <p className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Active Orders</p>
            <p className="text-xl font-black text-white">{orders.length}</p>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-200 pb-2">
        <button
          onClick={() => setActiveSubTab('profile')}
          className={`flex items-center gap-2 px-5 py-3 rounded-2xl font-bold text-xs transition-all ${
            activeSubTab === 'profile'
              ? 'bg-indigo-600 text-white shadow-md shadow-indigo-100'
              : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-50'
          }`}
        >
          <UserIcon size={16} /> Basic Profile & Business
        </button>

        <button
          onClick={() => setActiveSubTab('vault')}
          className={`flex items-center gap-2 px-5 py-3 rounded-2xl font-bold text-xs transition-all ${
            activeSubTab === 'vault'
              ? 'bg-indigo-600 text-white shadow-md shadow-indigo-100'
              : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-50'
          }`}
        >
          <ShieldCheck size={16} /> Document Vault (Google Drive)
        </button>

        <button
          onClick={() => setActiveSubTab('renewals')}
          className={`flex items-center gap-2 px-5 py-3 rounded-2xl font-bold text-xs transition-all ${
            activeSubTab === 'renewals'
              ? 'bg-indigo-600 text-white shadow-md shadow-indigo-100'
              : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-50'
          }`}
        >
          <Award size={16} /> Renewals & Subscriptions
        </button>

        <button
          onClick={() => setActiveSubTab('billing')}
          className={`flex items-center gap-2 px-5 py-3 rounded-2xl font-bold text-xs transition-all ${
            activeSubTab === 'billing'
              ? 'bg-indigo-600 text-white shadow-md shadow-indigo-100'
              : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-50'
          }`}
        >
          <Receipt size={16} /> Billing & Invoices
        </button>
      </div>

      {/* SUB-TAB CONTENT 1: PROFILE & BUSINESS INFO */}
      {activeSubTab === 'profile' && (
        <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm space-y-6 animate-in fade-in duration-300">
          {/* Visual Branding & Identity Uploader Card */}
          <div className="bg-slate-50/80 border border-slate-200/80 rounded-2xl p-5 space-y-4">
            <div>
              <h4 className="text-sm font-black text-slate-900 flex items-center gap-2">
                <Camera size={16} className="text-indigo-600" />
                Profile Photo & Company Logo
              </h4>
              <p className="text-xs text-slate-500 font-medium mt-0.5">
                Upload your personal photo to personalize your dashboard, and company logo for invoices and compliance filings.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
              
              {/* Person Profile Photo */}
              <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs flex items-center gap-4">
                <div className="relative shrink-0">
                  {formData.profilePhoto ? (
                    <img
                      src={formData.profilePhoto}
                      alt="Person Photo"
                      className="w-16 h-16 rounded-full object-cover border-2 border-indigo-500 shadow-sm"
                    />
                  ) : (
                    <div className="w-16 h-16 rounded-full bg-indigo-50 border-2 border-dashed border-indigo-200 flex items-center justify-center text-indigo-400 font-bold text-xs text-center p-1">
                      <UserIcon size={24} />
                    </div>
                  )}
                  {uploadingPhoto && (
                    <div className="absolute inset-0 bg-slate-900/60 rounded-full flex items-center justify-center text-white">
                      <Loader2 size={18} className="animate-spin" />
                    </div>
                  )}
                </div>

                <div className="flex-1 min-w-0">
                  <p className="text-xs font-black text-slate-900">Personal Photo</p>
                  <p className="text-[10px] text-slate-400 font-medium">Used next to your name & top bar</p>
                  <div className="flex items-center gap-2 mt-2">
                    <label className="cursor-pointer px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-bold rounded-lg border border-indigo-200/60 transition-colors inline-flex items-center gap-1.5">
                      <Upload size={12} />
                      <span>{formData.profilePhoto ? 'Change' : 'Upload Photo'}</span>
                      <input
                        type="file"
                        accept="image/*"
                        className="hidden"
                        onChange={handleUploadPhoto}
                        disabled={uploadingPhoto}
                      />
                    </label>
                    {formData.profilePhoto && (
                      <button
                        type="button"
                        onClick={() => setFormData(prev => ({ ...prev, profilePhoto: null }))}
                        className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors"
                        title="Remove Photo"
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Company / Business Logo */}
              <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs flex items-center gap-4">
                <div className="relative shrink-0">
                  {formData.companyLogo ? (
                    <img
                      src={formData.companyLogo}
                      alt="Company Logo"
                      className="w-16 h-16 rounded-xl object-contain bg-slate-50 border-2 border-indigo-500 shadow-sm p-1"
                    />
                  ) : (
                    <div className="w-16 h-16 rounded-xl bg-slate-50 border-2 border-dashed border-slate-300 flex items-center justify-center text-slate-400 font-bold text-xs text-center p-1">
                      <ImageIcon size={24} />
                    </div>
                  )}
                  {uploadingLogo && (
                    <div className="absolute inset-0 bg-slate-900/60 rounded-xl flex items-center justify-center text-white">
                      <Loader2 size={18} className="animate-spin" />
                    </div>
                  )}
                </div>

                <div className="flex-1 min-w-0">
                  <p className="text-xs font-black text-slate-900">Company Logo</p>
                  <p className="text-[10px] text-slate-400 font-medium">Used on invoices & filings</p>
                  <div className="flex items-center gap-2 mt-2">
                    <label className="cursor-pointer px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-bold rounded-lg border border-indigo-200/60 transition-colors inline-flex items-center gap-1.5">
                      <Upload size={12} />
                      <span>{formData.companyLogo ? 'Change' : 'Upload Logo'}</span>
                      <input
                        type="file"
                        accept="image/*"
                        className="hidden"
                        onChange={handleUploadLogo}
                        disabled={uploadingLogo}
                      />
                    </label>
                    {formData.companyLogo && (
                      <button
                        type="button"
                        onClick={() => setFormData(prev => ({ ...prev, companyLogo: null }))}
                        className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors"
                        title="Remove Logo"
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </div>
                </div>
              </div>

            </div>
          </div>

          <form onSubmit={handleSaveProfile} className="space-y-5">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              
              {/* Full Name */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-600 uppercase flex items-center gap-1.5">
                  <UserIcon size={14} className="text-indigo-500" /> Full Name / Primary Contact
                </label>
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full p-3.5 bg-slate-50 border border-slate-200 rounded-2xl text-sm font-bold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
                  placeholder="Enter full name"
                />
              </div>

              {/* Email Address */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-600 uppercase flex items-center gap-1.5">
                  <Mail size={14} className="text-indigo-500" /> Email Address
                </label>
                <input
                  type="email"
                  required
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  className="w-full p-3.5 bg-slate-50 border border-slate-200 rounded-2xl text-sm font-bold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
                  placeholder="name@company.com"
                />
              </div>

              {/* Phone Number */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-600 uppercase flex items-center gap-1.5">
                  <Phone size={14} className="text-indigo-500" /> Phone Number
                </label>
                <input
                  type="tel"
                  value={formData.phone}
                  onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                  className="w-full p-3.5 bg-slate-50 border border-slate-200 rounded-2xl text-sm font-bold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
                  placeholder="+91 9876543210"
                />
              </div>

              {/* Business / Company Name */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-600 uppercase flex items-center gap-1.5">
                  <Building2 size={14} className="text-indigo-500" /> Business / Company Name
                </label>
                <input
                  type="text"
                  value={formData.companyName}
                  onChange={(e) => setFormData({ ...formData, companyName: e.target.value })}
                  className="w-full p-3.5 bg-slate-50 border border-slate-200 rounded-2xl text-sm font-bold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
                  placeholder="ABC Enterprises"
                />
              </div>

              {/* Business Entity Type */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-600 uppercase">Entity Type</label>
                <select
                  value={formData.businessType}
                  onChange={(e) => setFormData({ ...formData, businessType: e.target.value })}
                  className="w-full p-3.5 bg-slate-50 border border-slate-200 rounded-2xl text-sm font-bold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
                >
                  <option value="Proprietorship">Proprietorship</option>
                  <option value="Private Limited">Private Limited (Pvt Ltd)</option>
                  <option value="LLP">Limited Liability Partnership (LLP)</option>
                  <option value="Partnership Firm">Partnership Firm</option>
                  <option value="One Person Company">One Person Company (OPC)</option>
                  <option value="Individual">Individual</option>
                </select>
              </div>

              {/* GSTIN */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-600 uppercase">GSTIN (Optional)</label>
                <input
                  type="text"
                  value={formData.gstin}
                  onChange={(e) => setFormData({ ...formData, gstin: e.target.value })}
                  className="w-full p-3.5 bg-slate-50 border border-slate-200 rounded-2xl text-sm font-bold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
                  placeholder="36AAAAA0000A1Z5"
                />
              </div>

            </div>

            {/* Registered Address */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-600 uppercase flex items-center gap-1.5">
                <MapPin size={14} className="text-indigo-500" /> Business Registered Address
              </label>
              <textarea
                rows={3}
                value={formData.address}
                onChange={(e) => setFormData({ ...formData, address: e.target.value })}
                className="w-full p-3.5 bg-slate-50 border border-slate-200 rounded-2xl text-sm font-bold text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
                placeholder="Enter complete office/registered business address..."
              />
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="submit"
                disabled={savingProfile}
                className="px-8 py-3.5 bg-indigo-600 hover:bg-slate-900 text-white rounded-2xl font-black text-sm shadow-xl shadow-indigo-100 transition-all flex items-center gap-2"
              >
                {savingProfile ? 'Saving...' : <><Save size={16} /> Save Profile Changes</>}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* SUB-TAB CONTENT 2: MY DOCUMENTS VAULT */}
      {activeSubTab === 'vault' && (
        <ProfileDocumentsVault token={authToken} orders={orders} />
      )}

      {/* SUB-TAB CONTENT 3: RENEWALS & SUBSCRIPTIONS */}
      {activeSubTab === 'renewals' && (
        <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm space-y-6 animate-in fade-in duration-300">
          <div>
            <h3 className="text-lg font-black text-slate-900 tracking-tight flex items-center gap-2">
              <Award className="text-indigo-600" size={20} />
              Active Registrations & Renewal Cycles
            </h3>
            <p className="text-xs text-slate-500 font-medium mt-0.5">
              Track upcoming registration renewals, annual compliance filing due dates, and renewal invoices.
            </p>
          </div>

          <div className="space-y-4">
            {recurringOrders.length === 0 ? (
              <div className="p-12 text-center text-slate-400 italic bg-slate-50 rounded-2xl border border-dashed border-slate-200">
                <Clock size={36} className="mx-auto mb-2 opacity-30 text-slate-400" />
                <p className="text-sm font-bold">No active recurring renewals set up yet.</p>
                <p className="text-xs text-slate-400 mt-1">When your service is up for annual renewal, you will receive reminders and notices here.</p>
              </div>
            ) : (
              recurringOrders.map((order) => (
                <div key={order._id} className="p-5 rounded-2xl border border-slate-100 bg-slate-50/50 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-black text-slate-800 text-base">{order.serviceName}</span>
                      <span className="px-2.5 py-0.5 bg-indigo-50 text-indigo-700 text-[10px] font-bold rounded-full border border-indigo-100">
                        {order.packageName || 'Yearly Cycle'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 font-semibold">
                      Order ID: #{order._id?.slice(-6).toUpperCase()} • Status: <strong className="text-emerald-600">{order.status}</strong>
                    </p>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <p className="text-[10px] font-black text-slate-400 uppercase">Renewal Price</p>
                      <p className="text-base font-black text-slate-900">₹{(order.price || 0).toLocaleString()}</p>
                    </div>

                    <a
                      href={`/renewals/pay/${order._id}`}
                      className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl font-bold text-xs shadow-md shadow-emerald-100 transition-all flex items-center gap-1.5"
                    >
                      <IndianRupee size={14} /> Pay Renewal
                    </a>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* SUB-TAB CONTENT 4: INVOICES & BILLING HISTORY */}
      {activeSubTab === 'billing' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          
          {/* Investment KPI */}
          <div className="bg-slate-900 rounded-3xl p-6 text-white relative overflow-hidden shadow-xl">
            <div className="relative z-10 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
              <div>
                <p className="text-slate-400 text-[10px] font-black uppercase tracking-widest mb-1">Total Verified Investment</p>
                <h2 className="text-3xl font-black text-white tracking-tight">₹{totalSpent.toLocaleString()}</h2>
              </div>
              <div className="flex gap-3">
                <div className="bg-white/10 px-4 py-2 rounded-2xl border border-white/10">
                  <p className="text-slate-400 text-[9px] font-black uppercase mb-0.5">Total Transactions</p>
                  <p className="font-black text-lg text-white">{payments.length}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Transactions List */}
          <div>
            <div className="flex justify-between items-center mb-4 px-1">
              <h3 className="font-black text-slate-800 text-lg flex items-center gap-2">
                <History size={18} className="text-indigo-600" />
                Payment & Invoice History
              </h3>
            </div>

            <div className="space-y-3 lg:grid lg:grid-cols-2 lg:gap-4 lg:space-y-0">
              {payments.map((payment) => (
                <div key={payment._id} className="bg-white p-4 rounded-3xl border border-slate-100 shadow-sm flex items-center justify-between group hover:border-indigo-100 transition-all">
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 bg-slate-50 text-indigo-600 rounded-2xl flex items-center justify-center border border-slate-100 group-hover:bg-indigo-50 transition-colors">
                      <Receipt size={20} />
                    </div>
                    <div className="max-w-[150px] md:max-w-none">
                      <h4 className="font-black text-slate-800 text-sm line-clamp-1">{payment.order?.serviceName || 'Service Payment'}</h4>
                      <div className="flex items-center gap-1.5 text-[9px] text-slate-400 font-bold uppercase tracking-wider">
                        <CheckCircle2 size={10} className={payment.status === 'Completed' ? 'text-emerald-500' : 'text-amber-500'} />
                        <span>{payment.status} • {new Date(payment.createdAt).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>
                  <div className="text-right flex flex-col items-end gap-1">
                    <span className="font-black text-slate-800 text-sm">₹{payment.amount?.toLocaleString()}</span>
                    <a
                      href={payment.invoiceUrl || '#'}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center gap-1 text-[9px] font-black text-indigo-600 uppercase tracking-widest bg-indigo-50 px-2.5 py-1 rounded-lg hover:bg-indigo-600 hover:text-white transition-all"
                    >
                      Invoice <Download size={10} />
                    </a>
                  </div>
                </div>
              ))}

              {payments.length === 0 && (
                <div className="bg-slate-50 border-2 border-dashed border-slate-200 rounded-3xl p-10 text-center text-slate-400 col-span-2">
                  <Receipt size={32} className="mx-auto mb-2 opacity-30" />
                  <p className="text-xs font-bold">No payment history found</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Support Mini Card */}
      <div className="bg-indigo-50 rounded-3xl p-6 border border-indigo-100 flex items-start gap-4">
        <div className="w-10 h-10 bg-white rounded-2xl flex items-center justify-center shadow-sm text-indigo-600 shrink-0">
          <ArrowUpRight size={20} />
        </div>
        <div>
          <h4 className="text-sm font-black text-indigo-900 mb-1">Billing or Profile Questions?</h4>
          <p className="text-[10px] text-indigo-700/70 mb-3 leading-relaxed">
            If you have any questions regarding your business profile, documents, or invoice statements, our dedicated accounts team is available to assist you.
          </p>
          <a
            href="https://wa.me/918008530606"
            target="_blank"
            rel="noreferrer"
            className="inline-block bg-indigo-600 text-white px-5 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest shadow-lg shadow-indigo-200 hover:bg-indigo-700 transition-all"
          >
            Contact Account Executive
          </a>
        </div>
      </div>

    </div>
  );
};

export default AccountsView;
