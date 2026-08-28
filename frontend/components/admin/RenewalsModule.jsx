import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import {
  RefreshCw,
  Search,
  Plus,
  Send,
  Edit3,
  Calendar,
  User as UserIcon,
  IndianRupee,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Bell,
  Mail,
  Smartphone,
  ShieldCheck,
  Award
} from 'lucide-react';

const Card = ({ children, className = '' }) => (
  <div className={`rounded-3xl border border-slate-100 bg-white shadow-sm hover:shadow-md transition-shadow ${className}`}>
    {children}
  </div>
);

const RenewalsModule = ({ token, onViewOrder }) => {
  const [renewals, setRenewals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState('All');
  
  // Modal states
  const [selectedRenewalForPrice, setSelectedRenewalForPrice] = useState(null);
  const [newPrice, setNewPrice] = useState('');
  const [isSendingReminder, setIsSendingReminder] = useState({});

  const config = useMemo(() => ({
    headers: { Authorization: `Bearer ${token}` }
  }), [token]);

  const fetchRenewals = async () => {
    try {
      setLoading(true);
      const res = await axios.get('/api/renewals/pending', config);
      setRenewals(res.data?.data || []);
      setError(null);
    } catch (err) {
      // Fallback to /api/recurring if /api/renewals isn't populated
      try {
        const fallback = await axios.get('/api/recurring', config);
        setRenewals(fallback.data || []);
      } catch (fErr) {
        setError('Failed to load certification and registration renewals.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRenewals();
  }, [token]);

  // Update Renewal Price
  const handleUpdatePrice = async (e) => {
    e.preventDefault();
    if (!selectedRenewalForPrice || !newPrice || isNaN(newPrice)) return alert('Please enter a valid price');
    
    try {
      await axios.put(`/api/renewals/${selectedRenewalForPrice._id}/price`, { price: Number(newPrice) }, config);
      alert(`Renewal price updated to ₹${newPrice} successfully`);
      setSelectedRenewalForPrice(null);
      setNewPrice('');
      fetchRenewals();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to update renewal price');
    }
  };

  // Dispatch Email + Push Reminder
  const handleSendReminder = async (renewalId) => {
    try {
      setIsSendingReminder((prev) => ({ ...prev, [renewalId]: true }));
      await axios.post(`/api/renewals/${renewalId}/send-reminder`, {}, config);
      alert('Renewal notice dispatched successfully via Email and Push Notification!');
      fetchRenewals();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to dispatch renewal reminder');
    } finally {
      setIsSendingReminder((prev) => ({ ...prev, [renewalId]: false }));
    }
  };

  // Filtered Renewals
  const filteredRenewals = useMemo(() => {
    return renewals.filter((r) => {
      const client = (r.clientName || r.user?.name || '').toLowerCase();
      const service = (r.serviceName || '').toLowerCase();
      const query = searchQuery.toLowerCase();
      const matchesSearch = client.includes(query) || service.includes(query);

      if (!matchesSearch) return false;

      if (activeTab === 'Needs Review') return r.status === 'InternalAlertSent';
      if (activeTab === 'Price Set') return r.status === 'PriceSet';
      if (activeTab === 'Reminder Sent') return r.status === 'ReminderSent' || r.status === 'PaymentPending';
      if (activeTab === 'Completed') return r.status === 'PaymentSuccess';
      return true;
    });
  }, [renewals, searchQuery, activeTab]);

  // KPIs
  const stats = useMemo(() => {
    const total = renewals.length;
    const needsReview = renewals.filter((r) => r.status === 'InternalAlertSent').length;
    const reminderSent = renewals.filter((r) => r.status === 'ReminderSent' || r.status === 'PaymentPending').length;
    const totalValue = renewals.reduce((acc, r) => acc + (r.renewalPrice || r.price || 0), 0);
    return { total, needsReview, reminderSent, totalValue };
  }, [renewals]);

  const getStatusBadge = (status) => {
    switch (status) {
      case 'InternalAlertSent':
        return <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-amber-50 text-amber-700 border border-amber-200/80 rounded-full text-xs font-bold"><AlertTriangle size={12} /> Needs Price Review</span>;
      case 'PriceSet':
        return <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-indigo-50 text-indigo-700 border border-indigo-200/80 rounded-full text-xs font-bold"><ShieldCheck size={12} /> Price Set</span>;
      case 'ReminderSent':
      case 'PaymentPending':
        return <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-purple-50 text-purple-700 border border-purple-200/80 rounded-full text-xs font-bold"><Mail size={12} /> Email & Push Sent</span>;
      case 'PaymentSuccess':
        return <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-emerald-50 text-emerald-700 border border-emerald-200/80 rounded-full text-xs font-bold"><CheckCircle2 size={12} /> Renewed</span>;
      default:
        return <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-slate-100 text-slate-600 border border-slate-200/80 rounded-full text-xs font-bold"><Clock size={12} /> Scheduled</span>;
    }
  };

  if (loading) return <div className="p-20 text-center text-slate-500 font-bold">Synchronizing Certification & Renewal Records...</div>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-2xl font-black text-slate-900 tracking-tight flex items-center gap-2.5">
            <Award className="text-indigo-600" size={26} />
            Certifications & Registration Renewals
          </h2>
          <p className="text-sm text-slate-500 font-medium mt-1">
            Automated recurring reminders, price updates, and payment collection via Email & Push Notifications.
          </p>
        </div>

        <div className="flex gap-2">
          <button 
            onClick={fetchRenewals} 
            className="p-3 bg-white border border-slate-200 rounded-2xl text-slate-600 hover:bg-slate-50 transition-all shadow-sm"
          >
            <RefreshCw size={18} />
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-bold text-slate-400 uppercase">Total Renewals</p>
              <p className="text-2xl font-black text-slate-900 mt-1">{stats.total}</p>
            </div>
            <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center font-bold">
              <Award size={24} />
            </div>
          </div>
        </Card>

        <Card className="p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-bold text-amber-500 uppercase">Needs Price Review</p>
              <p className="text-2xl font-black text-amber-600 mt-1">{stats.needsReview}</p>
            </div>
            <div className="w-12 h-12 bg-amber-50 text-amber-600 rounded-2xl flex items-center justify-center font-bold">
              <AlertTriangle size={24} />
            </div>
          </div>
        </Card>

        <Card className="p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-bold text-purple-500 uppercase">Reminders Dispatched</p>
              <p className="text-2xl font-black text-purple-600 mt-1">{stats.reminderSent}</p>
            </div>
            <div className="w-12 h-12 bg-purple-50 text-purple-600 rounded-2xl flex items-center justify-center font-bold">
              <Send size={24} />
            </div>
          </div>
        </Card>

        <Card className="p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-bold text-emerald-500 uppercase">Total Pipeline Value</p>
              <p className="text-2xl font-black text-emerald-600 mt-1">₹{stats.totalValue.toLocaleString()}</p>
            </div>
            <div className="w-12 h-12 bg-emerald-50 text-emerald-600 rounded-2xl flex items-center justify-center font-bold">
              <IndianRupee size={24} />
            </div>
          </div>
        </Card>
      </div>

      {/* Filter Tabs & Search */}
      <div className="flex flex-col sm:flex-row justify-between gap-4">
        <div className="flex flex-wrap gap-2">
          {['All', 'Needs Review', 'Price Set', 'Reminder Sent', 'Completed'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2.5 rounded-2xl font-bold text-xs transition-all ${
                activeTab === tab 
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-200' 
                  : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-50'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        <div className="relative min-w-[280px]">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
          <input
            type="text"
            placeholder="Search by client or registration..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-200 rounded-2xl text-sm font-medium outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
          />
        </div>
      </div>

      {/* Renewals Table & Cards Grid */}
      <div className="space-y-4">
        {filteredRenewals.length === 0 ? (
          <Card className="py-16 text-center">
            <Award className="mx-auto text-slate-300 mb-3" size={48} />
            <h3 className="font-bold text-slate-800 text-lg">No renewal records found</h3>
            <p className="text-sm text-slate-500 mt-1">Select "Make Recurring" on any order or set up a recurring compliance schedule.</p>
          </Card>
        ) : (
          filteredRenewals.map((item) => (
            <Card key={item._id} className="p-5 border border-slate-100 hover:border-indigo-100 transition-all">
              <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
                
                {/* Left Info */}
                <div className="space-y-2 flex-1">
                  <div className="flex items-center gap-3">
                    <span className="font-black text-slate-900 text-lg">{item.serviceName}</span>
                    {getStatusBadge(item.status)}
                  </div>

                  <div className="flex flex-wrap items-center gap-4 text-xs font-semibold text-slate-600">
                    <span className="flex items-center gap-1.5 bg-slate-50 px-3 py-1 rounded-xl border border-slate-100">
                      <UserIcon size={14} className="text-indigo-500" />
                      Client: <strong className="text-slate-900">{item.clientName || item.user?.name || 'N/A'}</strong>
                    </span>

                    <span className="flex items-center gap-1.5 bg-slate-50 px-3 py-1 rounded-xl border border-slate-100">
                      <Calendar size={14} className="text-indigo-500" />
                      Due Date: <strong className="text-slate-900">{new Date(item.nextRunDate).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}</strong>
                    </span>

                    <span className="flex items-center gap-1.5 bg-slate-50 px-3 py-1 rounded-xl border border-slate-100">
                      <RefreshCw size={14} className="text-indigo-500" />
                      Frequency: <strong className="text-slate-900">{item.frequency || 'Yearly'}</strong>
                    </span>

                    <span className="flex items-center gap-1.5 bg-emerald-50 text-emerald-700 px-3 py-1 rounded-xl border border-emerald-100">
                      <IndianRupee size={14} />
                      Price: <strong>₹{(item.renewalPrice || item.price || 0).toLocaleString()}</strong>
                    </span>
                  </div>
                </div>

                {/* Right Actions */}
                <div className="flex items-center gap-3 self-end lg:self-center shrink-0">
                  <button
                    onClick={() => {
                      setSelectedRenewalForPrice(item);
                      setNewPrice(String(item.renewalPrice || item.price || ''));
                    }}
                    className="px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-2xl text-xs font-bold transition-all flex items-center gap-1.5"
                  >
                    <Edit3 size={14} /> Edit Price & Date
                  </button>

                  <button
                    onClick={() => handleSendReminder(item._id)}
                    disabled={isSendingReminder[item._id]}
                    className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-2xl text-xs font-black shadow-md shadow-indigo-100 transition-all flex items-center gap-1.5 disabled:opacity-50"
                  >
                    <Send size={14} />
                    {isSendingReminder[item._id] ? 'Sending Notice...' : 'Send Email & Push Reminder'}
                  </button>
                </div>

              </div>
            </Card>
          ))
        )}
      </div>

      {/* Edit Renewal Price Modal */}
      {selectedRenewalForPrice && (
        <div className="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm">
          <div className="bg-white rounded-3xl max-w-md w-full p-6 shadow-2xl space-y-5">
            <div className="flex justify-between items-center border-b pb-3">
              <h3 className="text-lg font-black text-slate-900 flex items-center gap-2">
                <Edit3 className="text-indigo-600" size={18} /> Update Renewal Price
              </h3>
              <button 
                onClick={() => setSelectedRenewalForPrice(null)} 
                className="text-slate-400 hover:text-slate-600 text-lg font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleUpdatePrice} className="space-y-4">
              <div>
                <p className="text-xs font-bold text-slate-400 uppercase">Service Name</p>
                <p className="text-sm font-black text-slate-800">{selectedRenewalForPrice.serviceName}</p>
                <p className="text-xs text-slate-500">{selectedRenewalForPrice.clientName}</p>
              </div>

              <div>
                <label className="text-xs font-bold text-slate-600 uppercase mb-1 block">New Renewal Price (₹)</label>
                <input
                  type="number"
                  required
                  value={newPrice}
                  onChange={(e) => setNewPrice(e.target.value)}
                  className="w-full p-3 bg-slate-50 border border-slate-200 rounded-2xl text-base font-black outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Enter renewal amount"
                />
              </div>

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setSelectedRenewalForPrice(null)}
                  className="flex-1 py-3 bg-slate-100 text-slate-600 font-bold rounded-2xl text-xs hover:bg-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 py-3 bg-indigo-600 text-white font-black rounded-2xl text-xs shadow-md shadow-indigo-100 hover:bg-indigo-700"
                >
                  Save & Update Status
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default RenewalsModule;
