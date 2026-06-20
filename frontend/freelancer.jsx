import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { 
  LayoutDashboard, Briefcase, FolderKanban, CheckSquare, Clock3, 
  FileText, ClipboardList, MessageSquare, IndianRupee, Bell, 
  ShieldCheck, DollarSign, Users, Layers, LogOut, Play, Square, Award
} from 'lucide-react';

import FreelancerSidebar from './components/freelancer/FreelancerSidebar';
import FreelancerTopbar from './components/freelancer/FreelancerTopbar';
import DashboardOverviewModule from './components/employee/DashboardOverviewModule';
import WorkQueueModule from './components/employee/WorkQueueModule';
import OrderProcessingModule from './components/employee/OrderProcessingModule';
import { TaskManagementModule } from './modules/orders/v1.1';
import TimeTrackingModule from './components/employee/TimeTrackingModule';
import DocumentsModule from './components/employee/DocumentsModule';
import RequirementsModule from './components/employee/RequirementsModule';
import SupportModule from './components/employee/SupportModule';
import CommercialsModule from './components/employee/CommercialsModule';
import { dummyTickets } from './components/employee/mockData';
import { useNotifications, NotificationsFeed, InAppBanner } from './modules/notifications/v1.1';
import HRMSModule from './modules/hrms/v1.1/index.jsx';
import ServicesMasterView from './components/admin/ServicesMasterView';

// Freelancer custom subcomponents/views directly integrated
const AvailableJobsModule = ({ broadcasts, onClaimJob }) => (
  <div className="space-y-6">
    <div className="flex justify-between items-center mb-4">
      <h3 className="text-xl font-black text-slate-900">Open Broadcast Pools</h3>
    </div>
    {broadcasts.length === 0 ? (
      <div className="bg-white rounded-3xl p-12 text-center border border-slate-100 shadow-sm">
        <Bell className="w-12 h-12 text-slate-350 mx-auto mb-4" />
        <h4 className="text-lg font-bold text-slate-800">No active job broadcasts</h4>
        <p className="text-slate-400 mt-1 max-w-sm mx-auto font-medium">New requests matching your specializations will appear here in real-time.</p>
      </div>
    ) : (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {broadcasts.map((job) => (
          <div key={job._id} className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm relative overflow-hidden flex flex-col justify-between">
            <div>
              <div className="flex justify-between items-start gap-4">
                <span className="bg-indigo-50 text-indigo-600 px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider">
                  {job.serviceName}
                </span>
                <span className="text-2xl font-black text-slate-900">₹{job.freelancerPayout}</span>
              </div>
              <h4 className="text-lg font-black text-slate-900 mt-4">{job.packageName}</h4>
              <p className="text-xs text-slate-400 font-bold uppercase tracking-tight mt-1">Broadcasted: {new Date(job.createdAt).toLocaleDateString()}</p>
            </div>
            <button 
              onClick={() => onClaimJob(job._id)}
              className="w-full h-12 bg-slate-900 hover:bg-slate-800 text-white font-black rounded-xl mt-6 transition flex items-center justify-center gap-2"
            >
              Accept Job Request
            </button>
          </div>
        ))}
      </div>
    )}
  </div>
);

const EarningsLedgerModule = ({ ledger }) => {
  const totalEarned = ledger
    .filter(item => item.status === 'Paid')
    .reduce((sum, item) => sum + item.amount, 0);

  const pendingPayout = ledger
    .filter(item => item.status !== 'Paid')
    .reduce((sum, item) => sum + item.amount, 0);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm flex items-center gap-5">
          <div className="w-14 h-14 rounded-2xl bg-green-50 flex items-center justify-center text-green-600">
            <DollarSign className="w-7 h-7" />
          </div>
          <div>
            <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">Earned Payouts</p>
            <h3 className="text-3xl font-black text-slate-900 mt-1">₹{totalEarned}</h3>
          </div>
        </div>
        <div className="bg-white rounded-3xl p-6 border border-slate-100 shadow-sm flex items-center gap-5">
          <div className="w-14 h-14 rounded-2xl bg-yellow-50 flex items-center justify-center text-yellow-600">
            <Clock3 className="w-7 h-7" />
          </div>
          <div>
            <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">Pending Payouts</p>
            <h3 className="text-3xl font-black text-slate-900 mt-1">₹{pendingPayout}</h3>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-3xl p-8 border border-slate-100 shadow-sm">
        <h3 className="text-xl font-black text-slate-900 mb-6">Payment Ledger History</h3>
        
        {ledger.length === 0 ? (
          <div className="text-center py-12">
            <DollarSign className="w-12 h-12 text-slate-300 mx-auto mb-4" />
            <h4 className="text-lg font-bold text-slate-800">No transactions recorded</h4>
            <p className="text-slate-400 mt-1 font-medium">Approved earnings and payout checks will appear here in chronological order.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs font-semibold text-slate-600">
              <thead>
                <tr className="border-b border-slate-100 text-[10px] uppercase text-slate-400 tracking-wider">
                  <th className="py-4 px-4 font-black">Order ID</th>
                  <th className="py-4 px-4 font-black">Service Category</th>
                  <th className="py-4 px-4 font-black">Amount</th>
                  <th className="py-4 px-4 font-black">Status</th>
                  <th className="py-4 px-4 font-black">Date</th>
                  <th className="py-4 px-4 font-black">Reference ID</th>
                </tr>
              </thead>
              <tbody>
                {ledger.map((payout) => (
                  <tr key={payout._id} className="border-b border-slate-50 hover:bg-slate-50/50 transition">
                    <td className="py-4 px-4 font-bold text-slate-950">{payout.order?.packageName || 'N/A'}</td>
                    <td className="py-4 px-4">{payout.order?.serviceName || 'N/A'}</td>
                    <td className="py-4 px-4 font-bold text-slate-950">₹{payout.amount}</td>
                    <td className="py-4 px-4">
                      <span className={`px-2.5 py-1 rounded-full font-black uppercase tracking-wider text-[9px] ${payout.status === 'Paid' ? 'bg-green-50 text-green-700 border border-green-100' : payout.status === 'Approved' ? 'bg-indigo-50 text-indigo-700 border border-indigo-100' : 'bg-yellow-50 text-yellow-700 border border-yellow-100'}`}>
                        {payout.status}
                      </span>
                    </td>
                    <td className="py-4 px-4">{new Date(payout.createdAt).toLocaleDateString()}</td>
                    <td className="py-4 px-4">
                      {payout.status === 'Paid' ? (
                        <div className="font-mono text-[10px] text-slate-500 uppercase">
                          {payout.method} - {payout.transactionRef || 'N/A'}
                        </div>
                      ) : (
                        <span className="text-slate-400">Processing...</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

const FreelancerOverviewModule = ({ userInfo }) => (
  <div className="space-y-6">
    <div className="bg-white rounded-3xl p-8 border border-slate-100 shadow-sm grid md:grid-cols-2 gap-8">
      <div>
        <h3 className="text-lg font-black text-slate-900 mb-4">Qualifications & Experience</h3>
        <div className="space-y-4 font-semibold text-slate-600">
          <div className="flex justify-between border-b border-slate-50 pb-2">
            <span>Years of Experience:</span>
            <span className="text-slate-900 font-bold">{userInfo?.yearsOfExperience} years</span>
          </div>
          <div className="flex justify-between border-b border-slate-50 pb-2">
            <span>Specializations:</span>
            <span className="text-slate-900 font-bold">{userInfo?.skills?.join(', ') || 'N/A'}</span>
          </div>
          {userInfo?.resumeUrl && (
            <div className="flex justify-between pb-2">
              <span>Resume Link:</span>
              <a href={userInfo.resumeUrl} target="_blank" rel="noopener noreferrer" className="text-indigo-600 hover:underline font-bold">
                View Resume
              </a>
            </div>
          )}
        </div>
      </div>

      <div>
        <h3 className="text-lg font-black text-slate-900 mb-4">Settlement Account</h3>
        <div className="space-y-4 font-semibold text-slate-600">
          <div className="flex justify-between border-b border-slate-50 pb-2">
            <span>Bank Name:</span>
            <span className="text-slate-900 font-bold">{userInfo?.bankDetails?.bankName}</span>
          </div>
          <div className="flex justify-between border-b border-slate-50 pb-2">
            <span>Account Name:</span>
            <span className="text-slate-900 font-bold">{userInfo?.bankDetails?.accountName}</span>
          </div>
          <div className="flex justify-between border-b border-slate-50 pb-2">
            <span>Account Number:</span>
            <span className="text-slate-900 font-bold">{userInfo?.bankDetails?.accountNumber}</span>
          </div>
          <div className="flex justify-between pb-2">
            <span>IFSC Code:</span>
            <span className="text-slate-900 font-bold">{userInfo?.bankDetails?.ifscCode}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
);

const FreelancerSettingsModule = ({ token }) => {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    phone: '',
    skills: '',
    yearsOfExperience: '',
    resumeUrl: '',
    panCard: '',
    bankDetails: {
      bankName: '',
      accountName: '',
      accountNumber: '',
      ifscCode: ''
    }
  });

  const authConfig = useMemo(() => ({
    headers: { Authorization: `Bearer ${token}` }
  }), [token]);

  const fetchProfile = useCallback(async () => {
    try {
      setLoading(true);
      const { data } = await axios.get('/api/auth/profile', authConfig);
      setProfile(data);
      
      const source = data.pendingProfileUpdate || data;
      setFormData({
        name: source.name || '',
        phone: source.phone || '',
        skills: Array.isArray(source.skills) ? source.skills.join(', ') : source.skills || '',
        yearsOfExperience: source.yearsOfExperience ?? '',
        resumeUrl: source.resumeUrl || '',
        panCard: source.panCard || '',
        bankDetails: {
          bankName: source.bankDetails?.bankName || '',
          accountName: source.bankDetails?.accountName || '',
          accountNumber: source.bankDetails?.accountNumber || '',
          ifscCode: source.bankDetails?.ifscCode || ''
        }
      });
    } catch (error) {
      console.error('Failed to fetch profile:', error);
    } finally {
      setLoading(false);
    }
  }, [authConfig]);

  useEffect(() => {
    fetchProfile();
  }, [fetchProfile]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      const skillsArray = formData.skills.split(',').map(s => s.trim()).filter(Boolean);
      const payload = {
        ...formData,
        skills: skillsArray,
        yearsOfExperience: Number(formData.yearsOfExperience)
      };
      await axios.put('/api/freelancer/profile-update', payload, authConfig);
      alert('Profile update request submitted successfully. Awaiting admin approval.');
      fetchProfile();
    } catch (error) {
      alert(error?.response?.data?.message || 'Failed to update profile.');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <div className="text-center py-12 font-bold text-slate-500">Loading profile details...</div>;
  }

  return (
    <div className="space-y-6">
      {profile?.pendingProfileUpdate && (
        <div className="bg-amber-50 border border-amber-200 rounded-3xl p-5 text-amber-800 text-sm font-semibold flex items-center gap-3">
          <Clock3 className="w-5 h-5 shrink-0" />
          <div>
            <p className="font-bold text-amber-900">Pending Admin Approval</p>
            <p className="mt-0.5 text-xs text-amber-700">You have submitted a profile update request. You can modify your request below. The changes will be applied to your active profile once approved by the admin.</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Approved Current Profile Card */}
        <div className="bg-white rounded-3xl p-8 border border-slate-100 shadow-sm space-y-6">
          <h3 className="text-lg font-black text-slate-900 border-b border-slate-50 pb-4">Approved Profile (Active)</h3>
          
          <div className="space-y-4 font-semibold text-slate-600">
            <div className="flex justify-between pb-2 border-b border-slate-50">
              <span>Name:</span>
              <span className="text-slate-900 font-bold">{profile?.name}</span>
            </div>
            <div className="flex justify-between pb-2 border-b border-slate-50">
              <span>Phone Number:</span>
              <span className="text-slate-900 font-bold">{profile?.phone || 'N/A'}</span>
            </div>
            <div className="flex justify-between pb-2 border-b border-slate-50">
              <span>Years of Experience:</span>
              <span className="text-slate-900 font-bold">{profile?.yearsOfExperience} years</span>
            </div>
            <div className="flex justify-between pb-2 border-b border-slate-50">
              <span>Skills & Specializations:</span>
              <span className="text-slate-900 font-bold">{profile?.skills?.join(', ') || 'N/A'}</span>
            </div>
            <div className="flex justify-between pb-2 border-b border-slate-50">
              <span>PAN Card:</span>
              <span className="text-slate-900 font-bold">{profile?.panCard || 'N/A'}</span>
            </div>
            {profile?.resumeUrl && (
              <div className="flex justify-between pb-2 border-b border-slate-50">
                <span>Resume Link:</span>
                <a href={profile.resumeUrl} target="_blank" rel="noopener noreferrer" className="text-indigo-600 hover:underline font-bold">
                  View Resume
                </a>
              </div>
            )}

            <h4 className="text-sm font-black text-slate-800 pt-4 pb-2">Settlement Account</h4>
            <div className="flex justify-between pb-2 border-b border-slate-50">
              <span>Bank Name:</span>
              <span className="text-slate-900 font-bold">{profile?.bankDetails?.bankName || 'N/A'}</span>
            </div>
            <div className="flex justify-between pb-2 border-b border-slate-50">
              <span>Account Name:</span>
              <span className="text-slate-900 font-bold">{profile?.bankDetails?.accountName || 'N/A'}</span>
            </div>
            <div className="flex justify-between pb-2 border-b border-slate-50">
              <span>Account Number:</span>
              <span className="text-slate-900 font-bold">{profile?.bankDetails?.accountNumber || 'N/A'}</span>
            </div>
            <div className="flex justify-between pb-2">
              <span>IFSC Code:</span>
              <span className="text-slate-900 font-bold">{profile?.bankDetails?.ifscCode || 'N/A'}</span>
            </div>
          </div>
        </div>

        {/* Update Form Card */}
        <div className="bg-white rounded-3xl p-8 border border-slate-100 shadow-sm">
          <h3 className="text-lg font-black text-slate-900 border-b border-slate-50 pb-4 mb-6">Edit Profile Details</h3>
          
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Full Name</label>
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={e => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-4 py-2 text-xs border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-indigo-500 font-semibold"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Phone Number</label>
                <input
                  type="text"
                  required
                  value={formData.phone}
                  onChange={e => setFormData({ ...formData, phone: e.target.value })}
                  className="w-full px-4 py-2 text-xs border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-indigo-500 font-semibold"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Experience (Years)</label>
                <input
                  type="number"
                  required
                  value={formData.yearsOfExperience}
                  onChange={e => setFormData({ ...formData, yearsOfExperience: e.target.value })}
                  className="w-full px-4 py-2 text-xs border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-indigo-500 font-semibold"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">PAN Card</label>
                <input
                  type="text"
                  required
                  value={formData.panCard}
                  onChange={e => setFormData({ ...formData, panCard: e.target.value })}
                  className="w-full px-4 py-2 text-xs border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-indigo-500 font-semibold"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Specializations (comma separated)</label>
              <input
                type="text"
                placeholder="GST Return, ITR, Bookkeeping..."
                value={formData.skills}
                onChange={e => setFormData({ ...formData, skills: e.target.value })}
                className="w-full px-4 py-2 text-xs border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-indigo-500 font-semibold"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Resume URL</label>
              <input
                type="url"
                value={formData.resumeUrl}
                onChange={e => setFormData({ ...formData, resumeUrl: e.target.value })}
                className="w-full px-4 py-2 text-xs border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-indigo-500 font-semibold"
              />
            </div>

            <h4 className="text-xs font-black text-slate-800 pt-4 uppercase tracking-wider">Settlement Bank Account</h4>
            
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Bank Name</label>
                <input
                  type="text"
                  required
                  value={formData.bankDetails.bankName}
                  onChange={e => setFormData({
                    ...formData,
                    bankDetails: { ...formData.bankDetails, bankName: e.target.value }
                  })}
                  className="w-full px-4 py-2 text-xs border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-indigo-500 font-semibold"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Account Name</label>
                <input
                  type="text"
                  required
                  value={formData.bankDetails.accountName}
                  onChange={e => setFormData({
                    ...formData,
                    bankDetails: { ...formData.bankDetails, accountName: e.target.value }
                  })}
                  className="w-full px-4 py-2 text-xs border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-indigo-500 font-semibold"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Account Number</label>
                <input
                  type="text"
                  required
                  value={formData.bankDetails.accountNumber}
                  onChange={e => setFormData({
                    ...formData,
                    bankDetails: { ...formData.bankDetails, accountNumber: e.target.value }
                  })}
                  className="w-full px-4 py-2 text-xs border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-indigo-500 font-semibold"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">IFSC Code</label>
                <input
                  type="text"
                  required
                  value={formData.bankDetails.ifscCode}
                  onChange={e => setFormData({
                    ...formData,
                    bankDetails: { ...formData.bankDetails, ifscCode: e.target.value }
                  })}
                  className="w-full px-4 py-2 text-xs border border-slate-200 rounded-xl outline-none focus:ring-2 focus:ring-indigo-500 font-semibold"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={saving}
              className="w-full py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-black uppercase tracking-wider shadow-lg shadow-indigo-150 transition active:scale-95 disabled:opacity-50 mt-6"
            >
              {saving ? 'Submitting request...' : 'Submit Profile Changes'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

const ACTIVE_TASK_STORAGE_KEY = 'freelancer_active_task_v2';

const formatDuration = (totalSeconds) => {
  const safe = Math.max(0, Number(totalSeconds || 0));
  const h = Math.floor(safe / 3600);
  const m = Math.floor((safe % 3600) / 60);
  const s = safe % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
};

const FreelancerApp = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
  const [userInfo, setUserInfo] = useState(null);
  const [orders, setOrders] = useState([]);
  const [todos, setTodos] = useState([]);
  const [broadcasts, setBroadcasts] = useState([]);
  const [ledger, setLedger] = useState([]);
  const [selectedOrderId, setSelectedOrderId] = useState(null);
  
  const {
    notifications,
    activeBannerNotification,
    setActiveBannerNotification,
    unreadCount,
    markRead,
    markAllRead
  } = useNotifications(userInfo?.token);

  const [tickets, setTickets] = useState([]);
  const [isUploading, setIsUploading] = useState(false);
  const [isClockedIn, setIsClockedIn] = useState(false);
  const [shiftStartedAt, setShiftStartedAt] = useState(null);
  const [shiftElapsedSeconds, setShiftElapsedSeconds] = useState(0);
  const [activeTaskSession, setActiveTaskSession] = useState(null);
  const [activeTaskElapsedSeconds, setActiveTaskElapsedSeconds] = useState(0);

  const navigate = useNavigate();
  const shiftIntervalRef = useRef(null);
  const activeTaskIntervalRef = useRef(null);

  const authConfig = useMemo(() => (
    userInfo?.token
      ? { headers: { Authorization: `Bearer ${userInfo.token}` } }
      : null
  ), [userInfo]);

  const selectedOrder = useMemo(
    () => orders.find((order) => order._id === selectedOrderId) || null,
    [orders, selectedOrderId]
  );

  const activeTaskDetails = useMemo(() => {
    if (!activeTaskSession?.orderId || !activeTaskSession?.taskId) return null;
    const order = orders.find((item) => item._id === activeTaskSession.orderId);
    const task = order?.tasks?.find((item) => item._id === activeTaskSession.taskId);
    return {
      orderId: activeTaskSession.orderId,
      taskId: activeTaskSession.taskId,
      serviceName: order?.serviceName || activeTaskSession.serviceName || 'Unknown Service',
      taskTitle: task?.title || activeTaskSession.taskTitle || 'Unknown Task'
    };
  }, [activeTaskSession, orders]);

  const fetchOrders = useCallback(async () => {
    if (!authConfig) return;
    try {
      const { data } = await axios.get('/api/freelancer/orders', authConfig);
      setOrders(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Failed to fetch freelancer orders:', error);
    }
  }, [authConfig]);

  const fetchTodos = useCallback(async () => {
    if (!authConfig) return;
    try {
      const { data } = await axios.get('/api/todos', authConfig);
      setTodos(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Failed to fetch freelancer tasks:', error);
    }
  }, [authConfig]);

  const fetchBroadcasts = useCallback(async () => {
    if (!authConfig) return;
    try {
      const { data } = await axios.get('/api/freelancer/broadcasts', authConfig);
      setBroadcasts(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Failed to fetch broadcasts:', error);
    }
  }, [authConfig]);

  const fetchLedger = useCallback(async () => {
    if (!authConfig) return;
    try {
      const { data } = await axios.get('/api/freelancer/ledger', authConfig);
      setLedger(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Failed to fetch ledger:', error);
    }
  }, [authConfig]);

  const fetchAttendanceStatus = useCallback(async () => {
    if (!authConfig) return;
    try {
      const { data } = await axios.get('/api/attendance/my-status', authConfig);
      const openSession = data?.openSession || null;
      if (openSession?.clockInAt) {
        setIsClockedIn(true);
        setShiftStartedAt(openSession.clockInAt);
        const elapsed = Math.floor((Date.now() - new Date(openSession.clockInAt).getTime()) / 1000);
        setShiftElapsedSeconds(Math.max(0, elapsed));
      } else {
        setIsClockedIn(false);
        setShiftStartedAt(null);
        setShiftElapsedSeconds(0);
      }
    } catch (error) {
      console.error('Failed to fetch attendance status:', error);
    }
  }, [authConfig]);

  const fetchExtras = useCallback(async () => {
    if (!authConfig) return;
    try {
      const { data } = await axios.get('/api/tickets', authConfig);
      setTickets(Array.isArray(data) ? data : dummyTickets);
    } catch (error) {
      setTickets(dummyTickets);
    }
  }, [authConfig]);

  useEffect(() => {
    const stored = localStorage.getItem('userInfo');
    if (!stored) {
      navigate('/login');
      return;
    }

    const parsed = JSON.parse(stored);
    if (parsed.role !== 'freelancer' && parsed.role !== 'admin') {
      alert('Access denied. Freelancer dashboard only.');
      navigate('/');
      return;
    }

    setUserInfo(parsed);
  }, [navigate]);

  useEffect(() => {
    if (!userInfo) return;
    fetchOrders();
    fetchTodos();
    fetchBroadcasts();
    fetchLedger();
    fetchExtras();
    fetchAttendanceStatus();
  }, [userInfo, fetchOrders, fetchTodos, fetchBroadcasts, fetchLedger, fetchExtras, fetchAttendanceStatus]);

  useEffect(() => {
    const rawTask = localStorage.getItem(ACTIVE_TASK_STORAGE_KEY);
    if (rawTask) {
      try {
        const parsed = JSON.parse(rawTask);
        if (parsed?.orderId && parsed?.taskId && parsed?.startedAt) {
          setActiveTaskSession(parsed);
          const elapsed = Math.floor((Date.now() - new Date(parsed.startedAt).getTime()) / 1000);
          setActiveTaskElapsedSeconds(Math.max(0, elapsed));
        }
      } catch (error) {
        localStorage.removeItem(ACTIVE_TASK_STORAGE_KEY);
      }
    }
  }, []);

  useEffect(() => {
    if (isClockedIn && shiftStartedAt) {
      shiftIntervalRef.current = setInterval(() => {
        const elapsed = Math.floor((Date.now() - new Date(shiftStartedAt).getTime()) / 1000);
        setShiftElapsedSeconds(Math.max(0, elapsed));
      }, 1000);
    }
    return () => {
      if (shiftIntervalRef.current) {
        clearInterval(shiftIntervalRef.current);
        shiftIntervalRef.current = null;
      }
    };
  }, [isClockedIn, shiftStartedAt]);

  useEffect(() => {
    if (activeTaskSession?.startedAt) {
      activeTaskIntervalRef.current = setInterval(() => {
        const elapsed = Math.floor((Date.now() - new Date(activeTaskSession.startedAt).getTime()) / 1000);
        setActiveTaskElapsedSeconds(Math.max(0, elapsed));
      }, 1000);
    }
    return () => {
      if (activeTaskIntervalRef.current) {
        clearInterval(activeTaskIntervalRef.current);
        activeTaskIntervalRef.current = null;
      }
    };
  }, [activeTaskSession]);

  const refreshAll = () => {
    fetchOrders();
    fetchTodos();
    fetchBroadcasts();
    fetchLedger();
    fetchExtras();
    fetchAttendanceStatus();
  };

  const handleClaimJob = async (orderId) => {
    if (!authConfig) return;
    try {
      await axios.post(`/api/freelancer/claim/${orderId}`, {}, authConfig);
      alert('Job claimed successfully!');
      refreshAll();
    } catch (error) {
      alert(error?.response?.data?.message || 'Unable to claim job.');
    }
  };

  const clockIn = async () => {
    if (!authConfig) return;
    try {
      // Find default active order for freelancer clock in if no order selected
      const targetOrderId = selectedOrderId || orders[0]?._id;
      if (!targetOrderId) {
        alert('Please select an order from My Work Queue before clocking in.');
        return;
      }
      await axios.post(`/api/freelancer/clock-in/${targetOrderId}`, {}, authConfig);
      setIsClockedIn(true);
      setShiftStartedAt(new Date().toISOString());
      setShiftElapsedSeconds(0);
    } catch (error) {
      alert(error?.response?.data?.message || 'Unable to clock in.');
    }
  };

  const clockOut = async () => {
    if (!authConfig) return;
    try {
      const targetOrderId = selectedOrderId || orders[0]?._id;
      if (!targetOrderId) return;
      await axios.post(`/api/freelancer/clock-out/${targetOrderId}`, {}, authConfig);
      setIsClockedIn(false);
      setShiftStartedAt(null);
      setShiftElapsedSeconds(0);
    } catch (error) {
      alert(error?.response?.data?.message || 'Unable to clock out.');
    }
  };

  const openOrderInProcessing = (order) => {
    setSelectedOrderId(order._id);
    setActiveTab('processing');
  };

  const handleStatusChange = async (orderId, status) => {
    if (!authConfig) return;
    try {
      await axios.put(`/api/orders/${orderId}/status`, { status }, authConfig);
      await fetchOrders();
      await fetchTodos();
    } catch (error) {
      alert('Unable to update order status.');
    }
  };

  const handleUpdateOrderName = async (orderId, name) => {
    if (!authConfig) return;
    try {
      await axios.put(`/api/orders/${orderId}/commercials`, {
        serviceName: name
      }, authConfig);
      await fetchOrders();
    } catch (error) {
      alert('Unable to update order name.');
    }
  };

  const handleTaskStatusChange = async (orderId, taskId, status) => {
    if (!authConfig) return;
    try {
      await axios.put(`/api/orders/${orderId}/tasks/${taskId}`, { status }, authConfig);
      await fetchOrders();
    } catch (error) {
      alert('Unable to update task status.');
    }
  };

  const handleUpdateSubtask = async (orderId, taskId, subtaskId, payload) => {
    if (!authConfig) return;
    try {
      await axios.put(`/api/orders/${orderId}/tasks/${taskId}/subtasks/${subtaskId}`, payload, authConfig);
      await fetchOrders();
    } catch (error) {
      alert('Unable to update subtask.');
    }
  };

  const handleLogTime = async (orderId, taskId, minutes, notes) => {
    if (!authConfig) return;
    try {
      await axios.post(`/api/orders/${orderId}/tasks/${taskId}/time-log`, { minutes, notes }, authConfig);
      await fetchOrders();
    } catch (error) {
      alert('Unable to log task time.');
    }
  };

  const handleUpdateRequirementStatus = async (orderId, requirementId, status) => {
    if (!authConfig) return;
    try {
      await axios.put(`/api/orders/${orderId}/requirements/${requirementId}/status`, { status }, authConfig);
      await fetchOrders();
    } catch (error) {
      alert('Unable to update requirement status.');
    }
  };

  const handleRaiseRequirement = async (orderId, payload) => {
    if (!authConfig) return;
    try {
      await axios.post(`/api/orders/${orderId}/requirements`, payload, authConfig);
      await fetchOrders();
    } catch (error) {
      alert(error?.response?.data?.message || 'Unable to raise requirement.');
    }
  };

  const startTaskSession = async ({ orderId, taskId, serviceName, taskTitle }) => {
    if (!isClockedIn) {
      alert('Please clock in before starting a task timer.');
      return;
    }

    if (activeTaskSession && (activeTaskSession.orderId !== orderId || activeTaskSession.taskId !== taskId)) {
      alert('Pause or complete the current task before starting another one.');
      return;
    }

    if (activeTaskSession) return;

    const startedAt = new Date().toISOString();
    const nextSession = { orderId, taskId, startedAt, serviceName, taskTitle };
    setActiveTaskSession(nextSession);
    setActiveTaskElapsedSeconds(0);
    localStorage.setItem(ACTIVE_TASK_STORAGE_KEY, JSON.stringify(nextSession));
    await handleTaskStatusChange(orderId, taskId, 'In Progress');
  };

  const pauseTaskSession = async () => {
    if (!activeTaskSession?.orderId || !activeTaskSession?.taskId || !activeTaskSession?.startedAt) return;
    const elapsedSeconds = Math.floor((Date.now() - new Date(activeTaskSession.startedAt).getTime()) / 1000);
    const minutes = Math.max(1, Math.round(elapsedSeconds / 60));
    await handleLogTime(
      activeTaskSession.orderId,
      activeTaskSession.taskId,
      minutes,
      `Timer log (${formatDuration(elapsedSeconds)})`
    );

    setActiveTaskSession(null);
    setActiveTaskElapsedSeconds(0);
    localStorage.removeItem(ACTIVE_TASK_STORAGE_KEY);
  };

  const completeTaskSession = async () => {
    if (!activeTaskSession?.orderId || !activeTaskSession?.taskId) return;
    await pauseTaskSession();
    await handleTaskStatusChange(activeTaskSession.orderId, activeTaskSession.taskId, 'Completed');
  };

  const handleTodoStatusChange = async (todoId, status) => {
    if (!authConfig) return;
    try {
      await axios.put(`/api/todos/${todoId}`, { status }, authConfig);
      await fetchTodos();
    } catch (error) {
      alert('Unable to update todo status.');
    }
  };

  const handleUploadCertificate = async (file) => {
    if (!authConfig || !selectedOrder) return;

    const formData = new FormData();
    formData.append('document', file);

    setIsUploading(true);
    try {
      await axios.post(`/api/orders/${selectedOrder._id}/documents`, formData, {
        headers: {
          Authorization: `Bearer ${userInfo.token}`,
          'Content-Type': 'multipart/form-data'
        }
      });
      alert('Final certificate uploaded successfully.');
      await fetchOrders();
    } catch (error) {
      alert('Unable to upload final certificate.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('userInfo');
    navigate('/login');
  };

  const renderActiveModule = () => {
    switch (activeTab) {
      case 'dashboard':
        return (
          <DashboardOverviewModule
            userInfo={userInfo}
            orders={orders}
            todos={todos}
            onOpenOrder={openOrderInProcessing}
            onTodoStatusChange={handleTodoStatusChange}
            isClockedIn={isClockedIn}
          />
        );
      case 'jobs':
        return <AvailableJobsModule broadcasts={broadcasts} onClaimJob={handleClaimJob} />;
      case 'queue':
        return <WorkQueueModule orders={orders} todos={todos} onOpenOrder={openOrderInProcessing} onTodoStatusChange={handleTodoStatusChange} isClockedIn={isClockedIn} />;
      case 'processing':
        return (
          <OrderProcessingModule
            orders={orders}
            selectedOrder={selectedOrder}
            setSelectedOrder={(order) => setSelectedOrderId(order?._id || null)}
            onStatusChange={handleStatusChange}
            onUpdateOrderName={handleUpdateOrderName}
            onUploadCertificate={handleUploadCertificate}
            isUploading={isUploading}
            userInfo={userInfo}
            onUpdateRequirementStatus={handleUpdateRequirementStatus}
            onRaiseRequirement={handleRaiseRequirement}
            linkedTodos={todos.filter(t => t.orderId?._id === selectedOrderId || t.orderId === selectedOrderId)}
            onTodoStatusChange={handleTodoStatusChange}
            isClockedIn={isClockedIn}
            onTaskStatusChange={handleTaskStatusChange}
            onUpdateSubtask={handleUpdateSubtask}
          />
        );
      case 'tasks':
        return (
          <TaskManagementModule
            orders={orders}
            userInfo={userInfo}
            selectedOrder={selectedOrder}
            setSelectedOrder={(order) => setSelectedOrderId(order?._id || null)}
            onTaskStatusChange={handleTaskStatusChange}
            onUpdateSubtask={handleUpdateSubtask}
            activeTaskSession={activeTaskSession}
            activeTaskElapsedSeconds={activeTaskElapsedSeconds}
            onStartTask={startTaskSession}
            onPauseTask={pauseTaskSession}
            onCompleteTask={completeTaskSession}
            isClockedIn={isClockedIn}
          />
        );
      case 'time':
        return (
          <TimeTrackingModule
            orders={orders}
            selectedOrder={selectedOrder}
            setSelectedOrder={(order) => setSelectedOrderId(order?._id || null)}
            onLogTime={handleLogTime}
            userInfo={userInfo}
            activeTaskSession={activeTaskSession}
            activeTaskElapsedSeconds={activeTaskElapsedSeconds}
          />
        );
      case 'documents':
        return <DocumentsModule selectedOrder={selectedOrder} />;
      case 'requirements':
        return (
          <RequirementsModule
            selectedOrder={selectedOrder}
            onUpdateRequirementStatus={handleUpdateRequirementStatus}
            onRaiseRequirement={handleRaiseRequirement}
            isClockedIn={isClockedIn}
          />
        );
      case 'ledger':
        return <EarningsLedgerModule ledger={ledger} />;
      case 'notifications':
        return (
          <NotificationsFeed 
            notifications={notifications}
            onMarkRead={markRead}
            onMarkAllRead={markAllRead}
            onClickAction={(notif) => {
              setActiveTab('queue');
            }}
          />
        );
      case 'settings':
        return <FreelancerSettingsModule token={userInfo?.token} />;
      default:
        return (
          <DashboardOverviewModule
            userInfo={userInfo}
            orders={orders}
            todos={todos}
            onOpenOrder={openOrderInProcessing}
            onTodoStatusChange={handleTodoStatusChange}
            isClockedIn={isClockedIn}
          />
        );
    }
  };

  // Custom tabs specifically for Freelancer (adds Jobs and Ledger)
  const freelancerSidebarTabs = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'jobs', label: 'Available Jobs', icon: Award },
    { id: 'queue', label: 'Work Queue', icon: Briefcase },
    { id: 'processing', label: 'Order Processing', icon: FolderKanban },
    { id: 'tasks', label: 'Task Management', icon: CheckSquare },
    { id: 'time', label: 'Time Tracking', icon: Clock3 },
    { id: 'documents', label: 'Documents', icon: FileText },
    { id: 'requirements', label: 'Requirements', icon: ClipboardList },
    { id: 'ledger', label: 'Earnings Ledger', icon: DollarSign },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'settings', label: 'Account Settings', icon: ShieldCheck }
  ];

  return (
    <div className="flex h-screen bg-gradient-to-br from-slate-100 via-blue-50 to-indigo-100 font-sans text-slate-800 overflow-hidden">
      <FreelancerSidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        collapsed={sidebarCollapsed}
        setCollapsed={setSidebarCollapsed}
        onLogout={handleLogout}
      />

      <main className="flex-1 flex flex-col h-full overflow-hidden">
        <FreelancerTopbar
          activeTab={activeTab}
          userInfo={userInfo}
          onRefresh={refreshAll}
          isClockedIn={isClockedIn}
          shiftElapsedLabel={formatDuration(shiftElapsedSeconds)}
          onClockIn={clockIn}
          onClockOut={clockOut}
          activeTaskDetails={activeTaskDetails}
          activeTaskElapsedLabel={formatDuration(activeTaskElapsedSeconds)}
          onPauseTask={pauseTaskSession}
          onCompleteTask={completeTaskSession}
          unreadCount={unreadCount}
          onNotificationClick={() => setActiveTab('notifications')}
        />
        <div className="flex-1 overflow-y-auto p-4 sm:p-6">{renderActiveModule()}</div>
      </main>
      <InAppBanner 
        activeNotification={activeBannerNotification}
        onDismiss={() => setActiveBannerNotification(null)}
        onClickAction={() => setActiveTab('notifications')}
      />
    </div>
  );
};

export default FreelancerApp;
