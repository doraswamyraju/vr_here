import React, { useState, useEffect, useCallback, useMemo } from 'react';
import axios from 'axios';
import {
  Flame,
  Eye,
  CheckCircle2,
  Clock,
  Phone,
  Mail,
  MessageSquare,
  Search,
  Filter,
  User,
  Smartphone,
  Globe,
  RefreshCw,
  ArrowUpRight,
  TrendingUp,
  AlertCircle,
  MoreVertical,
  ChevronRight,
  Shield,
  Tag,
  DollarSign,
  Plus,
  Send,
  X,
  Calendar
} from 'lucide-react';

const LeadsManagerView = ({ userInfo, role = 'admin', employees = [] }) => {
  const [leads, setLeads] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeCategoryTab, setActiveCategoryTab] = useState('ALL'); // 'ALL', 'PACKAGE_CLICK', 'PAGE_VIEW', 'CONVERTED'
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [employeeFilter, setEmployeeFilter] = useState('ALL');
  const [selectedLeadForNotes, setSelectedLeadForNotes] = useState(null);
  const [newNoteText, setNewNoteText] = useState('');
  const [isAddingNote, setIsAddingNote] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const authHeaders = useMemo(() => ({
    headers: { Authorization: `Bearer ${userInfo?.token}` }
  }), [userInfo?.token]);

  const fetchLeadsData = useCallback(async (silent = false) => {
    if (!userInfo?.token) return;
    if (!silent) setLoading(true);
    setIsRefreshing(true);
    try {
      const params = {};
      if (activeCategoryTab === 'PACKAGE_CLICK') params.category = 'PACKAGE_CLICK';
      if (activeCategoryTab === 'PAGE_VIEW') params.category = 'PAGE_VIEW';
      if (activeCategoryTab === 'CONVERTED') params.status = 'CONVERTED';
      if (statusFilter !== 'ALL' && activeCategoryTab !== 'CONVERTED') params.status = statusFilter;
      if (sourceFilter !== 'ALL') params.source = sourceFilter;
      if (employeeFilter !== 'ALL') params.assignedTo = employeeFilter;
      if (searchQuery.trim()) params.search = searchQuery.trim();

      const [leadsRes, statsRes] = await Promise.all([
        axios.get('/api/leads', { ...authHeaders, params }),
        axios.get('/api/leads/stats', authHeaders)
      ]);

      setLeads(leadsRes.data?.leads || []);
      setStats(statsRes.data || null);
    } catch (err) {
      console.error('Failed to load leads data:', err);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, [userInfo?.token, activeCategoryTab, statusFilter, sourceFilter, employeeFilter, searchQuery, authHeaders]);

  useEffect(() => {
    fetchLeadsData();
  }, [fetchLeadsData]);

  // Auto-refresh every 30 seconds for live telemetry
  useEffect(() => {
    const interval = setInterval(() => {
      fetchLeadsData(true);
    }, 30000);
    return () => clearInterval(interval);
  }, [fetchLeadsData]);

  const handleStatusChange = async (leadId, newStatus) => {
    try {
      await axios.put(`/api/leads/${leadId}`, { status: newStatus }, authHeaders);
      setLeads(prev => prev.map(l => (l._id === leadId ? { ...l, status: newStatus } : l)));
      fetchLeadsData(true);
    } catch (err) {
      console.error('Failed to update lead status:', err);
      alert('Could not update status.');
    }
  };

  const handleAssignEmployee = async (leadId, employeeId) => {
    try {
      await axios.put(`/api/leads/${leadId}`, { assignedTo: employeeId }, authHeaders);
      fetchLeadsData(true);
    } catch (err) {
      console.error('Failed to reassign lead:', err);
      alert('Could not reassign lead.');
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!selectedLeadForNotes || !newNoteText.trim()) return;
    setIsAddingNote(true);
    try {
      const res = await axios.put(
        `/api/leads/${selectedLeadForNotes._id}`,
        { note: newNoteText.trim() },
        authHeaders
      );
      setSelectedLeadForNotes(res.data);
      setLeads(prev => prev.map(l => (l._id === res.data._id ? res.data : l)));
      setNewNoteText('');
    } catch (err) {
      console.error('Failed to add note:', err);
      alert('Could not add note.');
    } finally {
      setIsAddingNote(false);
    }
  };

  const formatTimeAgo = (dateStr) => {
    if (!dateStr) return '';
    const d = new Date(dateStr);
    const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHour = Math.floor(diffMin / 60);
    if (diffHour < 24) return `${diffHour}h ago`;
    const diffDays = Math.floor(diffHour / 24);
    return `${diffDays}d ago`;
  };

  const getWhatsAppLink = (lead) => {
    const cleanPhone = (lead.phone || '').replace(/[^0-9]/g, '');
    const formattedPhone = cleanPhone.length === 10 ? `91${cleanPhone}` : cleanPhone;
    const nameGreeting = lead.customerName && lead.customerName !== 'Guest Prospect' ? lead.customerName : 'there';
    
    let text = `Hi ${nameGreeting}, I am from VR Here Business Management Solutions. `;
    if (lead.category === 'PACKAGE_CLICK' && lead.packageName) {
      text += `I noticed you were looking into the *${lead.serviceName} (${lead.packageName})* plan. Would you like our legal & CA specialists to assist you with the onboarding requirements?`;
    } else {
      text += `I noticed you were exploring *${lead.serviceName}* on our platform. How can our compliance experts help you today?`;
    }
    return `https://wa.me/${formattedPhone}?text=${encodeURIComponent(text)}`;
  };

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      {/* 1. Header & Live Stats */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 p-6 md:p-8 rounded-3xl text-white shadow-xl relative overflow-hidden">
        <div className="absolute right-0 top-0 w-96 h-full bg-indigo-500/10 skew-x-12 pointer-events-none"></div>
        <div className="relative z-10 space-y-1">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-white/10 rounded-full text-xs font-bold text-indigo-300 backdrop-blur-md">
            <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></span>
            <span>Real-Time Mobile & Web Telemetry CRM</span>
          </div>
          <h1 className="text-2xl md:text-3xl font-black tracking-tight text-white flex items-center gap-3">
            <span>Leads & Intent Engine</span>
            {isRefreshing && <RefreshCw className="w-5 h-5 text-indigo-400 animate-spin" />}
          </h1>
          <p className="text-slate-300 text-xs md:text-sm max-w-2xl font-medium leading-relaxed">
            Automatically captures live visitors viewing services (Category A) and customers tapping pricing packages (Category B) across iOS, Android, and Web.
          </p>
        </div>

        <div className="relative z-10 flex items-center gap-3">
          <button
            onClick={() => fetchLeadsData(false)}
            className="px-4 py-2.5 bg-white/10 hover:bg-white/20 text-white rounded-xl text-xs font-bold transition flex items-center gap-2 border border-white/10 backdrop-blur-sm"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh Leads</span>
          </button>
        </div>
      </div>

      {/* 2. Key Metrics Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <div className="bg-white p-4 rounded-2xl border border-slate-200 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider">Total Inquiries</span>
            <UsersIcon className="w-4 h-4 text-slate-500" />
          </div>
          <div className="text-2xl font-black text-slate-900">{stats?.total || 0}</div>
          <div className="text-[10px] text-slate-400 font-medium mt-1">All Recorded Leads</div>
        </div>

        <div className="bg-gradient-to-br from-rose-50 to-orange-50 p-4 rounded-2xl border border-rose-200 shadow-sm flex flex-col justify-between relative overflow-hidden">
          <div className="flex items-center justify-between text-rose-600 mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider">Hot Intent (Clicks)</span>
            <Flame className="w-4 h-4 text-rose-500 animate-bounce" />
          </div>
          <div className="text-2xl font-black text-rose-600">{stats?.packageClicks || 0}</div>
          <div className="text-[10px] text-rose-700/70 font-black mt-1">Category B: High Intent</div>
        </div>

        <div className="bg-blue-50/60 p-4 rounded-2xl border border-blue-200 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-blue-600 mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider">Browsing Views</span>
            <Eye className="w-4 h-4 text-blue-500" />
          </div>
          <div className="text-2xl font-black text-blue-600">{stats?.pageViews || 0}</div>
          <div className="text-[10px] text-blue-700/70 font-medium mt-1">Category A: Service Pages</div>
        </div>

        <div className="bg-emerald-50/60 p-4 rounded-2xl border border-emerald-200 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-emerald-600 mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider">Converted Orders</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-2xl font-black text-emerald-600">{stats?.converted || 0}</div>
          <div className="text-[10px] text-emerald-700/70 font-bold mt-1">{stats?.conversionRate || '0.0'}% Win Rate</div>
        </div>

        <div className="bg-amber-50/60 p-4 rounded-2xl border border-amber-200 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-amber-600 mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider">Today's Fresh</span>
            <Clock className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-black text-amber-600">{stats?.todayCount || 0}</div>
          <div className="text-[10px] text-amber-700/70 font-bold mt-1">In Last 24 Hours</div>
        </div>

        <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider">Source Split</span>
            <Smartphone className="w-4 h-4 text-slate-500" />
          </div>
          <div className="flex items-center gap-1.5 text-xs font-bold text-slate-700">
            <span className="bg-slate-200 px-1.5 py-0.5 rounded text-[10px]">iOS: {stats?.sources?.ios || 0}</span>
            <span className="bg-slate-200 px-1.5 py-0.5 rounded text-[10px]">And: {stats?.sources?.android || 0}</span>
          </div>
          <div className="text-[10px] text-slate-400 font-medium mt-1">Web: {stats?.sources?.web || 0}</div>
        </div>
      </div>

      {/* 3. Category Tabs & Filter Toolbar */}
      <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm space-y-4">
        {/* Category Tabs */}
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 pb-4">
          {[
            { id: 'ALL', label: 'All Leads', icon: UsersIcon, count: stats?.total },
            { id: 'PACKAGE_CLICK', label: '🔥 High Intent (Price Clicks)', icon: Flame, count: stats?.packageClicks, badgeColor: 'bg-rose-100 text-rose-700' },
            { id: 'PAGE_VIEW', label: '👀 Browsing Leads (Views)', icon: Eye, count: stats?.pageViews, badgeColor: 'bg-blue-100 text-blue-700' },
            { id: 'CONVERTED', label: '✅ Converted to Orders', icon: CheckCircle2, count: stats?.converted, badgeColor: 'bg-emerald-100 text-emerald-700' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveCategoryTab(tab.id)}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
                activeCategoryTab === tab.id
                  ? 'bg-slate-900 text-white shadow-md'
                  : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
              }`}
            >
              <span>{tab.label}</span>
              {typeof tab.count === 'number' && (
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-black ${
                  activeCategoryTab === tab.id ? 'bg-white/20 text-white' : tab.badgeColor || 'bg-slate-200 text-slate-600'
                }`}>
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Filters and Search Bar */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="relative md:col-span-2">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by customer name, phone, email, or service..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-medium text-slate-800 placeholder-slate-400 focus:outline-none focus:border-indigo-500 transition"
            />
          </div>

          <div className="flex items-center gap-2">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-700 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="NEW">New (Uncontacted)</option>
              <option value="CONTACTED">Contacted</option>
              <option value="IN_PROGRESS">In Progress</option>
              <option value="CONVERTED">Converted</option>
              <option value="LOST">Lost</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="w-full px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-700 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Sources</option>
              <option value="ios">📱 iOS App</option>
              <option value="android">🤖 Android App</option>
              <option value="web">💻 Web Browser</option>
            </select>

            {role === 'admin' && employees.length > 0 && (
              <select
                value={employeeFilter}
                onChange={(e) => setEmployeeFilter(e.target.value)}
                className="w-full px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-700 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Staff</option>
                {employees.map(emp => (
                  <option key={emp._id} value={emp._id}>{emp.name}</option>
                ))}
              </select>
            )}
          </div>
        </div>
      </div>

      {/* 4. Leads List / Cards Grid */}
      <div className="space-y-3">
        {loading ? (
          <div className="bg-white p-12 rounded-3xl border border-slate-200 text-center space-y-3">
            <RefreshCw className="w-8 h-8 text-indigo-500 animate-spin mx-auto" />
            <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">Loading Live Lead Records...</p>
          </div>
        ) : leads.length === 0 ? (
          <div className="bg-white p-12 rounded-3xl border border-slate-200 text-center space-y-3">
            <AlertCircle className="w-10 h-10 text-slate-300 mx-auto" />
            <h3 className="text-base font-bold text-slate-800">No leads found</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              No leads match your current search and filter settings. New inquiries from iOS, Android, and web will show up here automatically.
            </p>
          </div>
        ) : (
          leads.map(lead => {
            const isPackageClick = lead.category === 'PACKAGE_CLICK';
            const isConverted = lead.status === 'CONVERTED';

            return (
              <div
                key={lead._id}
                className={`bg-white p-5 rounded-2xl border transition-all duration-200 flex flex-col lg:flex-row lg:items-center justify-between gap-4 hover:shadow-md ${
                  isPackageClick ? 'border-rose-200 bg-rose-50/10' : 'border-slate-200'
                }`}
              >
                {/* Left: Customer Info & Service Badge */}
                <div className="flex items-start gap-4 flex-1">
                  <div className={`w-11 h-11 rounded-2xl flex items-center justify-center font-black text-sm shrink-0 shadow-sm ${
                    isPackageClick ? 'bg-gradient-to-br from-rose-500 to-orange-500 text-white shadow-rose-500/20' : 'bg-slate-100 text-slate-700'
                  }`}>
                    {(lead.customerName || 'G').charAt(0).toUpperCase()}
                  </div>

                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="font-bold text-sm text-slate-900 flex items-center gap-1.5">
                        <span>{lead.customerName || 'Guest Prospect'}</span>
                        {lead.customerId && (
                          <span className="px-2 py-0.5 bg-indigo-50 text-indigo-700 rounded-full text-[10px] font-black uppercase">
                            Member
                          </span>
                        )}
                      </h3>

                      {/* Category Badge */}
                      {isPackageClick ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 bg-rose-500 text-white rounded-full text-[10px] font-black uppercase tracking-wider shadow-sm animate-pulse">
                          <Flame className="w-3 h-3 fill-current" />
                          <span>Hot Lead: Package Click</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-blue-50 text-blue-700 rounded-full text-[10px] font-black uppercase">
                          <Eye className="w-3 h-3" />
                          <span>Browsing View</span>
                        </span>
                      )}

                      {/* Source Device */}
                      <span className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded-full text-[10px] font-black uppercase flex items-center gap-1">
                        {lead.source === 'ios' ? '📱 iOS' : lead.source === 'android' ? '🤖 Android' : '💻 Web'}
                      </span>

                      <span className="text-[11px] text-slate-400 font-bold ml-auto lg:ml-0 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        <span>{formatTimeAgo(lead.lastActivityAt || lead.createdAt)}</span>
                      </span>
                    </div>

                    {/* Service & Package Info */}
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="font-black text-slate-800 bg-slate-100 px-2.5 py-1 rounded-lg">
                        {lead.serviceName}
                      </span>

                      {lead.packageName && (
                        <span className="font-bold text-rose-600 bg-rose-50 border border-rose-200 px-2 py-0.5 rounded-lg flex items-center gap-1">
                          <Tag className="w-3 h-3" />
                          <span>Plan: {lead.packageName}</span>
                          {lead.price > 0 && <span>(₹{lead.price.toLocaleString()})</span>}
                        </span>
                      )}
                    </div>

                    {/* Contact details */}
                    <div className="flex flex-wrap items-center gap-4 text-xs text-slate-500 font-medium">
                      {lead.phone && (
                        <a href={`tel:${lead.phone}`} className="flex items-center gap-1 hover:text-indigo-600 font-bold">
                          <Phone className="w-3.5 h-3.5 text-slate-400" />
                          <span>{lead.phone}</span>
                        </a>
                      )}
                      {lead.email && (
                        <a href={`mailto:${lead.email}`} className="flex items-center gap-1 hover:text-indigo-600">
                          <Mail className="w-3.5 h-3.5 text-slate-400" />
                          <span className="truncate max-w-[200px]">{lead.email}</span>
                        </a>
                      )}
                    </div>
                  </div>
                </div>

                {/* Right: Actions, Assignment & Status Dropdown */}
                <div className="flex flex-wrap items-center gap-2 pt-3 lg:pt-0 border-t lg:border-t-0 border-slate-100 shrink-0">
                  {/* WhatsApp Quick Action */}
                  {lead.phone && (
                    <a
                      href={getWhatsAppLink(lead)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-bold transition flex items-center gap-1.5 shadow-sm active:scale-95"
                    >
                      <MessageSquare className="w-3.5 h-3.5" />
                      <span>WhatsApp</span>
                    </a>
                  )}

                  {/* Direct Call */}
                  {lead.phone && (
                    <a
                      href={`tel:${lead.phone}`}
                      className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition"
                      title="Direct Call"
                    >
                      <Phone className="w-4 h-4" />
                    </a>
                  )}

                  {/* Notes button */}
                  <button
                    onClick={() => setSelectedLeadForNotes(lead)}
                    className="px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition flex items-center gap-1.5"
                  >
                    <span>Notes ({lead.notes?.length || 0})</span>
                  </button>

                  {/* Assign to Employee (Admin View) */}
                  {role === 'admin' && employees.length > 0 && (
                    <select
                      value={lead.assignedTo?._id || lead.assignedTo || ''}
                      onChange={(e) => handleAssignEmployee(lead._id, e.target.value)}
                      className="px-2.5 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-700 focus:outline-none"
                    >
                      <option value="">Unassigned</option>
                      {employees.map(emp => (
                        <option key={emp._id} value={emp._id}>{emp.name}</option>
                      ))}
                    </select>
                  )}

                  {/* Status Dropdown */}
                  <select
                    value={lead.status}
                    onChange={(e) => handleStatusChange(lead._id, e.target.value)}
                    className={`px-3 py-2 rounded-xl text-xs font-black uppercase tracking-wider focus:outline-none border ${
                      lead.status === 'CONVERTED' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' :
                      lead.status === 'NEW' ? 'bg-rose-50 text-rose-700 border-rose-200 font-black' :
                      lead.status === 'CONTACTED' ? 'bg-blue-50 text-blue-700 border-blue-200' :
                      lead.status === 'IN_PROGRESS' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                      'bg-slate-100 text-slate-600 border-slate-200'
                    }`}
                  >
                    <option value="NEW">🔴 New</option>
                    <option value="CONTACTED">🔵 Contacted</option>
                    <option value="IN_PROGRESS">🟡 In Progress</option>
                    <option value="CONVERTED">🟢 Converted</option>
                    <option value="LOST">⚪ Lost</option>
                  </select>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* 5. Notes & Follow-up History Modal */}
      {selectedLeadForNotes && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-3xl max-w-lg w-full p-6 shadow-2xl border border-slate-100 animate-in fade-in zoom-in-95 duration-200 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <h3 className="font-bold text-slate-900 text-base">Follow-Up Notes</h3>
                <p className="text-xs text-slate-400 font-medium">{selectedLeadForNotes.customerName} - {selectedLeadForNotes.serviceName}</p>
              </div>
              <button
                onClick={() => setSelectedLeadForNotes(null)}
                className="w-8 h-8 rounded-full bg-slate-100 hover:bg-slate-200 flex items-center justify-center text-slate-500"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Existing notes list */}
            <div className="space-y-3 max-h-60 overflow-y-auto pr-2">
              {selectedLeadForNotes.notes && selectedLeadForNotes.notes.length > 0 ? (
                selectedLeadForNotes.notes.map((note, idx) => (
                  <div key={idx} className="bg-slate-50 p-3 rounded-xl border border-slate-100 text-xs space-y-1">
                    <div className="flex items-center justify-between text-slate-400 font-bold text-[10px]">
                      <span>{note.author} ({note.authorRole})</span>
                      <span>{new Date(note.createdAt).toLocaleString()}</span>
                    </div>
                    <p className="text-slate-700 font-medium leading-relaxed">{note.text}</p>
                  </div>
                ))
              ) : (
                <p className="text-xs text-slate-400 italic text-center py-4">No notes added yet for this lead.</p>
              )}
            </div>

            {/* Add note form */}
            <form onSubmit={handleAddNote} className="space-y-3 pt-2 border-t border-slate-100">
              <textarea
                rows="3"
                placeholder="Write a follow-up note (e.g., Called client, requested company name suggestions)..."
                value={newNoteText}
                onChange={(e) => setNewNoteText(e.target.value)}
                className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-medium focus:outline-none focus:border-indigo-500"
                required
              ></textarea>
              <button
                type="submit"
                disabled={isAddingNote}
                className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-md"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{isAddingNote ? 'Saving Note...' : 'Add Follow-Up Note'}</span>
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default LeadsManagerView;
