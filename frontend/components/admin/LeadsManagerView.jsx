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
  Users as UsersIcon,
  Smartphone,
  Globe,
  RefreshCw,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Tag,
  Send,
  Calendar,
  Layers,
  Activity,
  Sparkles,
  DollarSign,
  ShieldCheck,
  ChevronRight,
  UserCheck
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
  
  // Accordion expansion state
  const [expandedClientKeys, setExpandedClientKeys] = useState({});
  const [clientNoteInputs, setClientNoteInputs] = useState({});
  const [isSubmittingNoteFor, setIsSubmittingNoteFor] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isUpdatingStatusFor, setIsUpdatingStatusFor] = useState(null);

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

  // Group leads into Unique Clients
  const groupedClients = useMemo(() => {
    if (!leads || leads.length === 0) return [];

    const map = new Map();

    leads.forEach(lead => {
      const rawCustomerId = lead.customerId?._id || (typeof lead.customerId === 'string' ? lead.customerId : null);
      const cleanPhone = (lead.phone || '').trim().replace(/[^0-9]/g, '');
      const cleanEmail = (lead.email || '').trim().toLowerCase();
      const cleanName = (lead.customerName || 'Guest Prospect').trim();

      let clientKey = '';
      if (rawCustomerId) {
        clientKey = `user_${rawCustomerId}`;
      } else if (cleanPhone && cleanPhone.length >= 7) {
        clientKey = `phone_${cleanPhone}`;
      } else if (cleanEmail && cleanEmail.includes('@')) {
        clientKey = `email_${cleanEmail}`;
      } else {
        clientKey = `lead_${lead._id}`;
      }

      const activityTime = new Date(lead.lastActivityAt || lead.createdAt || Date.now()).getTime();

      if (!map.has(clientKey)) {
        const servicesMap = new Map();
        const sKey = lead.serviceId || lead.serviceName;
        servicesMap.set(sKey, {
          serviceId: lead.serviceId,
          serviceName: lead.serviceName,
          packages: lead.packageName ? [{
            name: lead.packageName,
            price: lead.price || 0,
            category: lead.category,
            time: activityTime,
            source: lead.source
          }] : [],
          highestCategory: lead.category,
          lastActivityAt: activityTime,
          viewCount: lead.category === 'PAGE_VIEW' ? 1 : 0,
          clickCount: lead.category === 'PACKAGE_CLICK' ? 1 : 0,
          leadId: lead._id
        });

        map.set(clientKey, {
          id: clientKey,
          customerId: rawCustomerId ? lead.customerId : null,
          isMember: Boolean(rawCustomerId),
          customerName: cleanName !== 'Guest Prospect' ? cleanName : (lead.customerName || 'Guest Prospect'),
          email: cleanEmail,
          phone: lead.phone || '',
          deviceInfo: lead.deviceInfo || '',
          status: lead.status || 'NEW',
          assignedTo: lead.assignedTo || null,
          highestCategory: lead.category || 'PAGE_VIEW',
          totalPriceInterest: lead.price || 0,
          sources: new Set([lead.source || 'web']),
          firstSeenAt: activityTime,
          lastActivityAt: activityTime,
          leadIds: [lead._id],
          activities: [lead],
          servicesMap,
          notes: Array.isArray(lead.notes) ? [...lead.notes] : []
        });
      } else {
        const client = map.get(clientKey);
        client.leadIds.push(lead._id);
        client.activities.push(lead);
        if (lead.source) client.sources.add(lead.source);

        if (client.customerName === 'Guest Prospect' && cleanName !== 'Guest Prospect') {
          client.customerName = cleanName;
        }
        if (!client.phone && lead.phone) client.phone = lead.phone;
        if (!client.email && lead.email) client.email = lead.email;
        if (!client.customerId && rawCustomerId) {
          client.customerId = lead.customerId;
          client.isMember = true;
        }

        if (lead.category === 'PACKAGE_CLICK') {
          client.highestCategory = 'PACKAGE_CLICK';
        }

        if (lead.price) {
          client.totalPriceInterest += lead.price;
        }

        if (activityTime > client.lastActivityAt) {
          client.lastActivityAt = activityTime;
          client.status = lead.status || client.status;
          if (lead.assignedTo) client.assignedTo = lead.assignedTo;
        }
        if (activityTime < client.firstSeenAt) {
          client.firstSeenAt = activityTime;
        }

        if (Array.isArray(lead.notes) && lead.notes.length > 0) {
          lead.notes.forEach(note => {
            if (!client.notes.some(n => (n._id && note._id && n._id === note._id) || (n.text === note.text && n.createdAt === note.createdAt))) {
              client.notes.push(note);
            }
          });
        }

        const sKey = lead.serviceId || lead.serviceName;
        if (!client.servicesMap.has(sKey)) {
          client.servicesMap.set(sKey, {
            serviceId: lead.serviceId,
            serviceName: lead.serviceName,
            packages: lead.packageName ? [{
              name: lead.packageName,
              price: lead.price || 0,
              category: lead.category,
              time: activityTime,
              source: lead.source
            }] : [],
            highestCategory: lead.category,
            lastActivityAt: activityTime,
            viewCount: lead.category === 'PAGE_VIEW' ? 1 : 0,
            clickCount: lead.category === 'PACKAGE_CLICK' ? 1 : 0,
            leadId: lead._id
          });
        } else {
          const s = client.servicesMap.get(sKey);
          if (lead.category === 'PACKAGE_CLICK') s.highestCategory = 'PACKAGE_CLICK';
          if (lead.category === 'PACKAGE_CLICK') s.clickCount += 1;
          if (lead.category === 'PAGE_VIEW') s.viewCount += 1;
          if (activityTime > s.lastActivityAt) s.lastActivityAt = activityTime;
          if (lead.packageName) {
            s.packages.push({
              name: lead.packageName,
              price: lead.price || 0,
              category: lead.category,
              time: activityTime,
              source: lead.source
            });
          }
        }
      }
    });

    return Array.from(map.values()).map(client => ({
      ...client,
      sources: Array.from(client.sources),
      services: Array.from(client.servicesMap.values()).sort((a, b) => b.lastActivityAt - a.lastActivityAt),
      activities: client.activities.sort((a, b) => new Date(b.lastActivityAt || b.createdAt) - new Date(a.lastActivityAt || a.createdAt)),
      notes: client.notes.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    })).sort((a, b) => b.lastActivityAt - a.lastActivityAt);
  }, [leads]);

  const toggleClientExpansion = (clientKey) => {
    setExpandedClientKeys(prev => ({
      ...prev,
      [clientKey]: !prev[clientKey]
    }));
  };

  const toggleAllAccordions = (expandAll) => {
    const nextState = {};
    if (expandAll) {
      groupedClients.forEach(c => {
        nextState[c.id] = true;
      });
    }
    setExpandedClientKeys(nextState);
  };

  const areAllExpanded = useMemo(() => {
    if (groupedClients.length === 0) return false;
    return groupedClients.every(c => expandedClientKeys[c.id]);
  }, [groupedClients, expandedClientKeys]);

  const handleClientStatusChange = async (client, newStatus) => {
    setIsUpdatingStatusFor(client.id);
    try {
      // Update all lead documents for this client
      await Promise.all(
        client.leadIds.map(leadId =>
          axios.put(`/api/leads/${leadId}`, { status: newStatus }, authHeaders)
        )
      );
      setLeads(prev => prev.map(l => (client.leadIds.includes(l._id) ? { ...l, status: newStatus } : l)));
      fetchLeadsData(true);
    } catch (err) {
      console.error('Failed to update status for client leads:', err);
      alert('Could not update status.');
    } finally {
      setIsUpdatingStatusFor(null);
    }
  };

  const handleClientAssignEmployee = async (client, employeeId) => {
    try {
      await Promise.all(
        client.leadIds.map(leadId =>
          axios.put(`/api/leads/${leadId}`, { assignedTo: employeeId }, authHeaders)
        )
      );
      setLeads(prev => prev.map(l => (client.leadIds.includes(l._id) ? { ...l, assignedTo: employeeId } : l)));
      fetchLeadsData(true);
    } catch (err) {
      console.error('Failed to assign employee for client leads:', err);
      alert('Could not assign employee.');
    }
  };

  const handleAddClientNote = async (client) => {
    const text = (clientNoteInputs[client.id] || '').trim();
    if (!text) return;
    setIsSubmittingNoteFor(client.id);
    try {
      // Append note to the latest lead of this client
      const targetLeadId = client.activities[0]?._id || client.leadIds[0];
      const res = await axios.put(
        `/api/leads/${targetLeadId}`,
        { note: text },
        authHeaders
      );

      setLeads(prev => prev.map(l => (l._id === res.data._id ? res.data : l)));
      setClientNoteInputs(prev => ({ ...prev, [client.id]: '' }));
      fetchLeadsData(true);
    } catch (err) {
      console.error('Failed to add note for client:', err);
      alert('Could not add note.');
    } finally {
      setIsSubmittingNoteFor(null);
    }
  };

  const formatTimeAgo = (dateValue) => {
    if (!dateValue) return '';
    const d = typeof dateValue === 'number' ? new Date(dateValue) : new Date(dateValue);
    const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHour = Math.floor(diffMin / 60);
    if (diffHour < 24) return `${diffHour}h ago`;
    const diffDays = Math.floor(diffHour / 24);
    return `${diffDays}d ago`;
  };

  const getClientWhatsAppLink = (client) => {
    const cleanPhone = (client.phone || '').replace(/[^0-9]/g, '');
    const formattedPhone = cleanPhone.length === 10 ? `91${cleanPhone}` : cleanPhone;
    const nameGreeting = client.customerName && client.customerName !== 'Guest Prospect' ? client.customerName : 'there';

    const latestService = client.services[0];
    let text = `Hi ${nameGreeting}, I am reaching out from VR Here Business Solutions. `;

    if (latestService?.packages?.length > 0) {
      const topPkg = latestService.packages[0];
      text += `I saw you were interested in *${latestService.serviceName} (${topPkg.name})*. Would you like our CA & legal experts to assist you with the onboarding requirements?`;
    } else if (latestService) {
      text += `I noticed you were exploring *${latestService.serviceName}* on our platform. How can our compliance experts help you today?`;
    } else {
      text += `How can our legal and business compliance team assist you today?`;
    }

    return `https://wa.me/${formattedPhone}?text=${encodeURIComponent(text)}`;
  };

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      {/* 1. Header & Live Telemetry Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 p-6 md:p-8 rounded-3xl text-white shadow-xl relative overflow-hidden">
        <div className="absolute right-0 top-0 w-96 h-full bg-indigo-500/10 skew-x-12 pointer-events-none"></div>
        <div className="relative z-10 space-y-1">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-white/10 rounded-full text-xs font-bold text-indigo-300 backdrop-blur-md">
            <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></span>
            <span>Client-Centric Telemetry CRM</span>
          </div>
          <h1 className="text-2xl md:text-3xl font-black tracking-tight text-white flex items-center gap-3">
            <span>Leads & Intent Engine</span>
            {isRefreshing && <RefreshCw className="w-5 h-5 text-indigo-400 animate-spin" />}
          </h1>
          <p className="text-slate-300 text-xs md:text-sm max-w-2xl font-medium leading-relaxed">
            All mobile and web interactions are aggregated by client profile. Expand any client to review their full journey, service interests, package pricing clicks, and unified notes.
          </p>
        </div>

        <div className="relative z-10 flex items-center gap-3">
          <button
            onClick={() => toggleAllAccordions(!areAllExpanded)}
            className="px-4 py-2.5 bg-white/10 hover:bg-white/20 text-white rounded-xl text-xs font-bold transition flex items-center gap-2 border border-white/10 backdrop-blur-sm"
          >
            <Layers className="w-4 h-4" />
            <span>{areAllExpanded ? 'Collapse All' : 'Expand All'}</span>
          </button>
          <button
            onClick={() => fetchLeadsData(false)}
            className="px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-bold transition flex items-center gap-2 shadow-lg shadow-indigo-600/30"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* 2. Key Metrics Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <div className="bg-white p-4 rounded-2xl border border-slate-200 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider">Unique Clients</span>
            <UsersIcon className="w-4 h-4 text-slate-500" />
          </div>
          <div className="text-2xl font-black text-slate-900">{groupedClients.length}</div>
          <div className="text-[10px] text-slate-400 font-medium mt-1">{stats?.total || 0} Total Lead Events</div>
        </div>

        <div className="bg-gradient-to-br from-rose-50 to-orange-50 p-4 rounded-2xl border border-rose-200 shadow-sm flex flex-col justify-between relative overflow-hidden">
          <div className="flex items-center justify-between text-rose-600 mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider">Hot Intent</span>
            <Flame className="w-4 h-4 text-rose-500 animate-bounce" />
          </div>
          <div className="text-2xl font-black text-rose-600">{stats?.packageClicks || 0}</div>
          <div className="text-[10px] text-rose-700/70 font-black mt-1">Package Price Clicks</div>
        </div>

        <div className="bg-blue-50/60 p-4 rounded-2xl border border-blue-200 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-blue-600 mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider">Browsing Views</span>
            <Eye className="w-4 h-4 text-blue-500" />
          </div>
          <div className="text-2xl font-black text-blue-600">{stats?.pageViews || 0}</div>
          <div className="text-[10px] text-blue-700/70 font-medium mt-1">Service Page Views</div>
        </div>

        <div className="bg-emerald-50/60 p-4 rounded-2xl border border-emerald-200 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-emerald-600 mb-2">
            <span className="text-[10px] font-black uppercase tracking-wider">Converted</span>
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
          <div className="text-[10px] text-amber-700/70 font-bold mt-1">Last 24 Hours</div>
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
            { id: 'ALL', label: 'All Clients', count: groupedClients.length },
            { id: 'PACKAGE_CLICK', label: '🔥 High Intent (Price Clicks)', count: stats?.packageClicks, badgeColor: 'bg-rose-100 text-rose-700' },
            { id: 'PAGE_VIEW', label: '👀 Browsing Leads (Views)', count: stats?.pageViews, badgeColor: 'bg-blue-100 text-blue-700' },
            { id: 'CONVERTED', label: '✅ Converted to Orders', count: stats?.converted, badgeColor: 'bg-emerald-100 text-emerald-700' }
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
              placeholder="Search by client name, phone, email, or service explored..."
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
              <option value="NEW">🔴 New (Uncontacted)</option>
              <option value="CONTACTED">🔵 Contacted</option>
              <option value="IN_PROGRESS">🟡 In Progress</option>
              <option value="CONVERTED">🟢 Converted</option>
              <option value="LOST">⚪ Lost</option>
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

      {/* 4. Client-Centric Accordion Cards */}
      <div className="space-y-4">
        {loading ? (
          <div className="bg-white p-12 rounded-3xl border border-slate-200 text-center space-y-3">
            <RefreshCw className="w-8 h-8 text-indigo-500 animate-spin mx-auto" />
            <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">Aggregating Client Profiles & Telemetry...</p>
          </div>
        ) : groupedClients.length === 0 ? (
          <div className="bg-white p-12 rounded-3xl border border-slate-200 text-center space-y-3">
            <AlertCircle className="w-10 h-10 text-slate-300 mx-auto" />
            <h3 className="text-base font-bold text-slate-800">No client leads found</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              No recorded inquiries match your active filters. Telemetry leads from iOS, Android, and web will group automatically by client.
            </p>
          </div>
        ) : (
          groupedClients.map(client => {
            const isExpanded = Boolean(expandedClientKeys[client.id]);
            const isHotLead = client.highestCategory === 'PACKAGE_CLICK';
            const totalActivitiesCount = client.activities.length;
            const uniqueServicesCount = client.services.length;
            const latestService = client.services[0];

            return (
              <div
                key={client.id}
                className={`bg-white rounded-3xl border transition-all duration-300 overflow-hidden ${
                  isHotLead ? 'border-rose-200 shadow-sm' : 'border-slate-200 shadow-sm'
                }`}
              >
                {/* Master Header Row (Click to expand or action) */}
                <div
                  className={`p-5 md:p-6 transition-colors flex flex-col lg:flex-row lg:items-center justify-between gap-4 cursor-pointer select-none ${
                    isExpanded
                      ? isHotLead ? 'bg-rose-50/20' : 'bg-slate-50/50'
                      : 'hover:bg-slate-50/60'
                  }`}
                  onClick={() => toggleClientExpansion(client.id)}
                >
                  {/* Left: Avatar, Name, Member Pill, Phone, Email */}
                  <div className="flex items-start gap-4 flex-1 min-w-0">
                    <div className={`w-12 h-12 rounded-2xl flex items-center justify-center font-black text-base shrink-0 shadow-md ${
                      isHotLead
                        ? 'bg-gradient-to-br from-rose-500 to-orange-500 text-white shadow-rose-500/20'
                        : 'bg-gradient-to-br from-slate-700 to-slate-900 text-white shadow-slate-900/20'
                    }`}>
                      {(client.customerName || 'G').charAt(0).toUpperCase()}
                    </div>

                    <div className="space-y-1.5 flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="font-black text-base text-slate-900 flex items-center gap-2 truncate">
                          <span>{client.customerName}</span>
                          {client.isMember && (
                            <span className="px-2 py-0.5 bg-indigo-50 text-indigo-700 border border-indigo-200/60 rounded-full text-[10px] font-black uppercase tracking-wider">
                              Member
                            </span>
                          )}
                        </h3>

                        {/* Highest Intent Badge */}
                        {isHotLead ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 bg-rose-500 text-white rounded-full text-[10px] font-black uppercase tracking-wider shadow-sm animate-pulse">
                            <Flame className="w-3 h-3 fill-current" />
                            <span>Hot Lead</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-blue-50 text-blue-700 rounded-full text-[10px] font-black uppercase">
                            <Eye className="w-3 h-3" />
                            <span>Browsing</span>
                          </span>
                        )}

                        {/* Source Devices */}
                        <div className="flex items-center gap-1">
                          {client.sources.map(src => (
                            <span key={src} className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded-full text-[10px] font-black uppercase">
                              {src === 'ios' ? '📱 iOS' : src === 'android' ? '🤖 Android' : '💻 Web'}
                            </span>
                          ))}
                        </div>

                        <span className="text-[11px] text-slate-400 font-bold ml-auto lg:ml-0 flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          <span>{formatTimeAgo(client.lastActivityAt)}</span>
                        </span>
                      </div>

                      {/* Summary Sub-line: Services & Package clicks */}
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className="bg-indigo-50 text-indigo-800 font-black px-2.5 py-0.5 rounded-lg border border-indigo-100 flex items-center gap-1">
                          <Layers className="w-3 h-3" />
                          <span>{uniqueServicesCount} {uniqueServicesCount === 1 ? 'Service' : 'Services'} Explored</span>
                        </span>

                        <span className="bg-slate-100 text-slate-700 font-bold px-2.5 py-0.5 rounded-lg flex items-center gap-1">
                          <Activity className="w-3 h-3 text-slate-500" />
                          <span>{totalActivitiesCount} Telemetry Logs</span>
                        </span>

                        {latestService && (
                          <span className="text-slate-500 font-medium truncate max-w-xs">
                            Latest: <strong className="text-slate-800">{latestService.serviceName}</strong>
                          </span>
                        )}
                      </div>

                      {/* Contact Channels */}
                      <div className="flex flex-wrap items-center gap-4 text-xs text-slate-500 font-medium pt-0.5">
                        {client.phone && (
                          <span className="flex items-center gap-1 font-bold text-slate-700">
                            <Phone className="w-3.5 h-3.5 text-slate-400" />
                            <span>{client.phone}</span>
                          </span>
                        )}
                        {client.email && (
                          <span className="flex items-center gap-1 text-slate-600 truncate max-w-[220px]">
                            <Mail className="w-3.5 h-3.5 text-slate-400" />
                            <span className="truncate">{client.email}</span>
                          </span>
                        )}
                        {client.notes.length > 0 && (
                          <span className="px-2 py-0.5 bg-amber-50 text-amber-800 border border-amber-200 rounded-md font-bold text-[10px]">
                            {client.notes.length} {client.notes.length === 1 ? 'Note' : 'Notes'}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Right Actions & Status Controls (Stop propagation so clicking dropdowns won't toggle accordion) */}
                  <div
                    className="flex flex-wrap items-center gap-2 pt-3 lg:pt-0 border-t lg:border-t-0 border-slate-100 shrink-0"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {/* WhatsApp Quick Action */}
                    {client.phone && (
                      <a
                        href={getClientWhatsAppLink(client)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-3 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-bold transition flex items-center gap-1.5 shadow-sm active:scale-95"
                      >
                        <MessageSquare className="w-3.5 h-3.5" />
                        <span>WhatsApp</span>
                      </a>
                    )}

                    {/* Direct Call */}
                    {client.phone && (
                      <a
                        href={`tel:${client.phone}`}
                        className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition"
                        title="Direct Call"
                      >
                        <Phone className="w-4 h-4" />
                      </a>
                    )}

                    {/* Assign to Employee (Admin Only) */}
                    {role === 'admin' && employees.length > 0 && (
                      <select
                        value={client.assignedTo?._id || client.assignedTo || ''}
                        onChange={(e) => handleClientAssignEmployee(client, e.target.value)}
                        className="px-2.5 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-700 focus:outline-none focus:border-indigo-500"
                      >
                        <option value="">Unassigned</option>
                        {employees.map(emp => (
                          <option key={emp._id} value={emp._id}>{emp.name}</option>
                        ))}
                      </select>
                    )}

                    {/* Master Client Status Dropdown */}
                    <select
                      value={client.status}
                      disabled={isUpdatingStatusFor === client.id}
                      onChange={(e) => handleClientStatusChange(client, e.target.value)}
                      className={`px-3 py-2 rounded-xl text-xs font-black uppercase tracking-wider focus:outline-none border transition ${
                        client.status === 'CONVERTED' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' :
                        client.status === 'NEW' ? 'bg-rose-50 text-rose-700 border-rose-200 font-black' :
                        client.status === 'CONTACTED' ? 'bg-blue-50 text-blue-700 border-blue-200' :
                        client.status === 'IN_PROGRESS' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                        'bg-slate-100 text-slate-600 border-slate-200'
                      }`}
                    >
                      <option value="NEW">🔴 New</option>
                      <option value="CONTACTED">🔵 Contacted</option>
                      <option value="IN_PROGRESS">🟡 In Progress</option>
                      <option value="CONVERTED">🟢 Converted</option>
                      <option value="LOST">⚪ Lost</option>
                    </select>

                    {/* Accordion Expand/Collapse Button */}
                    <button
                      onClick={() => toggleClientExpansion(client.id)}
                      className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition flex items-center justify-center ml-1"
                      title={isExpanded ? 'Collapse Details' : 'Expand Client Details'}
                    >
                      {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-700" /> : <ChevronDown className="w-4 h-4 text-slate-700" />}
                    </button>
                  </div>
                </div>

                {/* 5. Expanded Accordion Content (Complete Client Journey Inside) */}
                {isExpanded && (
                  <div className="p-5 md:p-6 bg-slate-50/70 border-t border-slate-100 space-y-6 animate-in fade-in slide-in-from-top-2 duration-200">
                    {/* A. Services & Pricing Interest Grid */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Layers className="w-4 h-4 text-indigo-600" />
                          <h4 className="text-xs font-black uppercase tracking-wider text-slate-700">
                            Explored Services & Packages ({client.services.length})
                          </h4>
                        </div>
                        {client.totalPriceInterest > 0 && (
                          <span className="text-xs font-black text-rose-700 bg-rose-50 border border-rose-200 px-2.5 py-1 rounded-lg">
                            Pipeline Interest: ₹{client.totalPriceInterest.toLocaleString()}
                          </span>
                        )}
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {client.services.map((service, sIdx) => {
                          const hasPackageClicks = service.highestCategory === 'PACKAGE_CLICK';

                          return (
                            <div
                              key={sIdx}
                              className={`p-4 rounded-2xl border transition-all ${
                                hasPackageClicks
                                  ? 'bg-white border-rose-200 shadow-sm'
                                  : 'bg-white border-slate-200'
                              }`}
                            >
                              <div className="flex items-start justify-between gap-2 mb-2">
                                <h5 className="font-bold text-sm text-slate-900 leading-snug">
                                  {service.serviceName}
                                </h5>
                                {hasPackageClicks ? (
                                  <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-rose-100 text-rose-700 rounded-full text-[10px] font-black uppercase shrink-0">
                                    <Flame className="w-3 h-3" />
                                    <span>Hot Package Click</span>
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-slate-100 text-slate-600 rounded-full text-[10px] font-bold shrink-0">
                                    <Eye className="w-3 h-3" />
                                    <span>Page View</span>
                                  </span>
                                )}
                              </div>

                              {/* Package Clicks under this service */}
                              {service.packages.length > 0 ? (
                                <div className="space-y-1.5 mt-2 pt-2 border-t border-slate-100">
                                  <div className="text-[10px] font-black uppercase text-slate-400">Selected Plans & Pricing:</div>
                                  {service.packages.map((pkg, pIdx) => (
                                    <div key={pIdx} className="flex items-center justify-between bg-rose-50/60 p-2 rounded-xl border border-rose-100 text-xs">
                                      <span className="font-bold text-rose-900 flex items-center gap-1.5">
                                        <Tag className="w-3 h-3 text-rose-500" />
                                        <span>{pkg.name}</span>
                                      </span>
                                      <div className="flex items-center gap-2">
                                        {pkg.price > 0 && (
                                          <span className="font-black text-rose-700 bg-white px-2 py-0.5 rounded-lg border border-rose-200">
                                            ₹{pkg.price.toLocaleString()}
                                          </span>
                                        )}
                                        <span className="text-[10px] text-slate-400 font-medium">
                                          {formatTimeAgo(pkg.time)}
                                        </span>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <div className="text-[11px] text-slate-400 italic mt-2">
                                  Browsed service details and requirements.
                                </div>
                              )}

                              {/* Footer metrics for this service */}
                              <div className="flex items-center justify-between text-[10px] text-slate-400 font-medium mt-3 pt-2 border-t border-slate-100">
                                <span>{service.clickCount} Price Taps • {service.viewCount} Views</span>
                                <span>Active {formatTimeAgo(service.lastActivityAt)}</span>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* B. Follow-Up Notes & Client Conversation Thread */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <MessageSquare className="w-4 h-4 text-indigo-600" />
                          <h4 className="text-xs font-black uppercase tracking-wider text-slate-700">
                            Client Follow-Up Notes ({client.notes.length})
                          </h4>
                        </div>
                      </div>

                      {/* Notes list */}
                      <div className="space-y-2">
                        {client.notes.length > 0 ? (
                          client.notes.map((note, nIdx) => (
                            <div key={nIdx} className="bg-white p-3.5 rounded-xl border border-slate-200 text-xs space-y-1 shadow-sm">
                              <div className="flex items-center justify-between text-slate-400 font-bold text-[10px]">
                                <span className="text-indigo-600 font-black flex items-center gap-1">
                                  <UserCheck className="w-3 h-3" />
                                  <span>{note.author} ({note.authorRole})</span>
                                </span>
                                <span>{new Date(note.createdAt).toLocaleString()}</span>
                              </div>
                              <p className="text-slate-700 font-medium leading-relaxed">{note.text}</p>
                            </div>
                          ))
                        ) : (
                          <div className="bg-white p-4 rounded-xl border border-slate-200 text-center text-xs text-slate-400 italic">
                            No follow-up notes recorded yet for this client. Add the first note below.
                          </div>
                        )}
                      </div>

                      {/* Inline Note Composer */}
                      <div className="bg-white p-3 rounded-2xl border border-slate-200 shadow-sm flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                        <input
                          type="text"
                          placeholder="Write a follow-up note (e.g. Spoke to client on call, interested in startup plan)..."
                          value={clientNoteInputs[client.id] || ''}
                          onChange={(e) => setClientNoteInputs(prev => ({ ...prev, [client.id]: e.target.value }))}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') {
                              e.preventDefault();
                              handleAddClientNote(client);
                            }
                          }}
                          className="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-medium text-slate-800 placeholder-slate-400 focus:outline-none focus:border-indigo-500"
                        />
                        <button
                          onClick={() => handleAddClientNote(client)}
                          disabled={isSubmittingNoteFor === client.id || !(clientNoteInputs[client.id] || '').trim()}
                          className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-md shrink-0"
                        >
                          <Send className="w-3.5 h-3.5" />
                          <span>{isSubmittingNoteFor === client.id ? 'Saving...' : 'Add Note'}</span>
                        </button>
                      </div>
                    </div>

                    {/* C. Full Telemetry Journey Trail */}
                    <div className="pt-2 border-t border-slate-200">
                      <details className="group">
                        <summary className="cursor-pointer text-xs font-bold text-slate-500 hover:text-slate-800 flex items-center gap-1.5 select-none py-1">
                          <Activity className="w-3.5 h-3.5 text-indigo-500" />
                          <span>View Complete Raw Event Telemetry ({client.activities.length} Events)</span>
                          <ChevronRight className="w-3.5 h-3.5 transition group-open:rotate-90 ml-auto text-slate-400" />
                        </summary>
                        <div className="mt-3 space-y-2 max-h-52 overflow-y-auto pr-1">
                          {client.activities.map((act, actIdx) => (
                            <div key={actIdx} className="bg-white p-2.5 rounded-xl border border-slate-200 flex items-center justify-between text-[11px]">
                              <div className="flex items-center gap-2">
                                <span className={`w-2 h-2 rounded-full ${act.category === 'PACKAGE_CLICK' ? 'bg-rose-500' : 'bg-blue-500'}`}></span>
                                <strong className="text-slate-800">{act.serviceName}</strong>
                                {act.packageName && (
                                  <span className="text-rose-600 font-bold bg-rose-50 px-1.5 py-0.5 rounded">
                                    {act.packageName} {act.price ? `(₹${act.price})` : ''}
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center gap-2 text-slate-400 text-[10px]">
                                <span className="uppercase font-bold">{act.source}</span>
                                <span>•</span>
                                <span>{new Date(act.lastActivityAt || act.createdAt).toLocaleString()}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </details>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default LeadsManagerView;
