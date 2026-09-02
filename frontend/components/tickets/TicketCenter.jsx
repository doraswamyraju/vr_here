import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
  LifeBuoy,
  Plus,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  AlertCircle,
  MessageSquare,
  Send,
  User as UserIcon,
  Shield,
  Tag,
  ChevronRight,
  ArrowLeft,
  X,
  RefreshCw,
  Sparkles,
  Wrench,
  Briefcase,
  Headphones,
  CheckCheck
} from 'lucide-react';

const CATEGORY_CONFIG = {
  Technical: {
    label: 'Technical',
    desc: 'Website issues, login, file uploads, or gateway errors',
    icon: Wrench,
    badgeBg: 'bg-blue-50 text-blue-700 border-blue-200',
    headerGrad: 'from-blue-600 to-indigo-600'
  },
  Service: {
    label: 'Service',
    desc: 'Filing status, MCA queries, CA review, and incorporation',
    icon: Briefcase,
    badgeBg: 'bg-purple-50 text-purple-700 border-purple-200',
    headerGrad: 'from-purple-600 to-violet-600'
  },
  Support: {
    label: 'Support',
    desc: 'Billing, tax invoices, receipts, and general inquiries',
    icon: Headphones,
    badgeBg: 'bg-amber-50 text-amber-800 border-amber-200',
    headerGrad: 'from-amber-600 to-orange-600'
  }
};

const PRIORITY_BADGES = {
  Urgent: 'bg-rose-100 text-rose-700 border-rose-200 font-bold',
  High: 'bg-red-50 text-red-600 border-red-200',
  Medium: 'bg-amber-50 text-amber-700 border-amber-200',
  Low: 'bg-slate-100 text-slate-600 border-slate-200'
};

const STATUS_BADGES = {
  Open: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  'In Progress': 'bg-blue-50 text-blue-700 border-blue-200',
  Resolved: 'bg-teal-50 text-teal-700 border-teal-200',
  Closed: 'bg-slate-100 text-slate-500 border-slate-200'
};

export default function TicketCenter({ userInfo, userRole = 'client' }) {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [selectedStatus, setSelectedStatus] = useState('All');

  // Modal State
  const [isNewModalOpen, setIsNewModalOpen] = useState(false);
  const [newCategory, setNewCategory] = useState('Service');
  const [newSubject, setNewSubject] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newPriority, setNewPriority] = useState('Medium');
  const [isSubmittingNew, setIsSubmittingNew] = useState(false);

  // Message Sending
  const [replyMessage, setReplyMessage] = useState('');
  const [isSendingReply, setIsSendingReply] = useState(false);
  const messagesEndRef = useRef(null);

  const authHeaders = {
    headers: { Authorization: `Bearer ${userInfo?.token}` }
  };

  const isStaffOrAdmin = userRole === 'admin' || userRole === 'employee';

  const fetchTickets = async () => {
    try {
      setLoading(true);
      const { data } = await axios.get('/api/tickets', authHeaders);
      setTickets(Array.isArray(data) ? data : []);
      if (selectedTicket) {
        const updated = (Array.isArray(data) ? data : []).find(t => t._id === selectedTicket._id);
        if (updated) setSelectedTicket(updated);
      }
    } catch (err) {
      console.error('Failed to load tickets:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTickets();
  }, [userInfo?.token]);

  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [selectedTicket?.messages]);

  const handleCreateTicket = async (e) => {
    e.preventDefault();
    if (!newSubject.trim() || !newDescription.trim()) {
      alert('Please provide a subject and description.');
      return;
    }

    try {
      setIsSubmittingNew(true);
      const payload = {
        category: newCategory,
        subject: newSubject.trim(),
        description: newDescription.trim(),
        priority: newPriority
      };

      const { data: created } = await axios.post('/api/tickets', payload, authHeaders);
      setTickets(prev => [created, ...prev]);
      setSelectedTicket(created);
      setIsNewModalOpen(false);
      setNewSubject('');
      setNewDescription('');
      setNewPriority('Medium');
    } catch (err) {
      console.error('Failed to create ticket:', err);
      alert(err?.response?.data?.message || 'Failed to submit ticket. Please try again.');
    } finally {
      setIsSubmittingNew(false);
    }
  };

  const handleSendReply = async (e) => {
    e.preventDefault();
    if (!replyMessage.trim() || !selectedTicket) return;

    try {
      setIsSendingReply(true);
      const { data: updated } = await axios.post(
        `/api/tickets/${selectedTicket._id}/messages`,
        { message: replyMessage.trim() },
        authHeaders
      );

      setSelectedTicket(updated);
      setTickets(prev => prev.map(t => t._id === updated._id ? updated : t));
      setReplyMessage('');
    } catch (err) {
      console.error('Failed to send reply:', err);
      alert(err?.response?.data?.message || 'Failed to send message.');
    } finally {
      setIsSendingReply(false);
    }
  };

  const handleUpdateTicketProps = async (updates) => {
    if (!selectedTicket) return;
    try {
      const { data: updated } = await axios.put(
        `/api/tickets/${selectedTicket._id}`,
        updates,
        authHeaders
      );
      setSelectedTicket(updated);
      setTickets(prev => prev.map(t => t._id === updated._id ? updated : t));
    } catch (err) {
      console.error('Failed to update ticket:', err);
      alert(err?.response?.data?.message || 'Failed to update ticket properties.');
    }
  };

  // Filter tickets
  const filteredTickets = tickets.filter(t => {
    const matchesSearch = 
      (t.subject || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (t.ticketNumber || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (t.user?.name || '').toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesCategory = selectedCategory === 'All' || t.category === selectedCategory;
    const matchesStatus = selectedStatus === 'All' || t.status === selectedStatus;

    return matchesSearch && matchesCategory && matchesStatus;
  });

  return (
    <div className="space-y-6 pb-20 animate-in fade-in duration-300">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-950 to-slate-900 rounded-3xl p-6 sm:p-8 text-white border border-slate-800 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 text-xs font-black uppercase tracking-widest mb-3">
            <LifeBuoy size={14} /> Support & Resolution Desk
          </div>
          <h1 className="text-2xl sm:text-3xl font-black tracking-tight">
            {isStaffOrAdmin ? 'Support Ticket Management' : 'Help & Support Tickets'}
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 font-medium max-w-xl">
            {isStaffOrAdmin
              ? 'Resolve customer inquiries across Technical, Service, and Support channels with real-time tracking.'
              : 'Direct communication line with dedicated CA, legal compliance specialists, and tech support.'}
          </p>
        </div>

        <button
          onClick={() => setIsNewModalOpen(true)}
          className="px-6 py-3.5 bg-red-600 hover:bg-red-700 active:scale-95 text-white rounded-2xl text-xs font-black uppercase tracking-wider transition-all shadow-lg shadow-red-600/30 flex items-center justify-center gap-2 shrink-0"
        >
          <Plus size={16} /> Raise New Ticket
        </button>
      </div>

      {/* Main Workspace Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Side: Ticket List & Filters */}
        <div className={`lg:col-span-5 bg-white rounded-3xl border border-slate-200/80 shadow-sm overflow-hidden flex flex-col h-[700px] ${selectedTicket ? 'hidden lg:flex' : 'flex'}`}>
          {/* Filters Bar */}
          <div className="p-4 border-b border-slate-100 space-y-3 bg-slate-50/50">
            <div className="relative">
              <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search ticket number, subject, client..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-white rounded-xl border border-slate-200 text-xs font-medium placeholder:text-slate-400 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500 transition-all"
              />
            </div>

            {/* Category Tabs */}
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none">
              {['All', 'Technical', 'Service', 'Support'].map(cat => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-3 py-1.5 rounded-xl text-[11px] font-black uppercase tracking-wider whitespace-nowrap transition-all ${
                    selectedCategory === cat
                      ? 'bg-slate-900 text-white shadow-sm'
                      : 'bg-white text-slate-600 hover:bg-slate-100 border border-slate-200/70'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>

            {/* Status Pills */}
            <div className="flex items-center gap-1 overflow-x-auto text-[10px] font-bold text-slate-500">
              <span className="text-slate-400 mr-1 shrink-0">Status:</span>
              {['All', 'Open', 'In Progress', 'Resolved', 'Closed'].map(st => (
                <button
                  key={st}
                  onClick={() => setSelectedStatus(st)}
                  className={`px-2.5 py-1 rounded-lg transition-colors ${
                    selectedStatus === st
                      ? 'bg-red-50 text-red-700 font-black'
                      : 'hover:bg-slate-200/60'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          {/* Ticket List Items */}
          <div className="flex-1 overflow-y-auto divide-y divide-slate-100 p-2 space-y-1">
            {loading ? (
              <div className="flex flex-col items-center justify-center p-12 text-slate-400">
                <RefreshCw size={24} className="animate-spin mb-2 text-red-600" />
                <p className="text-xs font-bold">Loading tickets...</p>
              </div>
            ) : filteredTickets.length === 0 ? (
              <div className="p-12 text-center text-slate-400 space-y-2">
                <LifeBuoy size={36} className="mx-auto text-slate-300 stroke-[1.5]" />
                <p className="text-xs font-bold text-slate-600">No tickets found</p>
                <p className="text-[11px]">No active requests match your current filters.</p>
              </div>
            ) : (
              filteredTickets.map(ticket => {
                const catConfig = CATEGORY_CONFIG[ticket.category] || CATEGORY_CONFIG.Support;
                const CatIcon = catConfig.icon;
                const isSelected = selectedTicket?._id === ticket._id;

                return (
                  <div
                    key={ticket._id}
                    onClick={() => setSelectedTicket(ticket)}
                    className={`p-3.5 rounded-2xl cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-red-50/70 border border-red-200/90 shadow-sm'
                        : 'hover:bg-slate-50 border border-transparent'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-1.5">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[9px] font-black uppercase tracking-wider border ${catConfig.badgeBg}`}>
                          <CatIcon size={10} /> {ticket.category}
                        </span>
                        <span className="text-[10px] font-mono font-bold text-slate-400">
                          {ticket.ticketNumber || 'VR-TCK'}
                        </span>
                      </div>

                      <span className={`text-[9px] px-2 py-0.5 rounded-full border font-black uppercase tracking-wider ${STATUS_BADGES[ticket.status] || 'bg-slate-100'}`}>
                        {ticket.status}
                      </span>
                    </div>

                    <h4 className="text-xs font-black text-slate-900 line-clamp-1 mb-1">
                      {ticket.subject}
                    </h4>

                    <p className="text-[11px] text-slate-500 line-clamp-2 leading-relaxed mb-2">
                      {ticket.messages && ticket.messages.length > 0
                        ? ticket.messages[ticket.messages.length - 1].message
                        : ticket.description}
                    </p>

                    <div className="flex items-center justify-between text-[10px] text-slate-400 font-medium">
                      <span>{isStaffOrAdmin ? ticket.user?.name || 'Client' : 'Priority: ' + ticket.priority}</span>
                      <span>{new Date(ticket.updatedAt || ticket.createdAt).toLocaleDateString('en-IN', { month: 'short', day: 'numeric' })}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Side: Conversation Thread & Actions */}
        <div className={`lg:col-span-7 bg-white rounded-3xl border border-slate-200/80 shadow-sm overflow-hidden flex flex-col h-[700px] ${selectedTicket ? 'flex' : 'hidden lg:flex'}`}>
          {selectedTicket ? (
            <>
              {/* Header */}
              <div className="p-4 sm:p-5 border-b border-slate-100 bg-slate-50/70">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-3">
                    <button
                      onClick={() => setSelectedTicket(null)}
                      className="lg:hidden p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 rounded-lg mt-0.5"
                    >
                      <ArrowLeft size={18} />
                    </button>

                    <div>
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span className="text-xs font-mono font-black text-red-600 bg-red-50 px-2 py-0.5 rounded-md border border-red-100">
                          {selectedTicket.ticketNumber || 'VR-TCK'}
                        </span>
                        <span className="text-xs font-bold text-slate-500">
                          • {selectedTicket.category} Department
                        </span>
                        <span className={`text-[10px] px-2 py-0.5 rounded-md border font-black uppercase ${PRIORITY_BADGES[selectedTicket.priority]}`}>
                          {selectedTicket.priority} Priority
                        </span>
                      </div>
                      <h3 className="text-base font-black text-slate-900 leading-snug">
                        {selectedTicket.subject}
                      </h3>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        Opened by <strong>{selectedTicket.user?.name || 'Client'}</strong> on {new Date(selectedTicket.createdAt).toLocaleDateString('en-IN', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </p>
                    </div>
                  </div>

                  {/* Staff / Admin Controls */}
                  {isStaffOrAdmin && (
                    <div className="flex items-center gap-2 shrink-0">
                      <select
                        value={selectedTicket.status}
                        onChange={(e) => handleUpdateTicketProps({ status: e.target.value })}
                        className="text-xs font-bold px-3 py-1.5 bg-white border border-slate-200 rounded-xl focus:outline-none focus:border-red-500 shadow-sm"
                      >
                        <option value="Open">Open</option>
                        <option value="In Progress">In Progress</option>
                        <option value="Resolved">Resolved</option>
                        <option value="Closed">Closed</option>
                      </select>
                    </div>
                  )}
                </div>
              </div>

              {/* Chat Thread Messages */}
              <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4 bg-slate-50/30">
                {/* Initial Ticket Description Post */}
                <div className="bg-white p-4 rounded-2xl border border-slate-200/80 shadow-xs space-y-2">
                  <div className="flex items-center justify-between text-xs font-bold text-slate-700">
                    <span className="flex items-center gap-1.5 text-slate-900">
                      <UserIcon size={14} className="text-slate-400" />
                      {selectedTicket.user?.name || 'Client'} (Issue Description)
                    </span>
                    <span className="text-[10px] text-slate-400 font-normal">
                      {new Date(selectedTicket.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <p className="text-xs text-slate-700 whitespace-pre-wrap leading-relaxed">
                    {selectedTicket.description}
                  </p>
                </div>

                {/* Subsequent Messages */}
                {selectedTicket.messages && selectedTicket.messages.map((msg, mIdx) => {
                  const isStaff = msg.sender?.role === 'admin' || msg.sender?.role === 'employee';
                  const isCurrentClient = !isStaff;

                  return (
                    <div
                      key={mIdx}
                      className={`flex flex-col ${isCurrentClient ? 'items-start' : 'items-end'}`}
                    >
                      <div className="flex items-center gap-1.5 mb-1 px-1">
                        <span className="text-[10px] font-bold text-slate-500">
                          {msg.sender?.name || (isStaff ? 'VR HERE Specialist' : 'Client')}
                        </span>
                        {isStaff && (
                          <span className="px-1.5 py-0.2 rounded bg-red-100 text-red-700 text-[8px] font-black uppercase">
                            Team
                          </span>
                        )}
                        <span className="text-[9px] text-slate-400">
                          {new Date(msg.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>

                      <div
                        className={`max-w-[85%] p-3.5 rounded-2xl text-xs leading-relaxed whitespace-pre-wrap ${
                          isCurrentClient
                            ? 'bg-white border border-slate-200/80 text-slate-800 rounded-tl-sm'
                            : 'bg-gradient-to-br from-slate-900 to-slate-800 text-white shadow-md rounded-tr-sm'
                        }`}
                      >
                        {msg.message}
                      </div>
                    </div>
                  );
                })}
                <div ref={messagesEndRef} />
              </div>

              {/* Reply Input Box */}
              <form onSubmit={handleSendReply} className="p-3 sm:p-4 bg-white border-t border-slate-100 flex items-center gap-2">
                <input
                  type="text"
                  placeholder="Type a message or resolution update..."
                  value={replyMessage}
                  onChange={(e) => setReplyMessage(e.target.value)}
                  disabled={selectedTicket.status === 'Closed' || isSendingReply}
                  className="flex-1 px-4 py-3 bg-slate-50 rounded-2xl border border-slate-200 text-xs font-medium placeholder:text-slate-400 focus:outline-none focus:border-red-500 focus:bg-white transition-all disabled:opacity-50"
                />
                <button
                  type="submit"
                  disabled={!replyMessage.trim() || isSendingReply || selectedTicket.status === 'Closed'}
                  className="p-3 bg-red-600 hover:bg-red-700 active:scale-95 text-white rounded-2xl transition-all shadow-md shadow-red-600/20 disabled:opacity-40 shrink-0"
                >
                  <Send size={16} />
                </button>
              </form>
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-12 text-slate-400 text-center space-y-3">
              <div className="w-16 h-16 rounded-3xl bg-slate-50 border border-slate-200 flex items-center justify-center text-slate-400">
                <MessageSquare size={28} />
              </div>
              <h4 className="text-sm font-black text-slate-700">Select a Ticket</h4>
              <p className="text-xs text-slate-400 max-w-sm">
                Choose a ticket from the list to view its complete conversation history, status, and post replies.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Modal: Raise New Ticket */}
      {isNewModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-white w-full max-w-xl rounded-3xl shadow-2xl border border-slate-200 overflow-hidden animate-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="p-6 bg-slate-900 text-white flex items-center justify-between">
              <div>
                <span className="text-[10px] font-black uppercase tracking-widest text-red-400 bg-red-500/20 px-2.5 py-1 rounded-full border border-red-500/30">
                  New Support Request
                </span>
                <h3 className="text-lg font-black mt-1">Raise Support Ticket</h3>
              </div>
              <button
                onClick={() => setIsNewModalOpen(false)}
                className="p-2 text-slate-400 hover:text-white rounded-xl hover:bg-slate-800 transition-colors"
              >
                <X size={18} />
              </button>
            </div>

            {/* Form */}
            <form onSubmit={handleCreateTicket} className="p-6 space-y-4">
              {/* Category Selector Cards */}
              <div>
                <label className="block text-xs font-black uppercase tracking-wider text-slate-700 mb-2">
                  Select Department / Category
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                  {Object.entries(CATEGORY_CONFIG).map(([key, config]) => {
                    const IconComp = config.icon;
                    const isSelected = newCategory === key;
                    return (
                      <div
                        key={key}
                        onClick={() => setNewCategory(key)}
                        className={`p-3 rounded-2xl border cursor-pointer transition-all ${
                          isSelected
                            ? 'bg-slate-900 text-white border-slate-900 shadow-md ring-2 ring-red-500/50'
                            : 'bg-slate-50 hover:bg-slate-100/80 border-slate-200/80 text-slate-700'
                        }`}
                      >
                        <IconComp size={18} className={isSelected ? 'text-red-400' : 'text-slate-500'} />
                        <h5 className="text-xs font-black mt-2">{config.label}</h5>
                        <p className={`text-[10px] mt-1 leading-snug line-clamp-2 ${isSelected ? 'text-slate-300' : 'text-slate-400'}`}>
                          {config.desc}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Priority */}
              <div>
                <label className="block text-xs font-black uppercase tracking-wider text-slate-700 mb-1.5">
                  Urgency Level
                </label>
                <div className="flex items-center gap-2">
                  {['Low', 'Medium', 'High', 'Urgent'].map(p => (
                    <button
                      type="button"
                      key={p}
                      onClick={() => setNewPriority(p)}
                      className={`flex-1 py-2 rounded-xl text-xs font-bold border transition-all ${
                        newPriority === p
                          ? 'bg-slate-900 text-white border-slate-900 shadow-xs'
                          : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                      }`}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </div>

              {/* Subject */}
              <div>
                <label className="block text-xs font-black uppercase tracking-wider text-slate-700 mb-1.5">
                  Subject / Topic
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Query regarding DSC signature in MCA filing"
                  value={newSubject}
                  onChange={(e) => setNewSubject(e.target.value)}
                  className="w-full px-4 py-2.5 bg-slate-50 rounded-xl border border-slate-200 text-xs font-medium focus:outline-none focus:border-red-500 focus:bg-white transition-all"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-xs font-black uppercase tracking-wider text-slate-700 mb-1.5">
                  Detailed Explanation
                </label>
                <textarea
                  required
                  rows={4}
                  placeholder="Please describe what you need assistance with in detail..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full p-4 bg-slate-50 rounded-xl border border-slate-200 text-xs font-medium focus:outline-none focus:border-red-500 focus:bg-white transition-all resize-none"
                />
              </div>

              {/* Actions */}
              <div className="pt-2 flex items-center justify-end gap-2.5 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setIsNewModalOpen(false)}
                  className="px-5 py-2.5 text-xs font-bold text-slate-600 hover:bg-slate-100 rounded-xl transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingNew}
                  className="px-6 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-xl text-xs font-black uppercase tracking-wider transition-all shadow-md shadow-red-600/20 disabled:opacity-50 flex items-center gap-2"
                >
                  {isSubmittingNew ? <RefreshCw size={14} className="animate-spin" /> : <Send size={14} />}
                  Submit Ticket
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
