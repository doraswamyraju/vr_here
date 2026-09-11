import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { 
  AlertCircle, CheckCircle2, Clock, MessageSquare, Plus, 
  Send, ShieldAlert, Lock, User, Tag, ChevronDown, ChevronUp,
  AlertTriangle, Check, RefreshCw
} from 'lucide-react';

const ISSUE_TYPES = [
  'Workflow Blocked',
  'Missing Input / Client Document',
  'Quality & QA Audit Issue',
  'Technical / Portal Glitch',
  'Scope Clarification Required',
  'Timeline & SLA Risk',
  'Other Internal Issue'
];

export const CreateWorkflowTicketModal = ({ 
  isOpen, 
  onClose, 
  order, 
  token, 
  employees = [],
  onTicketCreated 
}) => {
  if (!isOpen || !order) return null;

  const [issueType, setIssueType] = useState('Workflow Blocked');
  const [priority, setPriority] = useState('High');
  const [subject, setSubject] = useState('');
  const [description, setDescription] = useState('');
  const [assignedTo, setAssignedTo] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!subject.trim() || !description.trim()) {
      setErrorMsg('Please enter both subject and description.');
      return;
    }

    setIsSubmitting(true);
    setErrorMsg('');

    try {
      const config = { headers: { Authorization: `Bearer ${token}` } };
      const payload = {
        orderId: order._id,
        isInternal: true,
        issueType,
        category: 'Workflow',
        subject: `[Order #${order._id.slice(-6).toUpperCase()}] ${subject.trim()}`,
        description: description.trim(),
        priority,
        assignedTo: assignedTo || null
      };

      const { data } = await axios.post('/api/tickets', payload, config);
      if (onTicketCreated) onTicketCreated(data);
      onClose();
    } catch (err) {
      setErrorMsg(err.response?.data?.message || 'Failed to raise workflow ticket.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-white w-full max-w-xl rounded-3xl shadow-2xl border border-slate-100 overflow-hidden animate-in zoom-in-95 duration-150">
        <div className="p-5 bg-gradient-to-r from-slate-900 via-rose-950 to-slate-900 text-white flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-rose-500/20 border border-rose-500/30 flex items-center justify-center text-rose-400">
              <ShieldAlert size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-extrabold text-base">Raise Internal Workflow Ticket</h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider bg-rose-500/30 text-rose-300 border border-rose-400/30 flex items-center gap-1">
                  <Lock size={10} /> Internal Staff Only
                </span>
              </div>
              <p className="text-xs text-slate-400">Not visible to customer • Tracked in tickets desk</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-white/10 hover:bg-white/20 text-slate-300 hover:text-white flex items-center justify-center transition"
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4 text-xs">
          {errorMsg && (
            <div className="p-3 rounded-xl bg-rose-50 text-rose-800 border border-rose-200 font-bold flex items-center gap-2">
              <AlertCircle size={15} />
              {errorMsg}
            </div>
          )}

          <div className="p-3 bg-amber-50/70 border border-amber-200/70 rounded-xl text-amber-900">
            <p className="font-bold flex items-center gap-1.5">
              <AlertTriangle size={14} className="text-amber-600" /> Linked Order: {order.serviceName}
            </p>
            <p className="text-[11px] text-amber-800 mt-0.5">
              Client: <strong>{order.clientName || order.user?.name || 'Customer'}</strong> • ID: {order._id.slice(-6).toUpperCase()}
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="font-bold text-slate-700">Issue Category / Type</label>
              <select
                value={issueType}
                onChange={(e) => setIssueType(e.target.value)}
                className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-rose-500"
              >
                {ISSUE_TYPES.map((type) => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            </div>

            <div className="space-y-1">
              <label className="font-bold text-slate-700">Urgency / Priority</label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-rose-500"
              >
                <option value="Low">Low (Minor Note)</option>
                <option value="Medium">Medium (Standard)</option>
                <option value="High">High (Needs Attention)</option>
                <option value="Urgent">Urgent (Workflow Blocked)</option>
              </select>
            </div>
          </div>

          <div className="space-y-1">
            <label className="font-bold text-slate-700">Assign To Staff / Manager (Optional)</label>
            <select
              value={assignedTo}
              onChange={(e) => setAssignedTo(e.target.value)}
              className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-rose-500"
            >
              <option value="">-- Unassigned (Admins & PMs Queue) --</option>
              {employees.map((emp) => (
                <option key={emp._id} value={emp._id}>
                  {emp.name} ({emp.role || 'Staff'})
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1">
            <label className="font-bold text-slate-700">Ticket Subject / Summary</label>
            <input
              type="text"
              required
              placeholder="e.g. Client uploaded expired Aadhaar OTP or Portal login error"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-rose-500"
            />
          </div>

          <div className="space-y-1">
            <label className="font-bold text-slate-700">Detailed Description of Hazard / Block</label>
            <textarea
              required
              rows={3}
              placeholder="Explain what is blocked, what action is needed from admin/PM/maker/checker..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-rose-500"
            />
          </div>

          <div className="pt-2 flex items-center justify-end gap-2.5 border-t border-slate-100">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-600 font-bold transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-5 py-2 rounded-xl bg-rose-600 hover:bg-rose-700 text-white font-extrabold shadow-md shadow-rose-200 transition flex items-center gap-1.5 disabled:opacity-50"
            >
              <ShieldAlert size={14} />
              {isSubmitting ? 'Raising Ticket...' : 'Raise Internal Ticket'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const OrderWorkflowTicketsTab = ({ order, token, employees = [] }) => {
  const [tickets, setTickets] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [expandedTicketId, setExpandedTicketId] = useState(null);
  const [replyText, setReplyText] = useState({});
  const [isSendingReply, setIsSendingReply] = useState({});

  const config = { headers: { Authorization: `Bearer ${token}` } };

  const fetchTickets = useCallback(async () => {
    if (!order?._id || !token) return;
    setIsLoading(true);
    try {
      const { data } = await axios.get(`/api/tickets?orderId=${order._id}`, config);
      setTickets(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error('Failed to load order workflow tickets:', err);
    } finally {
      setIsLoading(false);
    }
  }, [order?._id, token]);

  useEffect(() => {
    fetchTickets();
  }, [fetchTickets]);

  const handleStatusChange = async (ticketId, newStatus) => {
    try {
      await axios.put(`/api/tickets/${ticketId}/status`, { status: newStatus }, config);
      await fetchTickets();
    } catch (err) {
      alert('Failed to update ticket status');
    }
  };

  const handleSendReply = async (ticketId) => {
    const text = replyText[ticketId]?.trim();
    if (!text) return;

    setIsSendingReply(prev => ({ ...prev, [ticketId]: true }));
    try {
      await axios.post(`/api/tickets/${ticketId}/messages`, { message: text }, config);
      setReplyText(prev => ({ ...prev, [ticketId]: '' }));
      await fetchTickets();
    } catch (err) {
      alert('Failed to send reply');
    } finally {
      setIsSendingReply(prev => ({ ...prev, [ticketId]: false }));
    }
  };

  const openTicketsCount = tickets.filter(t => t.status !== 'Resolved' && t.status !== 'Closed').length;

  return (
    <div className="space-y-4">
      {/* Tab Header Card */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 rounded-2xl p-4 sm:p-5 text-white flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-md">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-2xl bg-rose-500/20 border border-rose-500/30 flex items-center justify-center text-rose-400 shrink-0">
            <ShieldAlert size={22} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="font-extrabold text-sm sm:text-base">Order Workflow Issues & Internal Tickets</h4>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-rose-500/30 text-rose-300 border border-rose-400/30 flex items-center gap-1">
                <Lock size={10} /> Internal Only
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-0.5">
              Raise blockers, quality flags, or missing item tickets strictly for Staff & Admins.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button
            onClick={fetchTickets}
            className="p-2 rounded-xl bg-white/10 hover:bg-white/20 text-slate-300 hover:text-white transition"
            title="Refresh Tickets"
          >
            <RefreshCw size={15} />
          </button>
          <button
            onClick={() => setIsModalOpen(true)}
            className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-extrabold flex items-center gap-1.5 shadow-lg shadow-rose-900/30 transition active:scale-95"
          >
            <Plus size={15} /> Raise Workflow Ticket
          </button>
        </div>
      </div>

      {/* Tickets List */}
      {isLoading ? (
        <div className="p-8 text-center text-xs font-bold text-slate-400 bg-white rounded-2xl border border-slate-100">
          Loading internal workflow tickets...
        </div>
      ) : tickets.length === 0 ? (
        <div className="p-8 text-center bg-white rounded-2xl border border-slate-100 space-y-2">
          <div className="w-12 h-12 bg-emerald-50 rounded-2xl flex items-center justify-center text-emerald-600 mx-auto border border-emerald-100">
            <CheckCircle2 size={24} />
          </div>
          <p className="text-xs font-bold text-slate-800">No active workflow issues on this order.</p>
          <p className="text-[11px] text-slate-400">Everything is progressing smoothly. Click "Raise Workflow Ticket" above if an issue arises.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {tickets.map((t) => {
            const isExpanded = expandedTicketId === t._id;
            const isResolved = t.status === 'Resolved' || t.status === 'Closed';

            return (
              <div 
                key={t._id} 
                className={`bg-white rounded-2xl border transition shadow-xs ${
                  isResolved ? 'border-slate-200/80 bg-slate-50/40' : 'border-rose-200/90 shadow-sm'
                }`}
              >
                <div className="p-4 sm:p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono font-black text-xs text-slate-900 bg-slate-100 px-2.5 py-0.5 rounded-lg border border-slate-200">
                        {t.ticketNumber || `TCK-${t._id.slice(-6).toUpperCase()}`}
                      </span>
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider ${
                        t.priority === 'Urgent' ? 'bg-rose-100 text-rose-800 border border-rose-200' :
                        t.priority === 'High' ? 'bg-amber-100 text-amber-800 border border-amber-200' :
                        'bg-blue-100 text-blue-800 border border-blue-200'
                      }`}>
                        {t.priority} Priority
                      </span>
                      <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-purple-50 text-purple-700 border border-purple-200 flex items-center gap-1">
                        <Tag size={10} /> {t.issueType || 'Workflow Blocked'}
                      </span>
                      {t.isInternal && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider bg-slate-100 text-slate-600 border border-slate-200 flex items-center gap-1">
                          <Lock size={10} /> Internal
                        </span>
                      )}
                    </div>

                    <h5 className="font-extrabold text-sm text-slate-900">{t.subject}</h5>
                    <p className="text-xs text-slate-600 leading-relaxed line-clamp-2">{t.description}</p>

                    <div className="flex items-center gap-4 text-[11px] text-slate-400 font-medium pt-1">
                      <span>Raised by: <strong className="text-slate-700">{t.user?.name || 'Staff'}</strong></span>
                      <span>•</span>
                      <span>Assigned: <strong className="text-slate-700">{t.assignedTo?.name || 'Unassigned (Admins Queue)'}</strong></span>
                      <span>•</span>
                      <span>{new Date(t.createdAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}</span>
                    </div>
                  </div>

                  {/* Actions & Status Dropdown */}
                  <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                    <select
                      value={t.status}
                      onChange={(e) => handleStatusChange(t._id, e.target.value)}
                      className={`px-3 py-1.5 rounded-xl text-xs font-bold outline-none border transition ${
                        t.status === 'Resolved' ? 'bg-emerald-50 text-emerald-800 border-emerald-200' :
                        t.status === 'In Progress' ? 'bg-amber-50 text-amber-800 border-amber-200' :
                        t.status === 'Closed' ? 'bg-slate-100 text-slate-700 border-slate-200' :
                        'bg-rose-50 text-rose-800 border-rose-200'
                      }`}
                    >
                      <option value="Open">Open</option>
                      <option value="In Progress">In Progress</option>
                      <option value="Resolved">Resolved</option>
                      <option value="Closed">Closed</option>
                    </select>

                    <button
                      onClick={() => setExpandedTicketId(isExpanded ? null : t._id)}
                      className="px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold flex items-center gap-1 transition"
                    >
                      <MessageSquare size={13} />
                      <span>{(t.messages || []).length} Replies</span>
                      {isExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                    </button>
                  </div>
                </div>

                {/* Expanded Thread & Reply Box */}
                {isExpanded && (
                  <div className="border-t border-slate-100 p-4 sm:p-5 bg-slate-50/50 space-y-3 animate-in fade-in duration-150">
                    <p className="text-[10px] font-black uppercase text-slate-400 tracking-wider">Internal Staff Notes & Thread</p>
                    
                    {/* Initial Description */}
                    <div className="p-3 bg-white rounded-xl border border-slate-200 text-xs text-slate-700">
                      <p className="font-bold text-slate-900 mb-1">{t.user?.name} (Original Note):</p>
                      <p className="whitespace-pre-wrap">{t.description}</p>
                    </div>

                    {/* Messages */}
                    {(t.messages || []).map((m, idx) => (
                      <div key={idx} className="p-3 bg-indigo-50/60 rounded-xl border border-indigo-100 text-xs text-slate-800 space-y-1">
                        <div className="flex items-center justify-between text-[10px] text-indigo-900 font-bold">
                          <span>{m.sender?.name || 'Staff Member'} ({m.sender?.role || 'Staff'})</span>
                          <span className="text-slate-400">{new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                        </div>
                        <p className="whitespace-pre-wrap">{m.message}</p>
                      </div>
                    ))}

                    {/* Reply Input */}
                    <div className="flex gap-2 pt-2">
                      <input
                        type="text"
                        placeholder="Write internal staff response or solution note..."
                        value={replyText[t._id] || ''}
                        onChange={(e) => setReplyText({ ...replyText, [t._id]: e.target.value })}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') handleSendReply(t._id);
                        }}
                        className="flex-1 px-3.5 py-2 bg-white border border-slate-200 rounded-xl text-xs font-medium text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500"
                      />
                      <button
                        onClick={() => handleSendReply(t._id)}
                        disabled={isSendingReply[t._id] || !replyText[t._id]?.trim()}
                        className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-bold transition flex items-center gap-1.5 disabled:opacity-50"
                      >
                        <Send size={13} />
                        {isSendingReply[t._id] ? 'Posting...' : 'Post Reply'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Modal to Create Ticket */}
      <CreateWorkflowTicketModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        order={order}
        token={token}
        employees={employees}
        onTicketCreated={() => fetchTickets()}
      />
    </div>
  );
};

export default OrderWorkflowTicketsTab;
