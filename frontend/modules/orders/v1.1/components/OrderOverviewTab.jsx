import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  CheckCircle, Clock, FileText, User, 
  Plus, CheckSquare, RefreshCcw, IndianRupee, AlertCircle, Check, Trash2 
} from 'lucide-react';
import { rupees } from '../utils/helpers';

const Metric = ({ label, value, icon: Icon, color = 'indigo' }) => {
  const colors = {
    indigo: 'text-indigo-600 bg-indigo-50 border-indigo-100',
    emerald: 'text-emerald-600 bg-emerald-50 border-emerald-100',
    amber: 'text-amber-600 bg-amber-50 border-amber-100',
    rose: 'text-rose-600 bg-rose-50 border-rose-100'
  };

  return (
    <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm flex items-center justify-between">
      <div>
        <p className="text-[10px] uppercase font-black tracking-widest text-slate-400">{label}</p>
        <p className="text-2xl font-black mt-1 text-slate-900 tracking-tight">{value}</p>
      </div>
      <div className={`p-3 rounded-xl border ${colors[color] || colors.indigo}`}>
        <Icon size={20} />
      </div>
    </div>
  );
};

const OrderOverviewTab = ({ selectedOrder, token }) => {
  const [todos, setTodos] = useState([]);
  const [attendance, setAttendance] = useState([]);
  const [history, setHistory] = useState([]);
  const [newTodoTitle, setNewTodoTitle] = useState('');
  const [isLoadingTodos, setIsLoadingTodos] = useState(false);
  const [isLoadingAttendance, setIsLoadingAttendance] = useState(false);
  const [confirmModal, setConfirmModal] = useState({
    isOpen: false,
    title: '',
    message: '',
    onConfirm: null
  });
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [freelancers, setFreelancers] = useState([]);
  const [isReassigning, setIsReassigning] = useState(false);
  const [selectedFreelancerId, setSelectedFreelancerId] = useState('');

  const [itrAssessment, setItrAssessment] = useState(null);
  const [isLoadingAssessment, setIsLoadingAssessment] = useState(false);
  const [isRaisingInvoice, setIsRaisingInvoice] = useState(false);
  const [balanceInvoiceForm, setBalanceInvoiceForm] = useState({
    amount: '',
    packageName: selectedOrder?.packageName || '',
    notes: 'Balance fees invoice raised by CA review.',
    dueDate: ''
  });
  const [invoiceError, setInvoiceError] = useState('');
  const [invoiceSuccess, setInvoiceSuccess] = useState('');


  const config = React.useMemo(() => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo') || '{}');
    const activeToken = token || userInfo?.token;
    return activeToken ? { headers: { Authorization: `Bearer ${activeToken}` } } : null;
  }, [token]);

  const fetchItrAssessment = async () => {
    if (!config || !selectedOrder?._id) return;
    const isITR = selectedOrder.serviceName?.toLowerCase().includes('income tax') || selectedOrder.packageName?.toLowerCase().includes('itr');
    if (!isITR) {
      setItrAssessment(null);
      return;
    }
    setIsLoadingAssessment(true);
    try {
      const { data } = await axios.get(`/api/income-tax-assessment?orderId=${selectedOrder._id}`, config);
      if (data && data.length > 0) {
        setItrAssessment(data[0]);
      } else {
        setItrAssessment(null);
      }
    } catch (err) {
      console.error('Error fetching ITR assessment:', err.message);
    } finally {
      setIsLoadingAssessment(false);
    }
  };

  const handleRaiseBalanceInvoice = async (e) => {
    e.preventDefault();
    if (!balanceInvoiceForm.amount || !config) return;
    setIsRaisingInvoice(true);
    setInvoiceError('');
    setInvoiceSuccess('');
    try {
      await axios.post(`/api/orders/${selectedOrder._id}/invoices/adjusted`, {
        packageName: balanceInvoiceForm.packageName || selectedOrder.packageName,
        amount: Number(balanceInvoiceForm.amount),
        adjustConsultation: false,
        adjustPreviousAmount: false,
        dueDate: balanceInvoiceForm.dueDate || null,
        notes: balanceInvoiceForm.notes
      }, config);
      setInvoiceSuccess('Balance invoice raised and sent to client successfully!');
      setBalanceInvoiceForm({
        amount: '',
        packageName: selectedOrder?.packageName || '',
        notes: 'Balance fees invoice raised by CA review.',
        dueDate: ''
      });
      if (typeof window.location.reload === 'function') {
        setTimeout(() => window.location.reload(), 1500);
      }
    } catch (err) {
      setInvoiceError(err.response?.data?.message || 'Failed to raise balance invoice');
    } finally {
      setIsRaisingInvoice(false);
    }
  };

  const fetchTodos = async () => {
    if (!config || !selectedOrder?._id) return;
    setIsLoadingTodos(true);
    try {
      const { data } = await axios.get(`/api/todos?orderId=${selectedOrder._id}`, config);
      setTodos(data || []);
    } catch (err) {
      console.error('Error fetching todos:', err.message);
    } finally {
      setIsLoadingTodos(false);
    }
  };

  const fetchAttendance = async () => {
    if (!config || !selectedOrder?._id) return;
    setIsLoadingAttendance(true);
    try {
      const { data } = await axios.get(`/api/orders/${selectedOrder._id}/attendance`, config);
      setAttendance(data || []);
    } catch (err) {
      console.error('Error fetching attendance:', err.message);
    } finally {
      setIsLoadingAttendance(false);
    }
  };

  const fetchHistory = async () => {
    if (!config || !selectedOrder?._id) return;
    setIsLoadingHistory(true);
    try {
      const { data } = await axios.get(`/api/orders/${selectedOrder._id}/history`, config);
      setHistory(data || []);
    } catch (err) {
      console.error('Error fetching history:', err.message);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const handleCreateTodo = async (e) => {
    e.preventDefault();
    if (!newTodoTitle.trim() || !config) return;
    try {
      await axios.post('/api/todos', {
        title: newTodoTitle.trim(),
        orderId: selectedOrder._id,
        priority: 'Medium'
      }, config);
      setNewTodoTitle('');
      fetchTodos();
    } catch (err) {
      console.error('Error creating todo:', err.message);
    }
  };

  const handleToggleTodo = async (todo) => {
    if (!config) return;
    const newStatus = todo.status === 'Completed' ? 'Pending' : 'Completed';
    try {
      await axios.put(`/api/todos/${todo._id}`, { status: newStatus }, config);
      fetchTodos();
    } catch (err) {
      console.error('Error toggling todo:', err.message);
    }
  };

  const fetchFreelancers = async () => {
    if (!config) return;
    try {
      const { data } = await axios.get('/api/freelancer/admin/users', config);
      setFreelancers(data.filter(f => f.isActive) || []);
    } catch (err) {
      console.error('Error fetching freelancers:', err.message);
    }
  };

  useEffect(() => {
    fetchTodos();
    fetchAttendance();
    fetchHistory();
    fetchFreelancers();
    fetchItrAssessment();
  }, [selectedOrder?._id, config]);

  return (
    <div className="space-y-6">
      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Metric label="Tasks" value={selectedOrder.tasks?.length || 0} icon={CheckSquare} color="indigo" />
        <Metric label="Requirements" value={selectedOrder.customerRequirements?.length || 0} icon={FileText} color="amber" />
        <Metric label="Invoices Raised" value={selectedOrder.invoices?.length || 0} icon={IndianRupee} color="emerald" />
        <Metric label="Service Budget" value={rupees(selectedOrder.price)} icon={Clock} color="rose" />
      </div>

      {/* Main Multi-Column Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Live ToDo & Attendance */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Freelancer Assignment / Broadcast Panel */}
          <div className="rounded-2xl border border-slate-200/60 bg-white p-5 shadow-sm space-y-4">
            <h4 className="font-black text-slate-900 uppercase tracking-tight text-sm flex items-center gap-2 border-b border-slate-50 pb-2">
              <IndianRupee size={16} className="text-indigo-600" /> Freelancer Assignment & Payout
            </h4>

            {!selectedOrder.assignedFreelancer ? (
              <div className="space-y-4">
                <div className="space-y-3">
                  <p className="text-[10px] text-slate-400 uppercase font-black tracking-widest border-b border-slate-50 pb-1">Option A: Broadcast to pool</p>
                  <p className="text-xs text-slate-500 font-medium">Broadcast this order to the freelancer pool. The first freelancer to accept will claim the project.</p>
                  <div className="flex flex-col sm:flex-row gap-3">
                    <div className="relative flex-grow">
                      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-xs font-bold text-slate-400">Payout (₹)</span>
                      <input 
                        type="number" 
                        placeholder="Define payout amount"
                        id="freelancerPayoutInput"
                        className="w-full pl-20 pr-4 py-2.5 border border-slate-200 rounded-xl text-xs font-bold focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none"
                      />
                    </div>
                    <button 
                      onClick={async () => {
                        const amount = Number(document.getElementById('freelancerPayoutInput')?.value || 0);
                        if (!amount || amount <= 0) return alert('Please input a valid payout amount');
                        try {
                          await axios.put(`/api/freelancer/admin/broadcast/${selectedOrder._id}`, { payoutAmount: amount }, config);
                          alert('Order broadcasted successfully!');
                          window.location.reload();
                        } catch (err) {
                          alert(err.response?.data?.message || 'Failed to broadcast order');
                        }
                      }}
                      className="px-6 py-2.5 bg-slate-900 text-white rounded-xl text-xs font-black hover:bg-slate-800 transition active:scale-[0.98]"
                    >
                      Broadcast Order
                    </button>
                  </div>
                </div>

                <div className="border-t border-slate-100 pt-3 space-y-3">
                  <p className="text-[10px] text-slate-400 uppercase font-black tracking-widest border-b border-slate-50 pb-1">Option B: Direct Assignment</p>
                  <p className="text-xs text-slate-500 font-medium">Select an approved freelancer to assign directly to this order.</p>
                  <div className="flex flex-col sm:flex-row gap-3">
                    <select
                      value={selectedFreelancerId}
                      onChange={(e) => setSelectedFreelancerId(e.target.value)}
                      className="flex-grow px-4 py-2.5 border border-slate-200 rounded-xl text-xs font-bold focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none bg-white"
                    >
                      <option value="">Select Freelancer...</option>
                      {freelancers.map(f => (
                        <option key={f._id} value={f._id}>{f.name} ({f.phone || f.email})</option>
                      ))}
                    </select>
                    
                    <div className="relative w-40">
                      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-xs font-bold text-slate-400">Payout</span>
                      <input 
                        type="number" 
                        placeholder="Payout"
                        id="directPayoutInput"
                        className="w-full pl-14 pr-4 py-2.5 border border-slate-200 rounded-xl text-xs font-bold focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none"
                      />
                    </div>

                    <button 
                      onClick={async () => {
                        if (!selectedFreelancerId) return alert('Please select a freelancer');
                        const amount = Number(document.getElementById('directPayoutInput')?.value || 0);
                        if (!amount || amount <= 0) return alert('Please input a valid payout amount');
                        try {
                          await axios.put(`/api/freelancer/admin/broadcast/${selectedOrder._id}`, { payoutAmount: amount }, config);
                          await axios.post(`/api/freelancer/admin/reassign/${selectedOrder._id}`, { freelancerId: selectedFreelancerId }, config);
                          alert('Freelancer assigned successfully!');
                          window.location.reload();
                        } catch (err) {
                          alert(err.response?.data?.message || 'Failed to assign freelancer');
                        }
                      }}
                      className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-black transition active:scale-[0.98]"
                    >
                      Assign Freelancer
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="space-y-3 text-xs font-semibold text-slate-600">
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-slate-50 p-3 rounded-xl border border-slate-100">
                    <p className="text-[10px] text-slate-400 uppercase font-black tracking-widest">Assigned Freelancer</p>
                    <p className="text-slate-900 font-black mt-1 text-sm">{selectedOrder.assignedFreelancer.name || 'Assigned'}</p>
                    <p className="text-slate-500 text-[10px] mt-0.5">{selectedOrder.assignedFreelancer.phone}</p>
                  </div>
                  <div className="bg-slate-50 p-3 rounded-xl border border-slate-100">
                    <p className="text-[10px] text-slate-400 uppercase font-black tracking-widest">Defined Payout</p>
                    <p className="text-slate-900 font-black mt-1 text-sm">₹{selectedOrder.freelancerPayout}</p>
                    <span className="bg-green-100 text-green-700 px-1.5 py-0.5 rounded-full text-[8px] font-black uppercase tracking-wider mt-1 inline-block">Claimed</span>
                  </div>
                </div>

                <div className="bg-slate-50 p-3 rounded-xl border border-slate-100 flex items-center justify-between">
                  <div>
                    <p className="text-[10px] text-slate-400 uppercase font-black tracking-widest">Accumulated Work Effort</p>
                    <p className="text-slate-900 font-black mt-1 text-sm">
                      {selectedOrder.freelancerTimeLogs?.reduce((sum, log) => sum + log.minutes, 0) || 0} Minutes
                    </p>
                  </div>
                  {selectedOrder.assignedFreelancer.isClockedIn ? (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 bg-red-50 text-red-600 rounded-full text-[9px] font-black uppercase tracking-widest animate-pulse">
                      <span className="w-1.5 h-1.5 bg-red-600 rounded-full"></span> Live Working
                    </span>
                  ) : (
                    <span className="text-slate-400 text-[10px]">Inactive</span>
                  )}
                </div>

                {isReassigning && (
                  <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-100 space-y-3">
                    <p className="text-[10px] text-slate-400 uppercase font-black tracking-widest">Reassign Freelancer</p>
                    <div className="flex flex-col sm:flex-row gap-3">
                      <select
                        value={selectedFreelancerId}
                        onChange={(e) => setSelectedFreelancerId(e.target.value)}
                        className="flex-grow px-4 py-2 border border-slate-200 rounded-xl text-xs font-bold focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none bg-white"
                      >
                        <option value="">Select Freelancer...</option>
                        {freelancers.map(f => (
                          <option key={f._id} value={f._id}>{f.name} ({f.phone || f.email})</option>
                        ))}
                      </select>
                      <div className="flex gap-2">
                        <button
                          onClick={async () => {
                            if (!selectedFreelancerId) return alert('Please select a freelancer');
                            if (!window.confirm('Are you sure you want to reassign this order to the selected freelancer?')) return;
                            try {
                              await axios.post(`/api/freelancer/admin/reassign/${selectedOrder._id}`, { freelancerId: selectedFreelancerId }, config);
                              alert('Freelancer reassigned successfully!');
                              window.location.reload();
                            } catch (err) {
                              alert(err.response?.data?.message || 'Failed to reassign freelancer');
                            }
                          }}
                          className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-black transition active:scale-[0.98]"
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => { setIsReassigning(false); setSelectedFreelancerId(''); }}
                          className="px-3 py-2 border border-slate-200 hover:bg-slate-150 text-slate-600 rounded-xl text-xs font-black transition"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex flex-col sm:flex-row gap-2">
                  <button 
                    onClick={() => {
                      setConfirmModal({
                        isOpen: true,
                        title: 'Approve Payout',
                        message: 'Are you sure you want to approve this work and authorize payout?',
                        onConfirm: async () => {
                          try {
                            await axios.post(`/api/freelancer/admin/approve-payout/${selectedOrder._id}`, {}, config);
                            alert('Work effort verified and payout approved successfully!');
                            window.location.reload();
                          } catch (err) {
                            alert(err.response?.data?.message || 'Failed to approve payout');
                          }
                        }
                      });
                    }}
                    className="flex-grow h-11 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-black transition flex items-center justify-center gap-2"
                  >
                    <Check size={14} /> Approve Work & Settle Payout
                  </button>

                  {!isReassigning && (
                    <button 
                      onClick={() => setIsReassigning(true)}
                      className="px-4 h-11 border border-slate-200 hover:bg-slate-50 text-slate-700 rounded-xl text-xs font-black transition flex items-center justify-center gap-1.5"
                    >
                      Reassign
                    </button>
                  )}

                  <button 
                    onClick={() => {
                      setConfirmModal({
                        isOpen: true,
                        title: 'Remove Assignment',
                        message: 'Are you sure you want to remove the assigned freelancer? This will return the order to the broadcast pool.',
                        onConfirm: async () => {
                          try {
                            await axios.post(`/api/freelancer/admin/reassign/${selectedOrder._id}`, { freelancerId: null }, config);
                            alert('Freelancer assignment removed successfully!');
                            window.location.reload();
                          } catch (err) {
                            alert(err.response?.data?.message || 'Failed to remove freelancer');
                          }
                        }
                      });
                    }}
                    className="px-4 h-11 border border-rose-250 hover:bg-rose-50 text-rose-600 rounded-xl text-xs font-black transition flex items-center justify-center gap-1.5"
                  >
                    <Trash2 size={14} /> Remove Assignment
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* ToDo List Card */}
          <div className="rounded-2xl border border-slate-200/60 bg-white p-5 shadow-sm">
            <h4 className="font-black text-slate-900 uppercase tracking-tight text-sm mb-4 flex items-center gap-2">
              <CheckCircle size={16} className="text-indigo-600" /> To-Dos Checklist
            </h4>
            
            <form onSubmit={handleCreateTodo} className="flex gap-2 mb-4">
              <input 
                type="text" 
                placeholder="Add new order-specific task..."
                value={newTodoTitle}
                onChange={e => setNewTodoTitle(e.target.value)}
                className="flex-1 p-2.5 border border-slate-200 rounded-xl text-sm focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none"
              />
              <button type="submit" className="p-2.5 rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 active:scale-95 transition-transform flex items-center justify-center">
                <Plus size={18} />
              </button>
            </form>

            <div className="space-y-2 max-h-60 overflow-y-auto">
              {todos.map(todo => (
                <div 
                  key={todo._id} 
                  onClick={() => handleToggleTodo(todo)}
                  className="flex items-center gap-3 p-3 rounded-xl border border-slate-100 hover:border-slate-200 bg-slate-50/30 cursor-pointer transition-colors group"
                >
                  <div className={`w-5 h-5 rounded-md border flex items-center justify-center transition-colors ${
                    todo.status === 'Completed' ? 'bg-indigo-600 border-indigo-600 text-white' : 'border-slate-300 bg-white group-hover:border-indigo-500'
                  }`}>
                    {todo.status === 'Completed' && <CheckSquare size={14} />}
                  </div>
                  <span className={`text-xs font-bold ${
                    todo.status === 'Completed' ? 'line-through text-slate-400' : 'text-slate-700'
                  }`}>
                    {todo.title}
                  </span>
                </div>
              ))}
              {todos.length === 0 && (
                <p className="text-center text-xs text-slate-400 italic py-4">No task listed. Add one above!</p>
              )}
            </div>
          </div>

          {/* Assigned Staff Attendance Card */}
          <div className="rounded-2xl border border-slate-200/60 bg-white p-5 shadow-sm">
            <h4 className="font-black text-slate-900 uppercase tracking-tight text-sm mb-4 flex items-center gap-2">
              <User size={16} className="text-indigo-600" /> Active Staff Sessions
            </h4>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {attendance.map(staff => (
                <div key={staff._id} className="p-3 rounded-xl border border-slate-100 bg-slate-50/50 flex items-center justify-between">
                  <div>
                    <p className="text-xs font-black text-slate-800">{staff.name}</p>
                    <p className="text-[9px] font-medium text-slate-400 uppercase tracking-wider">{staff.role}</p>
                  </div>
                  <span className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase flex items-center gap-1 ${
                    staff.isClockedIn 
                      ? 'bg-emerald-100 text-emerald-700 shadow-sm shadow-emerald-100' 
                      : 'bg-slate-100 text-slate-500'
                  }`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${staff.isClockedIn ? 'bg-emerald-500 animate-ping' : 'bg-slate-400'}`} />
                    {staff.isClockedIn ? 'Clocked In' : 'Offline'}
                  </span>
                </div>
              ))}
              {attendance.length === 0 && (
                <p className="col-span-full text-center text-xs text-slate-400 italic py-4">No staff members currently assigned.</p>
              )}
            </div>
          </div>

          {/* ITR Assessment Checklist Details & Raise Balance Invoice */}
          {itrAssessment && (
            <div className="rounded-2xl border border-slate-200/60 bg-white p-5 shadow-sm space-y-6">
              <div className="flex items-center justify-between border-b pb-3">
                <h4 className="font-black text-slate-900 uppercase tracking-tight text-sm flex items-center gap-2">
                  <FileText size={16} className="text-indigo-600" /> Client ITR Checklist Response
                </h4>
                <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider ${
                  itrAssessment.status === 'Approved' ? 'bg-green-50 text-green-700' : 'bg-amber-50 text-amber-700'
                }`}>
                  {itrAssessment.status}
                </span>
              </div>

              <div className="space-y-4 max-h-[300px] overflow-y-auto pr-1 text-xs">
                <div>
                  <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Client PAN</p>
                  <p className="font-black text-slate-800 text-sm mt-0.5 uppercase">{itrAssessment.pan}</p>
                </div>

                <div className="space-y-3.5 border-t pt-3.5">
                  <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Checked Items & Attachments</p>
                  {itrAssessment.responses?.filter(r => r.value === 'Yes').map((r, idx) => (
                    <div key={idx} className="p-3 bg-slate-50 border rounded-xl space-y-2">
                      <div className="flex justify-between items-start">
                        <span className="font-bold text-slate-800 leading-snug">{r.description}</span>
                        <span className="bg-emerald-50 text-emerald-700 border border-emerald-100 px-1.5 py-0.5 rounded text-[8px] font-black uppercase">Yes</span>
                      </div>
                      {r.remarks && <p className="text-[10px] text-slate-500 italic mt-1">Remarks: {r.remarks}</p>}
                      
                      {/* Render attachments */}
                      {((r.documents && r.documents.length > 0) || r.documentUrl) && (
                        <div className="flex flex-wrap gap-1.5 pt-1.5">
                          {r.documents?.map((doc, dIdx) => (
                            <a 
                              key={dIdx}
                              href={doc.documentUrl} 
                              target="_blank" 
                              rel="noreferrer" 
                              className="inline-flex items-center gap-1 bg-white border border-slate-200 hover:border-indigo-300 hover:text-indigo-700 px-2 py-1 rounded-lg text-[9px] font-bold text-slate-650 transition"
                            >
                              <FileText size={10} />
                              <span className="truncate max-w-[100px]">{doc.originalFileName}</span>
                            </a>
                          ))}
                          {r.documentUrl && !r.documents?.length && (
                            <a 
                              href={r.documentUrl} 
                              target="_blank" 
                              rel="noreferrer" 
                              className="inline-flex items-center gap-1 bg-white border border-slate-200 hover:border-indigo-300 hover:text-indigo-700 px-2 py-1 rounded-lg text-[9px] font-bold text-slate-650 transition"
                            >
                              <FileText size={10} />
                              <span className="truncate max-w-[100px]">{r.originalFileName || 'Legacy attachment'}</span>
                            </a>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                  {itrAssessment.responses?.filter(r => r.value === 'Yes').length === 0 && (
                    <p className="text-slate-400 italic text-[11px]">No items marked as 'Yes' in this checklist.</p>
                  )}
                </div>
              </div>

              {/* Raise Balance Invoice Block */}
              <div className="border-t pt-5 space-y-4">
                <h5 className="font-black text-slate-900 uppercase tracking-tight text-xs flex items-center gap-2">
                  <IndianRupee size={14} className="text-emerald-600" /> Raise Balance/Remaining Fees Invoice
                </h5>

                {invoiceError && (
                  <div className="p-3 bg-rose-50 text-rose-700 text-[10px] font-bold rounded-lg">{invoiceError}</div>
                )}
                {invoiceSuccess && (
                  <div className="p-3 bg-green-50 text-green-700 text-[10px] font-bold rounded-lg">{invoiceSuccess}</div>
                )}

                <form onSubmit={handleRaiseBalanceInvoice} className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-[9px] text-slate-400 uppercase font-black tracking-widest block mb-1">Balance Amount (INR)</label>
                      <input 
                        type="number" 
                        required
                        placeholder="2500" 
                        value={balanceInvoiceForm.amount}
                        onChange={e => setBalanceInvoiceForm(prev => ({ ...prev, amount: e.target.value }))}
                        className="w-full p-2.5 border rounded-xl text-xs font-bold outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="text-[9px] text-slate-400 uppercase font-black tracking-widest block mb-1">Due Date</label>
                      <input 
                        type="date" 
                        value={balanceInvoiceForm.dueDate}
                        onChange={e => setBalanceInvoiceForm(prev => ({ ...prev, dueDate: e.target.value }))}
                        className="w-full p-2.5 border rounded-xl text-xs font-bold outline-none focus:border-indigo-500"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="text-[9px] text-slate-400 uppercase font-black tracking-widest block mb-1">Invoice Notes</label>
                    <textarea 
                      placeholder="Specify billing description..." 
                      value={balanceInvoiceForm.notes}
                      onChange={e => setBalanceInvoiceForm(prev => ({ ...prev, notes: e.target.value }))}
                      rows={2}
                      className="w-full p-2.5 border rounded-xl text-xs font-medium outline-none focus:border-indigo-500 resize-none"
                    />
                  </div>
                  <button 
                    type="submit" 
                    disabled={isRaisingInvoice}
                    className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-black uppercase tracking-wider transition-all disabled:opacity-50"
                  >
                    {isRaisingInvoice ? 'Generating Invoice...' : 'Generate & Email Balance Invoice'}
                  </button>
                </form>
              </div>
            </div>
          )}

        </div>

        {/* Right Column: History Timeline Log */}
        <div className="space-y-6">
          <div className="rounded-2xl border border-slate-200/60 bg-white p-5 shadow-sm">
            <h4 className="font-black text-slate-900 uppercase tracking-tight text-sm mb-4 flex items-center gap-2">
              <Clock size={16} className="text-indigo-600" /> Project Milestones
            </h4>

            <div className="relative pl-4 border-l border-slate-100 space-y-4 max-h-[360px] overflow-y-auto pr-1">
              {history.map((log, idx) => (
                <div key={log._id} className="relative group">
                  <div className="absolute -left-[21px] top-1.5 w-2 h-2 rounded-full border-2 border-white bg-indigo-500 group-hover:scale-125 transition-transform" />
                  <p className="text-[10px] font-black text-indigo-600 uppercase tracking-wider">{log.action}</p>
                  <p className="text-xs font-bold text-slate-700 mt-0.5">{log.description}</p>
                  <p className="text-[9px] text-slate-400 mt-0.5">{new Date(log.createdAt).toLocaleString()}</p>
                </div>
              ))}
              {history.length === 0 && (
                <p className="text-center text-xs text-slate-400 italic py-8">No milestones recorded yet.</p>
              )}
            </div>
          </div>
        </div>

      </div>

      {confirmModal.isOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-slate-900/40 backdrop-blur-sm animate-fade-in">
          <div className="bg-white rounded-[32px] p-6 max-w-sm w-full shadow-2xl border border-slate-100 space-y-4">
            <h3 className="text-lg font-black text-slate-900">{confirmModal.title}</h3>
            <p className="text-xs text-slate-550 font-semibold leading-relaxed text-slate-600">{confirmModal.message}</p>
            <div className="flex gap-3 pt-2">
              <button
                onClick={() => setConfirmModal({ ...confirmModal, isOpen: false })}
                className="flex-1 py-2.5 bg-slate-105 hover:bg-slate-200 text-slate-600 font-bold rounded-xl text-xs transition"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  const onConfirm = confirmModal.onConfirm;
                  setConfirmModal({ ...confirmModal, isOpen: false });
                  if (onConfirm) {
                    await onConfirm();
                  }
                }}
                className="flex-1 py-2.5 bg-slate-900 hover:bg-slate-800 text-white font-bold rounded-xl text-xs transition"
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default OrderOverviewTab;
