import React, { useState, useEffect } from 'react';
import { X, Calendar, Building2, User, FileText, CheckCircle2, Clock, Trash2 } from 'lucide-react';
import axios from 'axios';

const CATEGORIES = ['GST', 'MCA', 'DIN KYC', 'TDS/TCS', 'Income Tax', 'Adv Tax', 'ESI', 'PF', 'PT', 'Notices'];
const MONTHS = ['APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC', 'JAN', 'FEB', 'MAR'];

const ComplianceTaskModal = ({ 
  isOpen, 
  onClose, 
  onSuccess, 
  token, 
  taskToEdit = null,
  employees = [],
  clients = []
}) => {
  const [formData, setFormData] = useState({
    clientName: '',
    category: 'GST',
    taskName: '',
    dueDate: new Date().toISOString().split('T')[0],
    periodMonth: 'AUG',
    periodYear: String(new Date().getFullYear()),
    status: 'Pending',
    notes: '',
    assignedTo: '',
    sendBroadcast: true
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (taskToEdit) {
      setFormData({
        clientName: taskToEdit.clientName || '',
        category: taskToEdit.category || 'GST',
        taskName: taskToEdit.taskName || '',
        dueDate: taskToEdit.dueDate ? new Date(taskToEdit.dueDate).toISOString().split('T')[0] : new Date().toISOString().split('T')[0],
        periodMonth: taskToEdit.periodMonth || 'AUG',
        periodYear: taskToEdit.periodYear || String(new Date().getFullYear()),
        status: taskToEdit.status || 'Pending',
        notes: taskToEdit.notes || '',
        assignedTo: taskToEdit.assignedTo?._id || taskToEdit.assignedTo || '',
        sendBroadcast: false
      });
    } else {
      setFormData({
        clientName: '',
        category: 'GST',
        taskName: '',
        dueDate: new Date().toISOString().split('T')[0],
        periodMonth: 'AUG',
        periodYear: String(new Date().getFullYear()),
        status: 'Pending',
        notes: '',
        assignedTo: '',
        sendBroadcast: true
      });
    }
    setError('');
  }, [taskToEdit, isOpen]);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!formData.taskName.trim() || !formData.dueDate) {
      return setError('Task Name and Statutory Due Date are required.');
    }

    setLoading(true);
    setError('');
    const config = { headers: { Authorization: `Bearer ${token}` } };

    try {
      if (taskToEdit?._id) {
        await axios.put(`/api/compliance/${taskToEdit._id}`, formData, config);
      } else {
        await axios.post('/api/compliance', formData, config);
      }
      onSuccess();
      onClose();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to save compliance task');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!taskToEdit?._id) return;
    if (!window.confirm('Are you sure you want to delete this compliance record?')) return;

    setLoading(true);
    const config = { headers: { Authorization: `Bearer ${token}` } };
    try {
      await axios.delete(`/api/compliance/${taskToEdit._id}`, config);
      onSuccess();
      onClose();
    } catch (err) {
      setError('Failed to delete record');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-white rounded-3xl max-w-xl w-full p-6 shadow-2xl border border-slate-100 animate-in zoom-in-95 duration-200">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-100 mb-6">
          <div>
            <h3 className="text-lg font-black text-slate-900 tracking-tight flex items-center gap-2">
              <Calendar className="text-indigo-600" size={20} />
              {taskToEdit ? 'Edit Compliance Deadline' : 'New Compliance Deadline'}
            </h3>
            <p className="text-xs text-slate-500 font-medium mt-0.5">Enter statutory dates and assigned team details</p>
          </div>
          <button 
            onClick={onClose} 
            className="p-2 rounded-xl text-slate-400 hover:text-slate-600 hover:bg-slate-50 transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-xl bg-rose-50 border border-rose-100 text-rose-600 text-xs font-bold">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Client Name Input / Selection */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block text-xs font-black uppercase tracking-wider text-slate-600">
                Client / Company Name
              </label>
              <span className="text-[10px] text-indigo-600 font-bold">Optional (Leave blank for All Active Clients)</span>
            </div>
            <input 
              type="text"
              list="client-suggestions"
              value={formData.clientName}
              onChange={(e) => setFormData({ ...formData, clientName: e.target.value })}
              placeholder="Leave blank for ALL clients (e.g. All Active Clients)"
              className="w-full px-4 py-3 rounded-xl border border-slate-200 text-sm font-bold focus:border-indigo-500 outline-none transition-all"
            />
            {clients.length > 0 && (
              <datalist id="client-suggestions">
                <option value="All Active Clients" />
                {clients.map((c, i) => (
                  <option key={i} value={typeof c === 'string' ? c : c.name || c.clientName} />
                ))}
              </datalist>
            )}
          </div>

          {!taskToEdit && (
            <div className="p-3 rounded-xl bg-indigo-50/60 border border-indigo-100 flex items-start gap-2.5">
              <input
                type="checkbox"
                id="sendBroadcast"
                checked={formData.sendBroadcast}
                onChange={(e) => setFormData({ ...formData, sendBroadcast: e.target.checked })}
                className="mt-0.5 w-4 h-4 text-indigo-600 rounded focus:ring-indigo-500 accent-indigo-600 cursor-pointer"
              />
              <label htmlFor="sendBroadcast" className="text-xs font-bold text-slate-700 cursor-pointer leading-tight">
                Broadcast Deadline Alert <span className="text-indigo-600">(In-App + FCM Push Notification + Email)</span> to all clients in this category.
              </label>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Category */}
            <div>
              <label className="block text-xs font-black uppercase tracking-wider text-slate-600 mb-1">
                Category *
              </label>
              <select
                value={formData.category}
                onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                className="w-full px-4 py-3 rounded-xl border border-slate-200 text-sm font-bold focus:border-indigo-500 outline-none bg-white transition-all"
              >
                {CATEGORIES.map(cat => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>
            </div>

            {/* Task / Compliance Title */}
            <div>
              <label className="block text-xs font-black uppercase tracking-wider text-slate-600 mb-1">
                Filing / Task Name *
              </label>
              <input 
                type="text"
                value={formData.taskName}
                onChange={(e) => setFormData({ ...formData, taskName: e.target.value })}
                placeholder="e.g. GSTR-3B Monthly Return"
                className="w-full px-4 py-3 rounded-xl border border-slate-200 text-sm font-bold focus:border-indigo-500 outline-none transition-all"
                required
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {/* Statutory Due Date */}
            <div>
              <label className="block text-xs font-black uppercase tracking-wider text-slate-600 mb-1">
                Due Date *
              </label>
              <input 
                type="date"
                value={formData.dueDate}
                onChange={(e) => setFormData({ ...formData, dueDate: e.target.value })}
                className="w-full px-3 py-3 rounded-xl border border-slate-200 text-sm font-bold focus:border-indigo-500 outline-none transition-all"
                required
              />
            </div>

            {/* Month Period */}
            <div>
              <label className="block text-xs font-black uppercase tracking-wider text-slate-600 mb-1">
                Period Month
              </label>
              <select
                value={formData.periodMonth}
                onChange={(e) => setFormData({ ...formData, periodMonth: e.target.value })}
                className="w-full px-3 py-3 rounded-xl border border-slate-200 text-sm font-bold focus:border-indigo-500 outline-none bg-white transition-all"
              >
                {MONTHS.map(m => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
            </div>

            {/* Year Period */}
            <div>
              <label className="block text-xs font-black uppercase tracking-wider text-slate-600 mb-1">
                Period Year
              </label>
              <input 
                type="text"
                value={formData.periodYear}
                onChange={(e) => setFormData({ ...formData, periodYear: e.target.value })}
                placeholder="2026"
                className="w-full px-3 py-3 rounded-xl border border-slate-200 text-sm font-bold focus:border-indigo-500 outline-none transition-all"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Status */}
            <div>
              <label className="block text-xs font-black uppercase tracking-wider text-slate-600 mb-1">
                Filing Status
              </label>
              <select
                value={formData.status}
                onChange={(e) => setFormData({ ...formData, status: e.target.value })}
                className="w-full px-4 py-3 rounded-xl border border-slate-200 text-sm font-bold focus:border-indigo-500 outline-none bg-white transition-all"
              >
                <option value="Pending">Pending</option>
                <option value="Filed">Filed (Completed)</option>
                <option value="Late">Late (Penalty Applied)</option>
                <option value="Missed">Missed / Expired</option>
              </select>
            </div>

            {/* Recurring Schedule */}
            <div>
              <label className="block text-xs font-black uppercase tracking-wider text-slate-600 mb-1">
                Repeat Schedule
              </label>
              <select
                value={formData.repeatFrequency || 'None'}
                onChange={(e) => setFormData({ 
                  ...formData, 
                  repeatFrequency: e.target.value,
                  isRecurring: e.target.value !== 'None',
                  generateFullYear: e.target.value === 'Monthly' || e.target.value === 'Quarterly'
                })}
                className="w-full px-4 py-3 rounded-xl border border-slate-200 text-sm font-bold focus:border-indigo-500 outline-none bg-white transition-all"
              >
                <option value="None">One-Time Only</option>
                <option value="Monthly">Monthly (e.g. 11th of Every Month)</option>
                <option value="Quarterly">Quarterly (Every 3 Months)</option>
              </select>
            </div>
          </div>

          {!taskToEdit && (formData.repeatFrequency === 'Monthly' || formData.repeatFrequency === 'Quarterly') && (
            <div className="p-3 rounded-xl bg-purple-50/70 border border-purple-100 flex items-start gap-2.5">
              <input
                type="checkbox"
                id="generateFullYear"
                checked={formData.generateFullYear}
                onChange={(e) => setFormData({ ...formData, generateFullYear: e.target.checked })}
                className="mt-0.5 w-4 h-4 text-purple-600 rounded focus:ring-purple-500 accent-purple-600 cursor-pointer"
              />
              <label htmlFor="generateFullYear" className="text-xs font-bold text-slate-700 cursor-pointer leading-tight">
                Auto-Generate Recurring Schedule for <span className="text-purple-700">All 12 Months of FY {formData.periodYear}-{Number(formData.periodYear) + 1}</span>
              </label>
            </div>
          )}

          {/* Notes */}
          <div>
            <label className="block text-xs font-black uppercase tracking-wider text-slate-600 mb-1">
              Filing Notes / Reference ARN
            </label>
            <textarea
              rows="2"
              value={formData.notes}
              onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
              placeholder="e.g. Challan paid via HDFC netbanking. ARN: AA24082600123"
              className="w-full px-4 py-3 rounded-xl border border-slate-200 text-sm font-medium focus:border-indigo-500 outline-none transition-all"
            />
          </div>

          {/* Action buttons */}
          <div className="flex items-center justify-between pt-4 border-t border-slate-100 mt-6">
            {taskToEdit?._id ? (
              <button
                type="button"
                onClick={handleDelete}
                disabled={loading}
                className="px-4 py-2.5 bg-rose-50 text-rose-600 hover:bg-rose-100 rounded-xl font-bold text-xs flex items-center gap-1.5 transition-colors"
              >
                <Trash2 size={15} /> Delete Task
              </button>
            ) : <div />}

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={onClose}
                className="px-5 py-2.5 text-slate-600 font-bold text-xs hover:bg-slate-100 rounded-xl transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white font-black text-xs uppercase tracking-wider rounded-xl shadow-lg shadow-indigo-200 transition-all active:scale-95 disabled:opacity-50"
              >
                {loading ? 'Saving...' : (taskToEdit ? 'Save Changes' : 'Create Task')}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ComplianceTaskModal;
