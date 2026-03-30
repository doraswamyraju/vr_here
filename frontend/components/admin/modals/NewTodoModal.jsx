import React, { useState } from 'react';
import { X, CheckSquare, Users, Calendar, Link, Zap } from 'lucide-react';
import axios from 'axios';

const NewTodoModal = ({ isOpen, onClose, orders, employees, token, onCreated }) => {
  const [loading, setLoading] = useState(false);
  const [taskType, setTaskType] = useState('standalone'); // 'standalone' or 'order'
  
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    status: 'Pending',
    priority: 'Medium',
    assignedTo: '',
    orderId: '',
    dueDate: ''
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!formData.title) {
        alert('Task title is required.');
        return;
    }

    setLoading(true);
    try {
      const config = { headers: { Authorization: `Bearer ${token}` } };
      
      // If linked to order, we can also add it to the Todo collection with orderId
      // This allows the unified Todo view to work efficiently.
      await axios.post('/api/todos', formData, config);
      
      onCreated();
      onClose();
      setFormData({
        title: '',
        description: '',
        status: 'Pending',
        priority: 'Medium',
        assignedTo: '',
        orderId: '',
        dueDate: ''
      });
    } catch (error) {
      alert(error.response?.data?.message || 'Error creating task');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm">
      <div className="bg-white rounded-3xl w-full max-w-lg shadow-2xl border border-slate-200 overflow-hidden flex flex-col">
        <div className="p-6 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
          <div>
            <h2 className="text-2xl font-black text-slate-900">Assign New Task</h2>
            <p className="text-slate-500 text-sm">Direct task assignment to your team.</p>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-200 rounded-full transition-colors">
            <X size={20} className="text-slate-500" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {/* Task Type Switch */}
          <div className="flex bg-slate-100 p-1 rounded-2xl">
            <button 
              type="button"
              onClick={() => { setTaskType('standalone'); setFormData({ ...formData, orderId: '' }); }}
              className={`flex-1 py-2 text-sm font-bold rounded-xl transition-all ${taskType === 'standalone' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-500 hover:text-slate-700'}`}
            >
              Standalone Task
            </button>
            <button 
              type="button"
              onClick={() => setTaskType('order')}
              className={`flex-1 py-2 text-sm font-bold rounded-xl transition-all ${taskType === 'order' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-500 hover:text-slate-700'}`}
            >
              Link to Order
            </button>
          </div>

          <div className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
                <CheckSquare size={12} /> Task Title
              </label>
              <input 
                className="w-full px-4 py-3 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none transition-all"
                placeholder="What needs to be done?"
                value={formData.title}
                onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                required
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
                Task Description
              </label>
              <textarea 
                className="w-full px-4 py-3 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none transition-all min-h-[80px]"
                placeholder="Additional details..."
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              />
            </div>

            {taskType === 'order' && (
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
                  <Link size={12} /> Select Related Order
                </label>
                <select 
                  className="w-full px-4 py-3 rounded-xl border border-slate-200 outline-none bg-slate-50"
                  value={formData.orderId}
                  onChange={(e) => setFormData({ ...formData, orderId: e.target.value })}
                  required={taskType === 'order'}
                >
                  <option value="">-- Choose an active order --</option>
                  {(orders || []).map(order => (
                    <option key={order._id} value={order._id}>
                      {order.serviceName} - {order.clientName}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
                  <Users size={12} /> Assign Employee
                </label>
                <select 
                  className="w-full px-4 py-3 rounded-xl border border-slate-200 outline-none bg-slate-50"
                  value={formData.assignedTo}
                  onChange={(e) => setFormData({ ...formData, assignedTo: e.target.value })}
                >
                  <option value="">Unassigned</option>
                  {(employees || []).map(emp => (
                    <option key={emp._id} value={emp._id}>{emp.name}</option>
                  ))}
                </select>
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
                  <Calendar size={12} /> Due Date
                </label>
                <input 
                  type="date"
                  className="w-full px-4 py-3 rounded-xl border border-slate-200 outline-none bg-slate-50"
                  value={formData.dueDate}
                  onChange={(e) => setFormData({ ...formData, dueDate: e.target.value })}
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Priority</label>
              <div className="flex gap-2">
                {['Low', 'Medium', 'High', 'Urgent'].map(p => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setFormData({ ...formData, priority: p })}
                    className={`flex-1 py-2 text-xs font-black rounded-lg transition-all border ${formData.priority === p ? 'bg-slate-900 border-slate-900 text-white' : 'border-slate-200 text-slate-500 hover:border-slate-300'}`}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </form>

        <div className="p-6 border-t border-slate-100 bg-slate-50/50 flex justify-end gap-3">
          <button 
            type="button"
            onClick={onClose}
            className="px-6 py-2 rounded-xl font-bold text-slate-600 hover:bg-slate-200 transition-colors"
          >
            Cancel
          </button>
          <button 
            type="button"
            onClick={handleSubmit}
            disabled={loading}
            className="px-8 py-2 rounded-xl font-bold bg-indigo-600 text-white shadow-xl shadow-indigo-200 hover:bg-indigo-700 disabled:bg-indigo-400 flex items-center gap-2 transition-all active:scale-95"
          >
            {loading ? 'Creating...' : (
              <>
                <Zap size={16} fill="currentColor" /> Assign Task
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default NewTodoModal;
