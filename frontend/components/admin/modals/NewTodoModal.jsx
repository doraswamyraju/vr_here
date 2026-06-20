import React, { useState } from 'react';
import { X, CheckSquare, User as UsersIcon, Calendar, Link, Zap } from 'lucide-react';
import axios from 'axios';

const NewTodoModal = ({ isOpen, onClose, orders, employees, freelancers = [], token, onCreated, todoToEdit = null }) => {
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

  const [searchTermEmployee, setSearchTermEmployee] = useState('');
  const [showEmployeeResults, setShowEmployeeResults] = useState(false);
  const [searchTermFreelancer, setSearchTermFreelancer] = useState('');
  const [showFreelancerResults, setShowFreelancerResults] = useState(false);

  React.useEffect(() => {
    if (todoToEdit) {
      const assignedId = todoToEdit.assignedTo?._id || todoToEdit.assignedTo || '';
      const emp = (employees || []).find(e => e._id === assignedId);
      const free = (freelancers || []).find(f => f._id === assignedId);

      setFormData({
        title: todoToEdit.title || '',
        description: todoToEdit.description || '',
        status: todoToEdit.status || 'Pending',
        priority: todoToEdit.priority || 'Medium',
        assignedTo: assignedId,
        orderId: todoToEdit.orderId?._id || todoToEdit.orderId || '',
        dueDate: todoToEdit.dueDate ? new Date(todoToEdit.dueDate).toISOString().split('T')[0] : ''
      });
      setTaskType(todoToEdit.orderId ? 'order' : 'standalone');
      setSearchTermEmployee(emp ? emp.name : '');
      setSearchTermFreelancer(free ? free.name : '');
    } else {
      setFormData({
        title: '',
        description: '',
        status: 'Pending',
        priority: 'Medium',
        assignedTo: '',
        orderId: '',
        dueDate: ''
      });
      setTaskType('standalone');
      setSearchTermEmployee('');
      setSearchTermFreelancer('');
    }
  }, [todoToEdit, isOpen, employees, freelancers]);

  const [searchTermOrder, setSearchTermOrder] = useState('');
  const [showOrderResults, setShowOrderResults] = useState(false);

  const filteredOrders = (orders || []).filter(order => 
    order.serviceName?.toLowerCase().includes(searchTermOrder.toLowerCase()) ||
    order.clientName?.toLowerCase().includes(searchTermOrder.toLowerCase())
  );

  const filteredEmployees = (employees || []).filter(emp =>
    emp.name?.toLowerCase().includes(searchTermEmployee.toLowerCase())
  );

  const filteredFreelancers = (freelancers || []).filter(free =>
    free.name?.toLowerCase().includes(searchTermFreelancer.toLowerCase())
  );

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!formData.title) {
        alert('Task title is required.');
        return;
    }

    setLoading(true);
    try {
      const config = { headers: { Authorization: `Bearer ${token}` } };
      
      if (todoToEdit) {
        await axios.put(`/api/todos/${todoToEdit._id}`, formData, config);
      } else {
        await axios.post('/api/todos', formData, config);
      }
      
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
      setSearchTermOrder('');
    } catch (error) {
      alert(error.response?.data?.message || 'Error saving task');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  const selectedOrder = (orders || []).find(o => o._id === formData.orderId);

  return (
    <div className="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm">
      <div className="bg-white rounded-3xl w-full max-w-lg shadow-2xl border border-slate-200 overflow-hidden flex flex-col">
        <div className="p-6 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
          <div>
            <h2 className="text-2xl font-black text-slate-900">{todoToEdit ? 'Edit Task' : 'Assign New Task'}</h2>
            <p className="text-slate-500 text-sm">{todoToEdit ? 'Update task details' : 'Direct task assignment to your team.'}</p>
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
                
                {formData.orderId ? (
                  <div className="p-3 bg-indigo-50 border border-indigo-100 rounded-xl flex justify-between items-center">
                    <div className="text-sm">
                      <p className="font-bold text-indigo-900">{selectedOrder?.serviceName}</p>
                      <p className="text-xs text-indigo-600">{selectedOrder?.clientName}</p>
                    </div>
                    <button 
                      type="button" 
                      onClick={() => setFormData({ ...formData, orderId: '' })}
                      className="text-xs font-bold text-rose-500 hover:underline"
                    >
                      Change
                    </button>
                  </div>
                ) : (
                  <div className="relative">
                    <input 
                      type="text" 
                      placeholder="Search order by service or client name..."
                      className="w-full px-4 py-3 rounded-xl border border-slate-200 bg-slate-50 focus:bg-white focus:ring-2 focus:ring-indigo-500 outline-none"
                      value={searchTermOrder}
                      onFocus={() => setShowOrderResults(true)}
                      onChange={(e) => setSearchTermOrder(e.target.value)}
                    />
                    {showOrderResults && searchTermOrder.length > 0 && (
                      <div className="absolute top-full left-0 right-0 mt-2 bg-white border border-slate-200 rounded-xl shadow-xl z-50 max-h-48 overflow-y-auto">
                        {filteredOrders.length > 0 ? (
                          filteredOrders.map(order => (
                            <button
                              key={order._id}
                              type="button"
                              className="w-full text-left px-4 py-3 hover:bg-slate-50 border-b border-slate-50 last:border-0"
                              onClick={() => {
                                setFormData({ ...formData, orderId: order._id });
                                setShowOrderResults(false);
                                setSearchTermOrder('');
                              }}
                            >
                              <p className="font-bold text-slate-900 text-sm">{order.serviceName}</p>
                              <p className="text-xs text-slate-500">{order.clientName}</p>
                            </button>
                          ))
                        ) : (
                          <div className="px-4 py-3 text-slate-500 text-xs italic">No matching orders found.</div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Employee Searchable Input */}
              <div className="space-y-1.5 relative">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
                  <UsersIcon size={12} /> Assign Employee
                </label>
                <div className="relative">
                  <input
                    type="text"
                    className="w-full px-4 py-3 rounded-xl border border-slate-200 outline-none bg-slate-50 focus:bg-white focus:ring-2 focus:ring-indigo-500 text-sm font-semibold text-slate-800"
                    placeholder="Search employee..."
                    value={searchTermEmployee}
                    onChange={(e) => {
                      setSearchTermEmployee(e.target.value);
                      setShowEmployeeResults(true);
                      if (formData.assignedTo && (employees || []).some(emp => emp._id === formData.assignedTo)) {
                        setFormData({ ...formData, assignedTo: '' });
                      }
                    }}
                    onFocus={() => {
                      setShowEmployeeResults(true);
                      setShowFreelancerResults(false);
                    }}
                    onBlur={() => setTimeout(() => setShowEmployeeResults(false), 200)}
                  />
                  {searchTermEmployee && (
                    <button
                      type="button"
                      onClick={() => {
                        setSearchTermEmployee('');
                        if ((employees || []).some(emp => emp._id === formData.assignedTo)) {
                          setFormData({ ...formData, assignedTo: '' });
                        }
                      }}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                    >
                      <X size={14} />
                    </button>
                  )}
                </div>
                {showEmployeeResults && (
                  <div className="absolute left-0 right-0 mt-1 bg-white border border-slate-200 rounded-xl shadow-xl z-50 max-h-40 overflow-y-auto">
                    {filteredEmployees.length > 0 ? (
                      filteredEmployees.map(emp => (
                        <button
                          key={emp._id}
                          type="button"
                          className="w-full text-left px-4 py-2 hover:bg-slate-50 border-b border-slate-50 last:border-0 text-xs font-semibold text-slate-700"
                          onClick={() => {
                            setFormData({ ...formData, assignedTo: emp._id });
                            setSearchTermEmployee(emp.name);
                            setSearchTermFreelancer(''); // Clear freelancer selection
                            setShowEmployeeResults(false);
                          }}
                        >
                          {emp.name}
                        </button>
                      ))
                    ) : (
                      <div className="px-4 py-2 text-slate-400 text-xs italic">No employees found</div>
                    )}
                  </div>
                )}
              </div>

              {/* Freelancer Searchable Input */}
              <div className="space-y-1.5 relative">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
                  <UsersIcon size={12} /> Assign Freelancer
                </label>
                <div className="relative">
                  <input
                    type="text"
                    className="w-full px-4 py-3 rounded-xl border border-slate-200 outline-none bg-slate-50 focus:bg-white focus:ring-2 focus:ring-indigo-500 text-sm font-semibold text-slate-800"
                    placeholder="Search freelancer..."
                    value={searchTermFreelancer}
                    onChange={(e) => {
                      setSearchTermFreelancer(e.target.value);
                      setShowFreelancerResults(true);
                      if (formData.assignedTo && (freelancers || []).some(f => f._id === formData.assignedTo)) {
                        setFormData({ ...formData, assignedTo: '' });
                      }
                    }}
                    onFocus={() => {
                      setShowFreelancerResults(true);
                      setShowEmployeeResults(false);
                    }}
                    onBlur={() => setTimeout(() => setShowFreelancerResults(false), 200)}
                  />
                  {searchTermFreelancer && (
                    <button
                      type="button"
                      onClick={() => {
                        setSearchTermFreelancer('');
                        if ((freelancers || []).some(f => f._id === formData.assignedTo)) {
                          setFormData({ ...formData, assignedTo: '' });
                        }
                      }}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                    >
                      <X size={14} />
                    </button>
                  )}
                </div>
                {showFreelancerResults && (
                  <div className="absolute left-0 right-0 mt-1 bg-white border border-slate-200 rounded-xl shadow-xl z-50 max-h-40 overflow-y-auto">
                    {filteredFreelancers.length > 0 ? (
                      filteredFreelancers.map(f => (
                        <button
                          key={f._id}
                          type="button"
                          className="w-full text-left px-4 py-2 hover:bg-slate-50 border-b border-slate-50 last:border-0 text-xs font-semibold text-slate-700"
                          onClick={() => {
                            setFormData({ ...formData, assignedTo: f._id });
                            setSearchTermFreelancer(f.name);
                            setSearchTermEmployee(''); // Clear employee selection
                            setShowFreelancerResults(false);
                          }}
                        >
                          {f.name}
                        </button>
                      ))
                    ) : (
                      <div className="px-4 py-2 text-slate-400 text-xs italic">No freelancers found</div>
                    )}
                  </div>
                )}
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
                <Calendar size={12} /> Due Date
              </label>
              <input 
                type="date"
                className="w-full px-4 py-3 rounded-xl border border-slate-200 outline-none bg-slate-50 text-sm font-semibold text-slate-700"
                value={formData.dueDate}
                onChange={(e) => setFormData({ ...formData, dueDate: e.target.value })}
              />
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
