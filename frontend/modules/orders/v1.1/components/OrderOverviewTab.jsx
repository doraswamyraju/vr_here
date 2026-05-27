import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  CheckCircle, Clock, FileText, User, 
  Plus, CheckSquare, RefreshCcw, IndianRupee, AlertCircle 
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
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);

  const config = React.useMemo(() => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo') || '{}');
    const activeToken = token || userInfo?.token;
    return activeToken ? { headers: { Authorization: `Bearer ${activeToken}` } } : null;
  }, [token]);

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

  useEffect(() => {
    fetchTodos();
    fetchAttendance();
    fetchHistory();
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
    </div>
  );
};

export default OrderOverviewTab;
