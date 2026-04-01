import React, { useState } from 'react';
import { 
  CheckSquare, Clock, AlertCircle, CheckCircle2, User, 
  Calendar, ArrowRight, Trash2, Edit, Filter, Search,
  CheckCircle, PlayCircle, XCircle
} from 'lucide-react';
import axios from 'axios';

const TodoModule = ({ todos, employees, token, onRefresh, onEdit }) => {
  const [filter, setFilter] = useState('All');
  const [priorityFilter, setPriorityFilter] = useState('All');
  const [assigneeFilter, setAssigneeFilter] = useState('All');
  const [searchTerm, setSearchTerm] = useState('');

  const updateStatus = async (todoId, status) => {
    try {
      const config = { headers: { Authorization: `Bearer ${token}` } };
      await axios.put(`/api/todos/${todoId}`, { status }, config);
      onRefresh();
    } catch (error) {
      alert('Error updating status');
    }
  };

  const deleteTodo = async (todoId) => {
    if (!window.confirm('Are you sure you want to delete this task?')) return;
    try {
      const config = { headers: { Authorization: `Bearer ${token}` } };
      await axios.delete(`/api/todos/${todoId}`, config);
      onRefresh();
    } catch (error) {
      alert('Error deleting task');
    }
  };

  const filteredTodos = todos.filter(t => {
    const matchesStatus = filter === 'All' || t.status === filter;
    const matchesPriority = priorityFilter === 'All' || t.priority === priorityFilter;
    const matchesAssignee = assigneeFilter === 'All' || t.assignedTo?._id === assigneeFilter || t.assignedTo === assigneeFilter;
    const matchesSearch = t.title?.toLowerCase().includes(searchTerm.toLowerCase()) || 
                         t.description?.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesStatus && matchesPriority && matchesAssignee && matchesSearch;
  });

  const getPriorityStyles = (p) => {
    switch (p) {
      case 'Urgent': return 'bg-rose-50 text-rose-700 border-rose-200';
      case 'High': return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'Medium': return 'bg-blue-50 text-blue-700 border-blue-200';
      default: return 'bg-slate-50 text-slate-700 border-slate-200';
    }
  };

  const getStatusIcon = (s) => {
    switch (s) {
      case 'Completed': return <CheckCircle2 size={16} className="text-emerald-500" />;
      case 'In Progress': return <Clock size={16} className="text-amber-500" />;
      case 'Dropped': return <XCircle size={16} className="text-slate-400" />;
      default: return <AlertCircle size={16} className="text-blue-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Filters Header */}
      <div className="bg-white/70 backdrop-blur-md rounded-3xl p-6 border border-white/50 shadow-xl shadow-slate-200/50 space-y-6">
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6">
          <div className="flex flex-wrap gap-2">
            {['All', 'Pending', 'In Progress', 'Completed', 'Dropped'].map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-5 py-2 rounded-xl text-xs font-black transition-all border ${filter === f ? 'bg-slate-900 border-slate-900 text-white translate-y-[-2px] shadow-lg shadow-slate-900/20' : 'bg-white border-slate-200 text-slate-500 hover:border-slate-300 hover:bg-slate-50'}`}
              >
                {f}
              </button>
            ))}
          </div>
          
          <div className="relative w-full lg:w-72">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
            <input 
              type="text"
              placeholder="Search tasks..."
              className="w-full pl-11 pr-4 py-2.5 rounded-xl border border-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none bg-white/50 transition-all text-sm"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>

        <div className="flex flex-wrap gap-4 pt-4 border-t border-slate-100">
           <div className="flex items-center gap-2">
              <Filter size={14} className="text-slate-400" />
              <span className="text-[10px] font-black uppercase text-slate-400 tracking-widest">Priority:</span>
              <select 
                className="text-xs font-bold text-slate-700 bg-transparent outline-none cursor-pointer"
                value={priorityFilter}
                onChange={(e) => setPriorityFilter(e.target.value)}
              >
                <option value="All">All Priorities</option>
                <option value="Urgent">Urgent</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
           </div>

           <div className="flex items-center gap-2 border-l pl-4 border-slate-100">
              <User size={14} className="text-slate-400" />
              <span className="text-[10px] font-black uppercase text-slate-400 tracking-widest">Assignee:</span>
              <select 
                className="text-xs font-bold text-slate-700 bg-transparent outline-none cursor-pointer"
                value={assigneeFilter}
                onChange={(e) => setAssigneeFilter(e.target.value)}
              >
                <option value="All">All Staff</option>
                {employees.map(emp => (
                  <option key={emp._id} value={emp._id}>{emp.name}</option>
                ))}
              </select>
           </div>
        </div>
      </div>

      {/* Stats Summary */}
      <div className="flex items-center justify-between px-2">
        <p className="text-xs text-slate-500 font-bold uppercase tracking-wider">
          Found <span className="text-slate-900">{filteredTodos.length}</span> results 
          {filter !== 'All' && <span> in <span className="text-indigo-600">{filter}</span></span>}
        </p>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-6">
        {filteredTodos.map(todo => (
          <div key={todo._id} className={`bg-white rounded-3xl border border-slate-200 shadow-sm hover:shadow-2xl hover:border-indigo-100 transition-all duration-300 p-6 flex flex-col gap-5 group relative overflow-hidden`}>
            {/* Status Accent Bar */}
            <div className={`absolute top-0 left-0 w-full h-1.5 ${
              todo.status === 'Completed' ? 'bg-emerald-500' : 
              todo.status === 'In Progress' ? 'bg-amber-500' :
              todo.status === 'Dropped' ? 'bg-slate-300' : 'bg-blue-500'
            }`} />

            <div className="flex justify-between items-start">
              <div className={`px-2.5 py-1 rounded-lg text-[10px] font-black border tracking-wider uppercase ${getPriorityStyles(todo.priority)}`}>
                {todo.priority}
              </div>
              <div className="flex items-center gap-1">
                <button 
                  onClick={() => onEdit(todo)}
                  className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition-all"
                  title="Edit Task"
                >
                  <Edit size={16} />
                </button>
                <button 
                  onClick={() => deleteTodo(todo._id)}
                  className="p-2 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-xl transition-all"
                  title="Delete Task"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </div>

            <div>
              <h3 className="font-bold text-slate-950 text-lg leading-tight group-hover:text-indigo-900 transition-colors">{todo.title}</h3>
              <p className="text-sm text-slate-500 mt-2 line-clamp-2 min-h-[40px] leading-relaxed">
                {todo.description || 'No description provided.'}
              </p>
            </div>

            {todo.orderId && (
              <div className="bg-indigo-50/70 p-3 rounded-2xl flex items-center gap-3 border border-indigo-100/50 group-hover:bg-indigo-100/50 transition-colors">
                <div className="p-2 bg-white text-indigo-600 rounded-xl shadow-sm">
                  <ArrowRight size={14} />
                </div>
                <div className="overflow-hidden">
                  <p className="text-[10px] text-indigo-400 font-black uppercase tracking-widest leading-none mb-1">Related Order</p>
                  <p className="text-indigo-950 text-xs font-bold truncate">{todo.orderId.serviceName}</p>
                </div>
              </div>
            )}

            <div className="mt-auto pt-5 border-t border-slate-50 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-2xl bg-slate-100 flex items-center justify-center text-slate-500 overflow-hidden shadow-inner font-black text-xs">
                  {todo.assignedTo?.name ? (
                    todo.assignedTo.name.charAt(0)
                  ) : (
                    <User size={18} />
                  )}
                </div>
                <div>
                  <p className="text-[9px] text-slate-400 font-black uppercase tracking-widest leading-none mb-1">Assignee</p>
                  <p className="font-bold text-slate-800 text-xs truncate max-w-[100px]">
                    {todo.assignedTo?.name || <span className="text-slate-400">Unassigned</span>}
                  </p>
                </div>
              </div>

              <div className="text-right">
                <div className="flex items-center gap-2 mb-1 justify-end">
                   <p className="text-[9px] text-slate-400 font-black uppercase tracking-widest leading-none">Status</p>
                   {getStatusIcon(todo.status)}
                </div>
                <select 
                  value={todo.status}
                  onChange={(e) => updateStatus(todo._id, e.target.value)}
                  className={`text-xs font-black outline-none cursor-pointer hover:underline underline-offset-4 appearance-none text-right bg-transparent ${
                    todo.status === 'Completed' ? 'text-emerald-600' : 
                    todo.status === 'In Progress' ? 'text-amber-600' : 'text-slate-900'
                  }`}
                >
                  <option value="Pending">Pending</option>
                  <option value="In Progress">In Progress</option>
                  <option value="Completed">Completed</option>
                  <option value="Dropped">Dropped</option>
                </select>
              </div>
            </div>
            
            {/* Quick Action Overlay on corner */}
            <div className="absolute bottom-6 right-6 opacity-0 group-hover:opacity-100 transition-opacity flex gap-2">
                {todo.status !== 'In Progress' && todo.status !== 'Completed' && (
                  <button 
                    onClick={() => updateStatus(todo._id, 'In Progress')}
                    className="p-2 bg-amber-500 text-white rounded-xl shadow-lg shadow-amber-200 hover:scale-110 active:scale-95 transition-all"
                    title="Start Progress"
                  >
                    <PlayCircle size={18} />
                  </button>
                )}
                {todo.status !== 'Completed' && (
                  <button 
                    onClick={() => updateStatus(todo._id, 'Completed')}
                    className="p-2 bg-emerald-500 text-white rounded-xl shadow-lg shadow-emerald-200 hover:scale-110 active:scale-95 transition-all"
                    title="Mark Completed"
                  >
                    <CheckCircle size={18} />
                  </button>
                )}
            </div>

            {todo.dueDate && (
              <div className="absolute top-6 right-6 flex items-center gap-1.5 text-[10px] font-black text-slate-500 bg-white/80 backdrop-blur-sm px-3 py-1.5 rounded-full border border-slate-100 shadow-sm opacity-100 group-hover:opacity-0 transition-opacity">
                <Calendar size={12} className="text-indigo-400" />
                {new Date(todo.dueDate).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
              </div>
            )}
          </div>
        ))}
      </div>

      {filteredTodos.length === 0 && (
        <div className="flex flex-col items-center justify-center py-32 bg-white/40 backdrop-blur-sm rounded-[3rem] border-2 border-dashed border-slate-200 shadow-inner">
          <div className="p-6 bg-white rounded-3xl shadow-xl shadow-slate-200/50 mb-6 text-slate-200">
            <CheckSquare size={48} />
          </div>
          <p className="text-slate-500 font-black text-xl">No tasks matched your criteria</p>
          <p className="text-slate-400 text-sm mt-1 font-medium">Try adjusting your filters or search term.</p>
          <button 
            onClick={() => { setFilter('All'); setPriorityFilter('All'); setAssigneeFilter('All'); setSearchTerm(''); }}
            className="mt-6 px-6 py-2 bg-slate-900 text-white rounded-xl text-sm font-bold shadow-lg shadow-slate-400/20 active:scale-95 transition-all"
          >
            Clear All Filters
          </button>
        </div>
      )}
    </div>
  );
};

export default TodoModule;
