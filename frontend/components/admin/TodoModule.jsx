import React, { useState } from 'react';
import { 
  CheckSquare, Clock, AlertCircle, CheckCircle2, User, 
  Calendar, Trash2, Edit, Filter, Search,
  XCircle, Link as LinkIcon, ChevronRight
} from 'lucide-react';
import axios from 'axios';

const TodoModule = ({ todos, employees, token, onRefresh, onEdit }) => {
  const [statusFilter, setStatusFilter] = useState('All');
  const [priorityFilter, setPriorityFilter] = useState('All');
  const [assigneeFilter, setAssigneeFilter] = useState('All');
  const [searchTerm, setSearchTerm] = useState('');

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

  const filteredTodos = (todos || []).filter(t => {
    const matchesStatus = statusFilter === 'All' || t.status === statusFilter;
    const matchesPriority = priorityFilter === 'All' || t.priority === priorityFilter;
    const matchesAssignee = assigneeFilter === 'All' || t.assignedTo?._id === assigneeFilter || t.assignedTo === assigneeFilter;
    const matchesSearch = !searchTerm || 
                         t.title?.toLowerCase().includes(searchTerm.toLowerCase()) || 
                         t.description?.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesStatus && matchesPriority && matchesAssignee && matchesSearch;
  });

  const getPriorityColor = (p) => {
    switch (p) {
      case 'Urgent': return 'bg-rose-500';
      case 'High': return 'bg-orange-500';
      case 'Medium': return 'bg-blue-500';
      case 'Low': return 'bg-slate-300';
      default: return 'bg-slate-200';
    }
  };

  const getStatusBadge = (s) => {
    switch (s) {
      case 'Completed': return 'bg-emerald-100 text-emerald-700 border-emerald-200';
      case 'In Progress': return 'bg-amber-100 text-amber-700 border-amber-200';
      case 'Dropped': return 'bg-slate-100 text-slate-600 border-slate-200';
      default: return 'bg-blue-100 text-blue-700 border-blue-200';
    }
  };

  return (
    <div className="space-y-6">
      {/* Stats Summary Panel */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          { label: 'Pending', count: todos.filter(t => t.status === 'Pending').length, color: 'text-blue-600', bg: 'bg-blue-50' },
          { label: 'In Progress', count: todos.filter(t => t.status === 'In Progress').length, color: 'text-amber-600', bg: 'bg-amber-50' },
          { label: 'Completed', count: todos.filter(t => t.status === 'Completed').length, color: 'text-emerald-600', bg: 'bg-emerald-50' },
          { label: 'Total Tasks', count: todos.length, color: 'text-slate-600', bg: 'bg-slate-50' },
        ].map((stat) => (
          <div key={stat.label} className="bg-white p-4 rounded-2xl border border-slate-100 shadow-sm flex flex-col">
            <span className="text-[10px] font-black uppercase text-slate-400 tracking-widest leading-none mb-2">{stat.label}</span>
            <div className="flex items-end justify-between">
              <span className={`text-2xl font-black ${stat.color}`}>{stat.count}</span>
              <div className={`p-2 rounded-xl ${stat.bg} ${stat.color}`}>
                <CheckSquare size={16} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Table Container */}
      <div className="bg-white rounded-3xl border border-slate-200 shadow-xl shadow-slate-200/50 overflow-hidden flex flex-col">
        {/* Advanced Filters Header */}
        <div className="p-6 border-b border-slate-100 space-y-4 bg-slate-50/30">
          <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
             <div className="flex bg-white p-1 rounded-2xl border border-slate-200 shadow-sm w-full lg:w-fit overflow-x-auto no-scrollbar">
                {['All', 'Pending', 'In Progress', 'Completed', 'Dropped'].map((s) => (
                  <button
                    key={s}
                    onClick={() => setStatusFilter(s)}
                    className={`px-5 py-2 rounded-xl text-xs font-black transition-all whitespace-nowrap ${statusFilter === s ? 'bg-slate-900 shadow-lg shadow-slate-900/20 text-white' : 'text-slate-500 hover:text-slate-900'}`}
                  >
                    {s}
                  </button>
                ))}
             </div>
             
             <div className="relative w-full lg:w-80">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                <input 
                  type="text"
                  placeholder="Search tasks..."
                  className="w-full pl-11 pr-4 py-3 rounded-2xl border border-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none bg-white transition-all text-sm shadow-sm"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
             </div>
          </div>

          <div className="flex flex-wrap items-center gap-6 pt-2">
            <div className="flex items-center gap-2">
               <Filter size={14} className="text-slate-400" />
               <span className="text-[10px] font-black uppercase text-slate-400 tracking-widest">Priority:</span>
               <select 
                 className="text-xs font-bold text-slate-800 bg-transparent outline-none cursor-pointer hover:text-indigo-600 transition-colors"
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

            <div className="flex items-center gap-2 border-l pl-6 border-slate-100">
               <User size={14} className="text-slate-400" />
               <span className="text-[10px] font-black uppercase text-slate-400 tracking-widest">Assignee:</span>
               <select 
                 className="text-xs font-bold text-slate-800 bg-transparent outline-none cursor-pointer hover:text-indigo-600 transition-colors"
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

        {/* List View Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-slate-50/50 text-slate-500 border-b border-slate-100">
                <th className="px-6 py-4 text-left font-black uppercase tracking-wider text-[10px]">Title & Description</th>
                <th className="px-6 py-4 text-left font-black uppercase tracking-wider text-[10px]">Assignee</th>
                <th className="px-6 py-4 text-left font-black uppercase tracking-wider text-[10px]">Linked Project</th>
                <th className="px-6 py-4 text-left font-black uppercase tracking-wider text-[10px]">Status</th>
                <th className="px-6 py-4 text-left font-black uppercase tracking-wider text-[10px]">Timeline</th>
                <th className="px-6 py-4 text-right font-black uppercase tracking-wider text-[10px]">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {filteredTodos.map((todo) => (
                <tr key={todo._id} className="hover:bg-slate-50/80 transition-colors group">
                  <td className="px-6 py-4 max-w-sm">
                    <div className="flex items-start gap-4">
                      <div className={`mt-1.5 h-3 w-1.5 rounded-full flex-shrink-0 ${getPriorityColor(todo.priority)} shadow-sm`} title={todo.priority} />
                      <div>
                        <p className="font-bold text-slate-900 group-hover:text-indigo-600 transition-colors leading-tight mb-0.5">{todo.title}</p>
                        <p className="text-xs text-slate-400 line-clamp-1">{todo.description || 'No description provided.'}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-xl bg-slate-100 flex items-center justify-center text-[10px] font-black text-slate-600 border border-white shadow-sm ring-1 ring-slate-100 group-hover:ring-indigo-200 transition-all">
                        {todo.assignedTo?.name?.charAt(0) || <User size={12} />}
                      </div>
                      <span className="font-bold text-slate-700 text-xs">{todo.assignedTo?.name || 'Unassigned'}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    {todo.orderId ? (
                      <div className="inline-flex items-center gap-2 py-1.5 px-3 rounded-xl bg-indigo-50 border border-indigo-100 text-indigo-700 hover:bg-indigo-100 transition-colors cursor-pointer group/link">
                        <LinkIcon size={12} className="opacity-50 group-hover/link:opacity-100" />
                        <span className="text-[11px] font-black tracking-tight max-w-[120px] truncate">{todo.orderId.serviceName}</span>
                      </div>
                    ) : (
                      <span className="text-slate-300 text-[10px] font-bold uppercase tracking-widest pl-2">Stand-alone</span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-xs font-bold text-slate-500">
                    <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider border whitespace-nowrap ${getStatusBadge(todo.status)} shadow-sm`}>
                      {todo.status}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex flex-col gap-0.5">
                       <span className="text-[11px] font-bold text-slate-800 flex items-center gap-1">
                          <Calendar size={10} className="text-slate-400" />
                          {todo.dueDate ? new Date(todo.dueDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '-'}
                       </span>
                       <span className="text-[9px] text-slate-400 font-black uppercase tracking-widest">Due Date</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex items-center justify-end gap-2 pr-2">
                       <button 
                         onClick={() => onEdit(todo)}
                         className="p-2.5 rounded-xl bg-white border border-slate-200 text-slate-400 hover:text-indigo-600 hover:border-indigo-100 hover:bg-slate-50 shadow-sm transition-all active:scale-90"
                         title="Edit"
                       >
                         <Edit size={16} />
                       </button>
                       <button 
                         onClick={() => deleteTodo(todo._id)}
                         className="p-2.5 rounded-xl bg-white border border-slate-200 text-slate-400 hover:text-rose-600 hover:border-rose-100 hover:bg-rose-50 shadow-sm transition-all active:scale-90"
                         title="Delete"
                       >
                         <Trash2 size={16} />
                       </button>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredTodos.length === 0 && (
                <tr>
                   <td colSpan={6} className="py-24 text-center">
                      <div className="flex flex-col items-center justify-center grayscale opacity-80">
                         <div className="w-16 h-16 bg-slate-50 flex items-center justify-center rounded-3xl mb-4 border border-slate-100 shadow-inner">
                            <CheckSquare size={32} className="text-slate-200" />
                         </div>
                         <p className="text-slate-400 font-bold tracking-tight">No tasks matched your search.</p>
                         <button 
                           onClick={() => { setStatusFilter('All'); setPriorityFilter('All'); setAssigneeFilter('All'); setSearchTerm(''); }}
                           className="text-xs font-black text-indigo-600 hover:underline mt-2 uppercase tracking-widest"
                         >
                           Reset Filters
                         </button>
                      </div>
                   </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Footer info */}
        <div className="px-6 py-4 border-t border-slate-50 bg-slate-50/50 flex flex-wrap gap-6 items-center">
           <div className="flex items-center gap-5">
              <span className="flex items-center gap-2"><div className="w-1.5 h-4 rounded-full bg-rose-500" /> <span className="text-[10px] font-black uppercase text-slate-500">Urgent</span></span>
              <span className="flex items-center gap-2"><div className="w-1.5 h-4 rounded-full bg-orange-500" /> <span className="text-[10px] font-black uppercase text-slate-500">High</span></span>
              <span className="flex items-center gap-2"><div className="w-1.5 h-4 rounded-full bg-blue-500" /> <span className="text-[10px] font-black uppercase text-slate-500">Medium</span></span>
              <span className="flex items-center gap-2"><div className="w-1.5 h-4 rounded-full bg-slate-300" /> <span className="text-[10px] font-black uppercase text-slate-500">Low</span></span>
           </div>
           <div className="ml-auto flex items-center gap-2 text-[10px] font-black uppercase text-slate-400">
              <span className="px-2 py-1 rounded bg-white border border-slate-200 shadow-sm text-slate-900">{filteredTodos.length}</span>
              Found Results
           </div>
        </div>
      </div>
    </div>
  );
};

export default TodoModule;
