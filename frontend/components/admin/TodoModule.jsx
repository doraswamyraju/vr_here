import React, { useState } from 'react';
import { 
  CheckSquare, Clock, AlertCircle, CheckCircle2, User, 
  Calendar, ArrowRight, MoreVertical, Trash2, Edit 
} from 'lucide-react';
import axios from 'axios';

const TodoModule = ({ todos, employees, token, onRefresh }) => {
  const [filter, setFilter] = useState('All');

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
    if (filter === 'All') return true;
    return t.status === filter;
  });

  const getPriorityColor = (p) => {
    switch (p) {
      case 'Urgent': return 'bg-rose-100 text-rose-700 border-rose-200';
      case 'High': return 'bg-orange-100 text-orange-700 border-orange-200';
      case 'Medium': return 'bg-blue-100 text-blue-700 border-blue-200';
      default: return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  const getStatusIcon = (s) => {
    switch (s) {
      case 'Completed': return <CheckCircle2 size={16} className="text-emerald-500" />;
      case 'In Progress': return <Clock size={16} className="text-blue-500" />;
      case 'Dropped': return <AlertCircle size={16} className="text-slate-400" />;
      default: return <Clock size={16} className="text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="flex gap-2 bg-white/50 p-1 rounded-xl border border-slate-200">
          {['All', 'Pending', 'In Progress', 'Completed'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${filter === f ? 'bg-slate-900 text-white' : 'text-slate-500 hover:text-slate-800'}`}
            >
              {f}
            </button>
          ))}
        </div>
        <p className="text-xs text-slate-500 font-medium">Showing {filteredTodos.length} tasks</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {filteredTodos.map(todo => (
          <div key={todo._id} className="bg-white rounded-2xl border border-slate-200 shadow-sm hover:shadow-md transition-all p-5 flex flex-col gap-4 relative group">
            <div className="flex justify-between items-start">
              <div className={`px-2 py-0.5 rounded text-[10px] font-black border tracking-wider uppercase ${getPriorityColor(todo.priority)}`}>
                {todo.priority}
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => deleteTodo(todo._id)} className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors opacity-0 group-hover:opacity-100">
                  <Trash2 size={14} />
                </button>
              </div>
            </div>

            <div>
              <h3 className="font-bold text-slate-900 line-clamp-1">{todo.title}</h3>
              <p className="text-sm text-slate-500 mt-1 line-clamp-2 min-h-[40px] leading-relaxed">
                {todo.description || 'No description provided.'}
              </p>
            </div>

            {todo.orderId && (
              <div className="bg-indigo-50/50 p-2 rounded-xl flex items-center gap-2 border border-indigo-100/50">
                <div className="p-1 bg-indigo-100 text-indigo-600 rounded">
                  <ArrowRight size={12} />
                </div>
                <div className="text-[10px] whitespace-nowrap overflow-hidden">
                  <p className="text-slate-400 font-bold uppercase tracking-tighter">Linked Order</p>
                  <p className="text-indigo-700 font-black truncate">{todo.orderId.serviceName} - {todo.orderId.clientName}</p>
                </div>
              </div>
            )}

            <div className="mt-auto pt-4 border-t border-slate-100 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-full bg-slate-100 flex items-center justify-center text-slate-500 overflow-hidden">
                  {todo.assignedTo?.name ? (
                    <span className="text-[10px] font-bold">{todo.assignedTo.name.charAt(0)}</span>
                  ) : (
                    <User size={14} />
                  )}
                </div>
                <div className="text-[10px]">
                  <p className="text-slate-400 font-bold uppercase">Assignee</p>
                  <p className="font-black text-slate-900 truncate max-w-[80px]">
                    {todo.assignedTo?.name || 'Unassigned'}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <div className="text-right">
                  <p className="text-slate-400 font-bold text-[10px] uppercase">Status</p>
                  <select 
                    value={todo.status}
                    onChange={(e) => updateStatus(todo._id, e.target.value)}
                    className="text-[10px] font-black text-slate-900 bg-transparent outline-none cursor-pointer hover:underline underline-offset-2"
                  >
                    <option value="Pending">Pending</option>
                    <option value="In Progress">In Progress</option>
                    <option value="Completed">Completed</option>
                    <option value="Dropped">Dropped</option>
                  </select>
                </div>
                <div className="p-1.5 bg-slate-50 rounded-lg">
                  {getStatusIcon(todo.status)}
                </div>
              </div>
            </div>
            
            {todo.dueDate && (
              <div className="absolute top-5 right-5 flex items-center gap-1 text-[10px] font-bold text-slate-400 bg-slate-50 px-2 py-0.5 rounded-full border border-slate-100">
                <Calendar size={10} />
                {new Date(todo.dueDate).toLocaleDateString()}
              </div>
            )}
          </div>
        ))}
      </div>

      {filteredTodos.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 bg-slate-50 rounded-3xl border-2 border-dashed border-slate-200">
          <div className="p-4 bg-white rounded-full shadow-sm mb-4">
            <CheckSquare size={32} className="text-slate-300" />
          </div>
          <p className="text-slate-500 font-bold">No tasks found</p>
          <p className="text-slate-400 text-sm">Create a new task using the "+" button.</p>
        </div>
      )}
    </div>
  );
};

export default TodoModule;
