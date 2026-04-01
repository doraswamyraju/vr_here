import React, { useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import { getOrderClientLabel, StatusBadge } from './helpers';

const WorkQueueModule = ({ orders, todos = [], onOpenOrder }) => {
  const [view, setView] = useState('orders'); // 'orders' or 'tasks'
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('All');

  const filteredOrders = useMemo(() => {
    return orders.filter((order) => {
      const text = `${order.serviceName} ${order.packageName} ${getOrderClientLabel(order)}`.toLowerCase();
      const queryOk = text.includes(query.toLowerCase());
      const statusOk = statusFilter === 'All' || order.status === statusFilter;
      return queryOk && statusOk;
    });
  }, [orders, query, statusFilter]);

  const filteredTodos = useMemo(() => {
    return todos.filter((todo) => {
      const text = `${todo.title} ${todo.description} ${todo.orderId?.serviceName || ''}`.toLowerCase();
      const queryOk = text.includes(query.toLowerCase());
      const statusOk = statusFilter === 'All' || todo.status === statusFilter;
      return queryOk && statusOk;
    });
  }, [todos, query, statusFilter]);

  const statusOptions = useMemo(() => {
    const src = view === 'orders' ? orders.map(o => o.status) : todos.map(t => t.status);
    return ['All', ...new Set(src.filter(Boolean))];
  }, [view, orders, todos]);

  return (
    <div className="space-y-5">
      <div className="flex bg-white/50 backdrop-blur-sm p-1 rounded-2xl border border-white/70 w-fit shadow-sm">
        <button 
          onClick={() => { setView('orders'); setStatusFilter('All'); }}
          className={`px-6 py-2 rounded-xl text-xs font-black transition-all ${view === 'orders' ? 'bg-slate-900 border-slate-900 text-white shadow-lg shadow-slate-900/10' : 'text-slate-500 hover:text-slate-800'}`}
        >
          Orders Queue ({orders.length})
        </button>
        <button 
          onClick={() => { setView('tasks'); setStatusFilter('All'); }}
          className={`px-6 py-2 rounded-xl text-xs font-black transition-all ${view === 'tasks' ? 'bg-slate-900 border-slate-900 text-white shadow-lg shadow-slate-900/10' : 'text-slate-500 hover:text-slate-800'}`}
        >
          Tasks & TODOs ({todos.length})
        </button>
      </div>

      <div className="rounded-3xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-5 flex flex-col md:flex-row gap-4">
        <div className="relative flex-1">
          <Search size={18} className="absolute top-1/2 -translate-y-1/2 left-4 text-slate-400" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={view === 'orders' ? "Search by service, client..." : "Search by task title..."}
            className="w-full pl-12 pr-4 py-3 border border-slate-200 rounded-xl text-sm outline-none focus:ring-2 focus:ring-indigo-500 transition-all"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-4 py-3 border border-slate-200 rounded-xl text-sm outline-none focus:ring-2 focus:ring-indigo-500 md:w-56 font-bold text-slate-700"
        >
          {statusOptions.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
      </div>

      <div className="rounded-3xl border border-white/70 bg-white/90 shadow-[0_10px_30px_rgba(15,23,42,0.08)] p-6 overflow-x-auto">
        {view === 'orders' ? (
          <table className="w-full text-left min-w-[820px]">
            <thead className="text-[10px] uppercase font-black text-slate-400 tracking-widest border-b border-slate-100 pb-4">
              <tr>
                <th className="p-3">Client</th>
                <th className="p-3">Service</th>
                <th className="p-3">Package</th>
                <th className="p-3">Status</th>
                <th className="p-3">Created</th>
                <th className="p-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {filteredOrders.map((order) => (
                <tr key={order._id} className="hover:bg-slate-50/50 group transition-colors">
                  <td className="p-3">
                    <p className="font-bold text-slate-800">{getOrderClientLabel(order)}</p>
                    <p className="text-[10px] text-slate-400">ID: {order._id.slice(-6).toUpperCase()}</p>
                  </td>
                  <td className="p-3 font-semibold text-slate-700">{order.serviceName}</td>
                  <td className="p-3">
                    <span className="text-xs text-slate-500 bg-slate-100 px-2.5 py-1 rounded-full font-bold">{order.packageName || '-'}</span>
                  </td>
                  <td className="p-3">
                    <StatusBadge status={order.status} />
                  </td>
                  <td className="p-3 text-slate-500 text-xs font-bold">{new Date(order.createdAt).toLocaleDateString()}</td>
                  <td className="p-3 text-right">
                    <button
                      onClick={() => onOpenOrder(order)}
                      className="px-5 py-2 bg-indigo-600 text-white rounded-xl text-xs font-bold hover:bg-slate-900 transition-all shadow-lg shadow-indigo-100 group-hover:scale-105 active:scale-95"
                    >
                      Process Now
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <table className="w-full text-left min-w-[820px]">
            <thead className="text-[10px] uppercase font-black text-slate-400 tracking-widest border-b border-slate-100 pb-4">
              <tr>
                <th className="p-3">Priority</th>
                <th className="p-3">Task Title</th>
                <th className="p-3">Linked To</th>
                <th className="p-3">Due Date</th>
                <th className="p-3">Status</th>
                <th className="p-3 text-right">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {filteredTodos.map((todo) => (
                <tr key={todo._id} className="hover:bg-slate-50/50 transition-colors">
                  <td className="p-3">
                    <span className={`px-2.5 py-1 rounded-lg text-[10px] font-black uppercase tracking-wider ${
                      todo.priority === 'Urgent' ? 'bg-rose-100 text-rose-700' : 
                      todo.priority === 'High' ? 'bg-orange-100 text-orange-700' : 
                      todo.priority === 'Medium' ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-700'
                    }`}>
                      {todo.priority}
                    </span>
                  </td>
                  <td className="p-3">
                    <p className="font-bold text-slate-800">{todo.title}</p>
                    <p className="text-[10px] text-slate-500 line-clamp-1">{todo.description || 'No description'}</p>
                  </td>
                  <td className="p-3">
                    {todo.orderId ? (
                      <div>
                        <p className="text-xs font-bold text-indigo-700">{todo.orderId.serviceName}</p>
                        <p className="text-[10px] text-indigo-400">{todo.orderId.clientName}</p>
                      </div>
                    ) : (
                      <span className="text-xs text-slate-400 font-bold bg-slate-50 px-2 py-1 rounded-lg border border-slate-100">Standalone</span>
                    )}
                  </td>
                  <td className="p-3 text-slate-700 text-xs font-bold">
                    {todo.dueDate ? new Date(todo.dueDate).toLocaleDateString() : 'No date'}
                  </td>
                  <td className="p-3">
                    <span className={`px-3 py-1.5 rounded-xl text-[10px] font-black uppercase tracking-wider ${
                      todo.status === 'Completed' ? 'bg-emerald-100 text-emerald-700' : 
                      todo.status === 'In Progress' ? 'bg-amber-100 text-amber-700' : 'bg-blue-50 text-blue-600'
                    }`}>
                      {todo.status}
                    </span>
                  </td>
                  <td className="p-3 text-right text-slate-400 text-[10px] font-black">{new Date(todo.createdAt).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        
        {((view === 'orders' && filteredOrders.length === 0) || (view === 'tasks' && filteredTodos.length === 0)) && (
          <div className="flex flex-col items-center justify-center py-20 opacity-60">
             <div className="w-16 h-16 bg-slate-100 rounded-2xl flex items-center justify-center mb-4 border-2 border-dashed border-slate-300">
                <Search size={32} className="text-slate-300" />
             </div>
             <p className="text-slate-500 font-bold">No {view} found matching filters.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default WorkQueueModule;
