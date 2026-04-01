import React from 'react';
import { CheckCircle } from 'lucide-react';
import { getOrderClientLabel, StatusBadge } from './helpers';

const DashboardOverviewModule = ({ userInfo, orders, todos = [], onOpenOrder, onTodoStatusChange, isClockedIn }) => {
  const handleTodoAction = (id, status) => {
    if (!isClockedIn) {
      alert('Please clock in before starting work.');
      return;
    }
    onTodoStatusChange(id, status);
  };

  const activeCount = orders.filter((order) => order.status !== 'Completed').length;
  const pendingDocsCount = orders.filter((order) => order.status === 'Pending Documents').length;
  const completedOrdersCount = orders.filter((order) => order.status === 'Completed').length;
  
  const pendingTodos = todos.filter(t => t.status !== 'Completed');

  return (
    <div className="space-y-6">
      <div className="rounded-2xl p-8 text-white bg-gradient-to-r from-slate-900 via-blue-900 to-indigo-900 shadow-[0_10px_30px_rgba(15,23,42,0.18)]">
        <h2 className="text-3xl font-bold mb-2">Welcome, {userInfo?.name || 'Employee'}</h2>
        <p className="text-slate-400">You have {activeCount} active orders and {pendingTodos.length} pending tasks.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="rounded-2xl border border-white/70 bg-white/90 p-6 shadow-[0_10px_30px_rgba(15,23,42,0.08)] transition-all hover:scale-105">
          <p className="text-sm font-bold text-slate-500 mb-1">Active Projects</p>
          <h3 className="text-3xl font-black text-slate-800">{activeCount}</h3>
        </div>
        <div className="rounded-2xl border border-white/70 bg-white/90 p-6 shadow-[0_10px_30px_rgba(15,23,42,0.08)] transition-all hover:scale-105">
          <p className="text-sm font-bold text-amber-500 mb-1">Doc Pending</p>
          <h3 className="text-3xl font-black text-amber-600">{pendingDocsCount}</h3>
        </div>
        <div className="rounded-2xl border border-white/70 bg-white/90 p-6 shadow-[0_10px_30px_rgba(15,23,42,0.08)] transition-all hover:scale-105">
          <p className="text-sm font-bold text-indigo-500 mb-1">Global Tasks</p>
          <h3 className="text-3xl font-black text-indigo-600">{pendingTodos.length}</h3>
        </div>
        <div className="rounded-2xl border border-white/70 bg-white/90 p-6 shadow-[0_10px_30px_rgba(15,23,42,0.08)] transition-all hover:scale-105">
          <p className="text-sm font-bold text-emerald-500 mb-1">Success Units</p>
          <h3 className="text-3xl font-black text-emerald-600">{completedOrdersCount}</h3>
        </div>
      </div>

      <div className="space-y-4">
        <h3 className="font-extrabold text-xs uppercase tracking-[0.2em] text-slate-400 mb-2 ml-1">Current Assignments</h3>
        <div className="rounded-[32px] border border-white/70 bg-white/60 backdrop-blur-xl shadow-[0_20px_50px_rgba(15,23,42,0.05)] overflow-hidden">
          <table className="w-full text-left">
            <thead className="text-[10px] uppercase font-black text-slate-400 tracking-widest border-b border-slate-100/50">
              <tr>
                <th className="px-6 py-4">Title / Context</th>
                <th className="px-6 py-4">Linked Project</th>
                <th className="px-6 py-4">Status / Priority</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100/50">
              {/* Combine and Sort Assignments */}
              {[
                ...orders.filter(o => o.status !== 'Completed').map(o => ({ ...o, type: 'order' })),
                ...pendingTodos.map(t => ({ ...t, type: 'todo' }))
              ].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 8).map((item) => (
                <tr key={item._id} className="group hover:bg-white/80 transition-colors">
                  <td className="px-6 py-5">
                    <div className="flex items-center gap-3">
                      <div className={`w-1.5 h-8 rounded-full ${item.type === 'order' ? 'bg-indigo-500' : 'bg-amber-500'}`}></div>
                      <div>
                         <p className="font-black text-slate-800 leading-tight">{item.serviceName || item.title}</p>
                         <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-1">
                           {item.type === 'order' ? 'Project' : 'Standalone Task'}
                         </p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-5">
                    {item.type === 'order' ? (
                       <p className="text-sm font-bold text-slate-600">{getOrderClientLabel(item)}</p>
                    ) : (
                       item.orderId ? (
                         <button 
                            onClick={() => onOpenOrder(item.orderId)}
                            className="text-sm font-bold text-indigo-600 hover:underline text-left leading-tight"
                         >
                            {item.orderId.serviceName}
                         </button>
                       ) : (
                         <span className="text-xs text-slate-300 font-bold tracking-widest uppercase">Internal</span>
                       )
                    )}
                  </td>
                  <td className="px-6 py-5">
                     <div className="flex items-center gap-3">
                        {item.type === 'order' ? <StatusBadge status={item.status} /> : (
                           <span className={`px-2.5 py-1 rounded-lg text-[9px] font-black uppercase tracking-wider ${
                              item.priority === 'Urgent' ? 'bg-rose-100 text-rose-700' : 
                              item.priority === 'High' ? 'bg-orange-100 text-orange-700' : 'bg-blue-100 text-blue-700'
                           }`}>
                              {item.priority}
                           </span>
                        )}
                        {item.type === 'todo' && (
                           <span className="text-[10px] font-bold text-slate-400 capitalize">{item.status}</span>
                        )}
                     </div>
                  </td>
                  <td className="px-6 py-5 text-right">
                    <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                      {item.type === 'order' ? (
                        <button
                          onClick={() => onOpenOrder(item)}
                          className="px-4 py-2 bg-slate-900 text-white rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-indigo-600 transition-all shadow-lg shadow-slate-900/10 active:scale-95"
                        >
                          Control
                        </button>
                      ) : (
                        <>
                          {item.status === 'Pending' && (
                            <button
                              onClick={() => handleTodoAction(item._id, 'In Progress')}
                              className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all active:scale-95 shadow-lg ${isClockedIn ? 'bg-indigo-600 text-white shadow-indigo-100 hover:bg-slate-900' : 'bg-slate-100 text-slate-400 cursor-not-allowed shadow-none'}`}
                            >
                              Start
                            </button>
                          )}
                          <button
                            onClick={() => handleTodoAction(item._id, 'Completed')}
                            className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all active:scale-95 shadow-lg ${isClockedIn ? 'bg-emerald-600 text-white shadow-emerald-100 hover:bg-slate-900' : 'bg-slate-100 text-slate-400 cursor-not-allowed shadow-none'}`}
                          >
                            Done
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {(orders.length === 0 && pendingTodos.length === 0) && (
                <tr>
                  <td colSpan="4" className="py-20 text-center">
                    <p className="text-slate-400 font-bold tracking-tight">No active assignments on your desk.</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default DashboardOverviewModule;
