import React from 'react';
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
        <h3 className="font-black text-xs uppercase tracking-[0.2em] text-slate-400 mb-4 ml-1">Current Assignments</h3>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* Recent Orders */}
          {orders.slice(0, 4).filter(o => o.status !== 'Completed').map((order) => (
            <div key={order._id} className="rounded-3xl border border-white/80 bg-white/70 backdrop-blur-md p-6 shadow-[0_10px_40px_rgba(15,23,42,0.06)] flex flex-col justify-between hover:shadow-indigo-100 transition-all group overflow-hidden relative">
              <div className="absolute top-0 right-0 w-24 h-24 bg-indigo-50 rounded-full -mr-12 -mt-12 opacity-50 group-hover:scale-110 transition-transform"></div>
              <div className="flex justify-between items-start mb-4 relative">
                <div>
                  <div className="text-[10px] font-black uppercase text-indigo-400 mb-1 tracking-widest">Active Project</div>
                  <h4 className="font-black text-xl text-slate-800 leading-tight">{order.serviceName}</h4>
                  <p className="text-sm font-bold text-slate-400 mt-1">Client: <span className="text-slate-600">{getOrderClientLabel(order)}</span></p>
                </div>
                <div className="scale-90"><StatusBadge status={order.status} /></div>
              </div>
              <button
                onClick={() => onOpenOrder(order)}
                className="mt-6 w-full py-3.5 bg-indigo-50 text-indigo-700 font-black rounded-2xl hover:bg-slate-900 hover:text-white transition-all shadow-md shadow-indigo-50 active:scale-95 text-xs uppercase tracking-widest"
              >
                Launch Process Control
              </button>
            </div>
          ))}

          {/* Recent TODOs */}
          {pendingTodos.slice(0, 4).map((todo) => (
            <div key={todo._id} className="rounded-3xl border border-indigo-100/50 bg-indigo-50/20 p-6 shadow-[0_10px_40px_rgba(15,23,42,0.04)] flex flex-col justify-between border-dashed hover:border-indigo-300 transition-all group">
               <div className="flex justify-between items-start mb-4">
                <div>
                  <div className="text-[10px] font-black uppercase text-indigo-500 mb-1 tracking-widest">Task / Todo</div>
                  <h4 className="font-black text-xl text-slate-800 leading-tight">{todo.title}</h4>
                  {todo.orderId ? (
                    <button 
                       onClick={() => onOpenOrder(todo.orderId)}
                       className="text-xs font-bold text-indigo-600 mt-2 hover:underline inline-flex items-center gap-1"
                    >
                       Linked to: {todo.orderId.serviceName}
                    </button>
                  ) : (
                    <p className="text-[10px] font-black uppercase text-slate-400 mt-2 tracking-widest">Standalone Workflow</p>
                  )}
                </div>
                <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider shadow-sm border ${
                  todo.priority === 'Urgent' ? 'bg-rose-50 text-rose-700 border-rose-100' : 
                  todo.priority === 'High' ? 'bg-orange-50 text-orange-700 border-orange-100' : 'bg-blue-50 text-blue-700 border-blue-100'
                }`}>
                  {todo.priority}
                </span>
              </div>
              
              <div className="mt-6 flex items-center gap-3">
                 {todo.status === 'Pending' && (
                    <button 
                      onClick={() => handleTodoAction(todo._id, 'In Progress')}
                      className={`flex-1 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all active:scale-95 shadow-sm ${isClockedIn ? 'bg-white border border-indigo-200 text-indigo-700 hover:bg-indigo-600 hover:text-white' : 'bg-slate-100 text-slate-300 opacity-50 cursor-not-allowed'}`}
                    >
                       Start task
                    </button>
                 )}
                 <button 
                   onClick={() => handleTodoAction(todo._id, 'Completed')}
                   className={`flex-1 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all active:scale-95 shadow-sm ${isClockedIn ? 'bg-white border border-emerald-200 text-emerald-700 hover:bg-emerald-600 hover:text-white' : 'bg-slate-100 text-slate-300 opacity-50 cursor-not-allowed'}`}
                 >
                    Mark Done
                 </button>
              </div>
            </div>
          ))}

          {orders.length === 0 && pendingTodos.length === 0 && (
            <div className="col-span-full py-20 flex flex-col items-center justify-center bg-white/50 rounded-[40px] border border-dashed border-slate-200">
               <div className="w-16 h-16 bg-slate-50 rounded-full flex items-center justify-center mb-4 italic text-slate-200 font-black">?</div>
               <p className="text-slate-400 font-bold tracking-tight">No active assignments on your desk.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DashboardOverviewModule;
