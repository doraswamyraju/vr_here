import React from 'react';
import { getOrderClientLabel, StatusBadge } from './helpers';

const DashboardOverviewModule = ({ userInfo, orders, todos = [], onOpenOrder }) => {
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
        <div className="rounded-2xl border border-white/70 bg-white/90 p-6 shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
          <p className="text-sm font-bold text-slate-500 mb-1">Active Orders</p>
          <h3 className="text-3xl font-black text-slate-800">{activeCount}</h3>
        </div>
        <div className="rounded-2xl border border-white/70 bg-white/90 p-6 shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
          <p className="text-sm font-bold text-amber-500 mb-1">Pending Docs</p>
          <h3 className="text-3xl font-black text-amber-600">{pendingDocsCount}</h3>
        </div>
        <div className="rounded-2xl border border-white/70 bg-white/90 p-6 shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
          <p className="text-sm font-bold text-indigo-500 mb-1">Pending TASKS</p>
          <h3 className="text-3xl font-black text-indigo-600">{pendingTodos.length}</h3>
        </div>
        <div className="rounded-2xl border border-white/70 bg-white/90 p-6 shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
          <p className="text-sm font-bold text-emerald-500 mb-1">Completed Orders</p>
          <h3 className="text-3xl font-black text-emerald-600">{completedOrdersCount}</h3>
        </div>
      </div>

      <div>
        <h3 className="font-bold text-xl text-slate-800 mb-4">Recent Assignments</h3>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Recent Orders */}
          {orders.slice(0, 2).map((order) => (
            <div key={order._id} className="rounded-2xl border border-white/70 bg-white/90 p-6 shadow-[0_10px_30px_rgba(15,23,42,0.08)] flex flex-col justify-between">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <div className="text-[10px] font-black uppercase text-slate-400 mb-1 tracking-widest">Order Processing</div>
                  <h4 className="font-bold text-lg text-slate-800">{order.serviceName}</h4>
                  <p className="text-sm text-slate-500">Client: {getOrderClientLabel(order)}</p>
                </div>
                <StatusBadge status={order.status} />
              </div>
              <button
                onClick={() => onOpenOrder(order)}
                className="mt-4 w-full py-2 bg-indigo-50 text-indigo-700 font-bold rounded-lg hover:bg-indigo-100 transition"
              >
                Open Order Processing
              </button>
            </div>
          ))}

          {/* Recent TODOs */}
          {pendingTodos.slice(0, 2).map((todo) => (
            <div key={todo._id} className="rounded-2xl border border-white/70 bg-indigo-50/20 p-6 shadow-[0_10px_30px_rgba(15,23,42,0.08)] flex flex-col justify-between border-dashed">
               <div className="flex justify-between items-start mb-4">
                <div>
                  <div className="text-[10px] font-black uppercase text-indigo-500 mb-1 tracking-widest">Task / Todo</div>
                  <h4 className="font-bold text-lg text-slate-800">{todo.title}</h4>
                  {todo.orderId && <p className="text-sm text-slate-500">Linked to: {todo.orderId.serviceName}</p>}
                </div>
                <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider ${
                  todo.priority === 'Urgent' ? 'bg-rose-100 text-rose-700' : 
                  todo.priority === 'High' ? 'bg-orange-100 text-orange-700' : 'bg-blue-100 text-blue-700'
                }`}>
                  {todo.priority}
                </span>
              </div>
              <div className="mt-4 flex items-center justify-between">
                 <div className="text-xs font-bold text-slate-400">Status: {todo.status}</div>
                 <div className="text-xs font-bold text-indigo-600">Pending Action</div>
              </div>
            </div>
          ))}

          {orders.length === 0 && pendingTodos.length === 0 && (
            <p className="text-slate-500 p-4 border rounded-xl border-dashed border-slate-300">
              No recent assignments.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};

export default DashboardOverviewModule;
