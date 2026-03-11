import React from 'react';
import { getOrderClientLabel, StatusBadge } from './helpers';

const DashboardOverviewModule = ({ userInfo, orders, onOpenOrder }) => {
  const activeCount = orders.filter((order) => order.status !== 'Completed').length;
  const pendingCount = orders.filter((order) => order.status === 'Pending Documents').length;
  const completedCount = orders.filter((order) => order.status === 'Completed').length;

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 rounded-3xl p-8 text-white shadow-lg">
        <h2 className="text-3xl font-bold mb-2">Welcome, {userInfo?.name || 'Employee'}</h2>
        <p className="text-slate-400">You have {activeCount} active assignments.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <p className="text-sm font-bold text-slate-500 mb-1">Total Assigned</p>
          <h3 className="text-3xl font-black text-slate-800">{orders.length}</h3>
        </div>
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <p className="text-sm font-bold text-amber-500 mb-1">Pending Documents</p>
          <h3 className="text-3xl font-black text-amber-600">{pendingCount}</h3>
        </div>
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <p className="text-sm font-bold text-emerald-500 mb-1">Completed</p>
          <h3 className="text-3xl font-black text-emerald-600">{completedCount}</h3>
        </div>
      </div>

      <div>
        <h3 className="font-bold text-xl text-slate-800 mb-4">Recent Assignments</h3>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {orders.slice(0, 4).map((order) => (
            <div key={order._id} className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between">
              <div className="flex justify-between items-start mb-4">
                <div>
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
          {orders.length === 0 && (
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

