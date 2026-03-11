import React, { useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import { getOrderClientLabel, StatusBadge } from './helpers';

const WorkQueueModule = ({ orders, onOpenOrder }) => {
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('All');

  const filtered = useMemo(() => {
    return orders.filter((order) => {
      const text = `${order.serviceName} ${order.packageName} ${getOrderClientLabel(order)}`.toLowerCase();
      const queryOk = text.includes(query.toLowerCase());
      const statusOk = statusFilter === 'All' || order.status === statusFilter;
      return queryOk && statusOk;
    });
  }, [orders, query, statusFilter]);

  const statusOptions = ['All', ...new Set(orders.map((order) => order.status).filter(Boolean))];

  return (
    <div className="space-y-5">
      <div className="bg-white border border-slate-200 rounded-xl p-4 flex flex-col md:flex-row gap-3">
        <div className="relative flex-1">
          <Search size={16} className="absolute top-3 left-3 text-slate-400" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by service, package or client..."
            className="w-full pl-10 pr-3 py-2.5 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2.5 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-indigo-500 md:w-56"
        >
          {statusOptions.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
      </div>

      <div className="bg-white rounded-2xl shadow-sm border border-slate-200 p-4 overflow-x-auto">
        <table className="w-full text-left min-w-[820px]">
          <thead className="text-xs uppercase font-bold text-slate-500">
            <tr>
              <th className="p-3">Client</th>
              <th className="p-3">Service</th>
              <th className="p-3">Package</th>
              <th className="p-3">Status</th>
              <th className="p-3">Created</th>
              <th className="p-3">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {filtered.map((order) => (
              <tr key={order._id} className="hover:bg-slate-50">
                <td className="p-3 font-semibold text-slate-700">{getOrderClientLabel(order)}</td>
                <td className="p-3 text-slate-700">{order.serviceName}</td>
                <td className="p-3 text-slate-500">{order.packageName || '-'}</td>
                <td className="p-3">
                  <StatusBadge status={order.status} />
                </td>
                <td className="p-3 text-slate-500">{new Date(order.createdAt).toLocaleDateString()}</td>
                <td className="p-3">
                  <button
                    onClick={() => onOpenOrder(order)}
                    className="px-3 py-1.5 bg-indigo-50 text-indigo-700 rounded-lg text-xs font-bold hover:bg-indigo-100"
                  >
                    Open
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <p className="text-slate-500 text-sm text-center py-6">No queue items match the current filters.</p>
        )}
      </div>
    </div>
  );
};

export default WorkQueueModule;

