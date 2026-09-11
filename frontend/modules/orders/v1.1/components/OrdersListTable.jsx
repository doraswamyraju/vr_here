import React from 'react';
import { Pencil, RefreshCw, Trash2 } from 'lucide-react';
import StatusBadge from './StatusBadge';
import { getOrderClientLabel, rupees } from '../utils/helpers';

const OrdersListTable = ({ orders, onOpen, onQuickUpdate, onDelete }) => (
  <div className="rounded-2xl border border-white/70 bg-white/90 overflow-hidden shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
    <div className="overflow-x-auto">
      <table className="w-full text-sm min-w-[980px]">
        <thead className="bg-slate-900 text-slate-200 text-xs uppercase">
          <tr>
            <th className="text-left px-5 py-3">Order</th>
            <th className="text-left px-5 py-3">Client</th>
            <th className="text-left px-5 py-3">Assigned</th>
            <th className="text-left px-5 py-3">Status</th>
            <th className="text-left px-5 py-3">Amount</th>
            <th className="text-left px-5 py-3">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {orders.map((order) => (
            <tr 
              key={order._id} 
              onClick={() => onOpen(order)}
              className="hover:bg-indigo-50/70 transition cursor-pointer group"
              title="Click to view order details"
            >
              <td className="px-5 py-3.5">
                <p className="font-semibold text-slate-800 group-hover:text-indigo-600 transition-colors">{order.serviceName}</p>
                <p className="text-xs text-slate-500">{order.packageName}</p>
              </td>
              <td className="px-5 py-3.5">{getOrderClientLabel(order)}</td>
              <td className="px-5 py-3.5">{order.assignedProjectManager?.name || order.assignedEmployee?.name || order.assignedMaker?.name || 'Unassigned'}</td>
              <td className="px-5 py-3.5"><StatusBadge status={order.status} /></td>
              <td className="px-5 py-3.5 font-semibold text-slate-800">{rupees(order.price)}</td>
              <td className="px-5 py-3.5">
                <div className="flex items-center gap-2">
                  <button 
                    onClick={(e) => {
                      e.stopPropagation();
                      onOpen(order);
                    }} 
                    className="px-2.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold inline-flex items-center gap-1 shadow-sm transition"
                  >
                    <Pencil size={12} /> Edit
                  </button>
                  <button 
                    onClick={(e) => {
                      e.stopPropagation();
                      onQuickUpdate(order);
                    }} 
                    className="px-2.5 py-1.5 rounded-lg bg-sky-100 hover:bg-sky-200 text-sky-700 text-xs font-semibold inline-flex items-center gap-1 transition"
                  >
                    <RefreshCw size={12} /> Update
                  </button>
                  <button 
                    onClick={(e) => {
                      e.stopPropagation();
                      onDelete(order);
                    }} 
                    className="px-2.5 py-1.5 rounded-lg bg-rose-100 hover:bg-rose-200 text-rose-700 text-xs font-semibold inline-flex items-center gap-1 transition"
                  >
                    <Trash2 size={12} /> Delete
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

export default OrdersListTable;
