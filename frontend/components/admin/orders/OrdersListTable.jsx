import React from 'react';
import { Pencil, RefreshCw, Trash2, ShieldCheck, Clock, AlertTriangle } from 'lucide-react';
import StatusBadge from './StatusBadge';
import { getOrderClientLabel, rupees } from './helpers';

const OrdersListTable = ({ orders, onOpen, onQuickUpdate, onDelete }) => (
  <div className="rounded-2xl border border-white/70 bg-white/90 overflow-hidden shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
    <div className="overflow-x-auto">
      <table className="w-full text-sm min-w-[1080px]">
        <thead className="bg-slate-900 text-slate-200 text-xs uppercase">
          <tr>
            <th className="text-left px-5 py-3.5">Order</th>
            <th className="text-left px-5 py-3.5">Client</th>
            <th className="text-left px-5 py-3.5">3-Tier Team (PM / Maker / Checker)</th>
            <th className="text-left px-5 py-3.5">Audit Stage</th>
            <th className="text-left px-5 py-3.5">Status</th>
            <th className="text-left px-5 py-3.5">Amount</th>
            <th className="text-left px-5 py-3.5">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {orders.map((order) => {
            const auditStatus = order.auditStatus || 'Not Submitted';
            const pmName = order.assignedProjectManager?.name || order.assignedEmployee?.name || 'Unassigned';
            const makerName = order.assignedMaker?.name || 'Unassigned';
            const checkerName = order.assignedChecker?.name || 'Unassigned';

            return (
              <tr 
                key={order._id} 
                onClick={() => onOpen(order)}
                className="hover:bg-indigo-50/70 transition cursor-pointer group"
                title="Click to view order details"
              >
                <td className="px-5 py-3.5">
                  <p className="font-bold text-slate-800 group-hover:text-indigo-600 transition-colors">{order.serviceName}</p>
                  <p className="text-[11px] text-slate-400 font-semibold uppercase">{order.packageName || 'Standard'}</p>
                </td>
                <td className="px-5 py-3.5">
                  <p className="font-semibold text-slate-800">{getOrderClientLabel(order)}</p>
                  {order.phone && <p className="text-[11px] text-slate-400">{order.phone}</p>}
                </td>
                <td className="px-5 py-3.5">
                  <div className="space-y-1 text-xs">
                    <div className="flex items-center gap-1">
                      <span className="text-[9px] font-black uppercase tracking-wider text-indigo-600 bg-indigo-50 px-1 rounded">PM:</span>
                      <span className="font-medium text-slate-700 truncate max-w-[130px]">{pmName}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="text-[9px] font-black uppercase tracking-wider text-slate-600 bg-slate-100 px-1 rounded">MK:</span>
                      <span className="font-medium text-slate-700 truncate max-w-[130px]">{makerName}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="text-[9px] font-black uppercase tracking-wider text-emerald-700 bg-emerald-50 px-1 rounded">CK:</span>
                      <span className="font-medium text-slate-700 truncate max-w-[130px]">{checkerName}</span>
                    </div>
                  </div>
                </td>
                <td className="px-5 py-3.5">
                  <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-black uppercase tracking-wider ${
                    auditStatus === 'Approved by Checker' ? 'bg-emerald-100 text-emerald-800' :
                    auditStatus === 'Submitted for Review' ? 'bg-amber-100 text-amber-800 animate-pulse' :
                    auditStatus === 'Changes Requested' ? 'bg-rose-100 text-rose-800' :
                    'bg-slate-100 text-slate-600'
                  }`}>
                    {auditStatus === 'Approved by Checker' && <ShieldCheck size={12} />}
                    {auditStatus === 'Submitted for Review' && <Clock size={12} />}
                    {auditStatus === 'Changes Requested' && <AlertTriangle size={12} />}
                    {auditStatus}
                  </span>
                </td>
                <td className="px-5 py-3.5"><StatusBadge status={order.status} /></td>
                <td className="px-5 py-3.5 font-black text-slate-800">{rupees(order.price)}</td>
                <td className="px-5 py-3.5">
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={(e) => {
                        e.stopPropagation();
                        onOpen(order);
                      }} 
                      className="px-2.5 py-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold inline-flex items-center gap-1 shadow-sm transition"
                    >
                      <Pencil size={12} /> Manage
                    </button>
                    <button 
                      onClick={(e) => {
                        e.stopPropagation();
                        onQuickUpdate(order);
                      }} 
                      className="px-2.5 py-1.5 rounded-xl bg-sky-100 hover:bg-sky-200 text-sky-700 text-xs font-bold inline-flex items-center gap-1 transition"
                    >
                      <RefreshCw size={12} /> Status
                    </button>
                    <button 
                      onClick={(e) => {
                        e.stopPropagation();
                        onDelete(order);
                      }} 
                      className="px-2.5 py-1.5 rounded-xl bg-rose-100 hover:bg-rose-200 text-rose-700 text-xs font-bold inline-flex items-center gap-1 transition"
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  </div>
);

export default OrdersListTable;
