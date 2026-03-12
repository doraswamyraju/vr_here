import React from 'react';
import StatusBadge from './StatusBadge';
import { getOrderClientLabel, rupees } from './helpers';

const OrdersBoardView = ({ orders, onOpen }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
    {orders.map((order) => (
      <button
        type="button"
        key={order._id}
        onClick={() => onOpen(order)}
        className="text-left rounded-2xl border border-white/70 bg-white/90 p-4 hover:-translate-y-1 transition-all shadow-[0_10px_30px_rgba(15,23,42,0.08)]"
      >
        <div className="flex justify-between items-start gap-3">
          <h3 className="font-semibold text-slate-800">{order.serviceName}</h3>
          <StatusBadge status={order.status} />
        </div>
        <p className="text-sm text-slate-600 mt-2">{getOrderClientLabel(order)}</p>
        <p className="text-sm text-slate-500">{order.packageName}</p>
        <div className="mt-3 text-sm font-semibold text-indigo-700">{rupees(order.price)}</div>
      </button>
    ))}
  </div>
);

export default OrdersBoardView;
