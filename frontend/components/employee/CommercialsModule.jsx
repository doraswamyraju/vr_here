import React from 'react';

const CommercialsModule = ({ selectedOrder }) => {
  if (!selectedOrder) {
    return <div className="bg-white rounded-2xl border border-slate-200 p-6 text-sm text-slate-500">Select an order to view commercials and payment details.</div>;
  }

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6">
      <h3 className="font-bold text-slate-800 mb-4">Commercial Snapshot</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
        <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
          <p className="text-slate-500">Service</p>
          <p className="font-semibold text-slate-800">{selectedOrder.serviceName || '-'}</p>
        </div>
        <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
          <p className="text-slate-500">Package</p>
          <p className="font-semibold text-slate-800">{selectedOrder.packageName || '-'}</p>
        </div>
        <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
          <p className="text-slate-500">Price</p>
          <p className="font-semibold text-slate-800">INR {Number(selectedOrder.price || 0).toLocaleString('en-IN')}</p>
        </div>
        <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
          <p className="text-slate-500">Payment Ref</p>
          <p className="font-semibold text-slate-800">{selectedOrder.paymentId || '-'}</p>
        </div>
      </div>
      <p className="text-xs text-indigo-600 mt-4">
        Employee scope: read-only visibility. Admin-only controls can be attached here later.
      </p>
    </div>
  );
};

export default CommercialsModule;

