import React from 'react';

const STEPS = [
  'Package/Consultation',
  'Package Finalization',
  'Tasks + Requirements Import',
  'Client Upload',
  'Employee Validation + Additional Requests'
];

const OrderFlowSnapshot = () => (
  <div className="rounded-2xl border border-white/70 bg-white/90 p-4 shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
    <p className="text-sm font-semibold text-slate-800 mb-3">Order Flow Snapshot</p>
    <div className="grid grid-cols-1 md:grid-cols-5 gap-2 text-xs">
      {STEPS.map((step, idx) => (
        <div key={step} className="rounded-lg border border-slate-200 p-3 bg-slate-50">
          <p className="text-indigo-600 font-bold">Step {idx + 1}</p>
          <p className="mt-1 text-slate-700">{step}</p>
        </div>
      ))}
    </div>
  </div>
);

export default OrderFlowSnapshot;
