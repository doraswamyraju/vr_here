import React from 'react';

const Metric = ({ label, value }) => (
  <div className="rounded-xl border border-slate-200 bg-white p-4">
    <p className="text-xs text-slate-500">{label}</p>
    <p className="text-2xl font-bold">{value}</p>
  </div>
);

const OrderOverviewTab = ({ selectedOrder }) => (
  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
    <Metric label="Tasks" value={selectedOrder.tasks?.length || 0} />
    <Metric label="Requirements" value={selectedOrder.customerRequirements?.length || 0} />
    <Metric label="Invoices" value={selectedOrder.invoices?.length || 0} />
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <p className="text-xs text-slate-500">Package</p>
      <p className="text-base font-semibold">{selectedOrder.packageName || '-'}</p>
    </div>
  </div>
);

export default OrderOverviewTab;
