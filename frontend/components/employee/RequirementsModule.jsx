import React from 'react';

const RequirementsModule = ({ selectedOrder }) => {
  if (!selectedOrder) {
    return <div className="bg-white rounded-2xl border border-slate-200 p-6 text-sm text-slate-500">Select an order to track customer requirements.</div>;
  }

  const requirements = selectedOrder.customerRequirements || [];

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6">
      <h3 className="font-bold text-slate-800 mb-4">Customer Requirements</h3>
      <div className="space-y-3">
        {requirements.map((item) => (
          <div key={item._id} className="border border-slate-200 rounded-lg p-3">
            <div className="flex items-center justify-between">
              <p className="font-semibold text-slate-700">{item.title}</p>
              <span className="text-xs px-2 py-1 rounded-full bg-slate-100 text-slate-600 font-bold">{item.status || 'Pending'}</span>
            </div>
            {item.description && <p className="text-sm text-slate-500 mt-1">{item.description}</p>}
            {item.value && <p className="text-sm text-indigo-600 mt-1">Value: {item.value}</p>}
          </div>
        ))}
        {requirements.length === 0 && (
          <div className="text-sm text-slate-500 border border-dashed border-slate-300 rounded-lg p-4">
            No requirement records yet. Placeholder ready for status update/edit actions.
          </div>
        )}
      </div>
    </div>
  );
};

export default RequirementsModule;

