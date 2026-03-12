import React from 'react';

const STATUS_STYLES = {
  'Pending Documents': 'bg-amber-100 text-amber-800',
  'Documents Verified': 'bg-blue-100 text-blue-800',
  'Processing at Portal': 'bg-indigo-100 text-indigo-800',
  'Waiting for Clarification': 'bg-purple-100 text-purple-800',
  Completed: 'bg-emerald-100 text-emerald-800',
  Pending: 'bg-amber-100 text-amber-800',
  'In Progress': 'bg-blue-100 text-blue-800',
  Received: 'bg-sky-100 text-sky-800',
  Verified: 'bg-emerald-100 text-emerald-800',
  Draft: 'bg-slate-100 text-slate-700',
  Sent: 'bg-sky-100 text-sky-800',
  Paid: 'bg-emerald-100 text-emerald-800',
  Overdue: 'bg-rose-100 text-rose-800'
};

const StatusBadge = ({ status }) => (
  <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${STATUS_STYLES[status] || 'bg-slate-100 text-slate-700'}`}>
    {status}
  </span>
);

export default StatusBadge;
