export const getOrderClientLabel = (order) =>
  order?.user?.name || order?.clientName || order?.email || order?.phone || 'Guest';

export const getStatusBadgeClass = (status) => {
  const styles = {
    'Pending Documents': 'bg-amber-100 text-amber-700',
    'Documents Verified': 'bg-blue-100 text-blue-700',
    'Processing at Portal': 'bg-indigo-100 text-indigo-700',
    'Waiting for Clarification': 'bg-purple-100 text-purple-700',
    Completed: 'bg-emerald-100 text-emerald-700'
  };
  return styles[status] || 'bg-slate-100 text-slate-600';
};

export const StatusBadge = ({ status }) => (
  <span className={`px-3 py-1 rounded-full text-xs font-bold ${getStatusBadgeClass(status)}`}>
    {status || 'Unknown'}
  </span>
);

