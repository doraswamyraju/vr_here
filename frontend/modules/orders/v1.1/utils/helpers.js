export const getOrderClientLabel = (order) =>
  order?.user?.name || order?.clientName || order?.email || order?.phone || 'Guest';

export const rupees = (value) => `Rs. ${Number(value || 0).toLocaleString()}`;

export const nextStatus = (currentStatus, statuses) => {
  const index = statuses.indexOf(currentStatus);
  if (index < 0) return statuses[0];
  return statuses[(index + 1) % statuses.length];
};

export const formatDuration = (totalSeconds) => {
  const safe = Math.max(0, Number(totalSeconds || 0));
  const h = Math.floor(safe / 3600);
  const m = Math.floor((safe % 3600) / 60);
  const s = safe % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
};
