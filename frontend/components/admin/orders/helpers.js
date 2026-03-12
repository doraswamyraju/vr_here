export const getOrderClientLabel = (order) =>
  order?.user?.name || order?.clientName || order?.email || order?.phone || 'Guest';

export const rupees = (value) => `Rs. ${Number(value || 0).toLocaleString()}`;

export const nextStatus = (currentStatus, statuses) => {
  const index = statuses.indexOf(currentStatus);
  if (index < 0) return statuses[0];
  return statuses[(index + 1) % statuses.length];
};
