export const formatDuration = (totalSeconds) => {
  const safe = Math.max(0, Number(totalSeconds || 0));
  const h = Math.floor(safe / 3600);
  const m = Math.floor((safe % 3600) / 60);
  const s = safe % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
};

export const toHours = (minutes) => (Number(minutes || 0) / 60).toFixed(2);
