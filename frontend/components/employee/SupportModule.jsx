import React from 'react';

const SupportModule = ({ tickets }) => {
  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6">
      <h3 className="font-bold text-slate-800 mb-4">Customer Support Tickets</h3>
      <div className="space-y-3">
        {tickets.map((ticket) => (
          <div key={ticket._id} className="border border-slate-200 rounded-lg p-3">
            <div className="flex items-center justify-between">
              <p className="font-semibold text-slate-700">{ticket.subject || 'Support Request'}</p>
              <span className="text-xs px-2 py-1 rounded-full bg-slate-100 text-slate-600 font-bold">{ticket.status || 'Open'}</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Created: {new Date(ticket.createdAt || Date.now()).toLocaleString()}
            </p>
          </div>
        ))}
        {tickets.length === 0 && <p className="text-sm text-slate-500">No tickets assigned currently.</p>}
      </div>
      <p className="text-xs text-indigo-600 mt-4">Placeholder ready for ticket reply and internal-note actions.</p>
    </div>
  );
};

export default SupportModule;

