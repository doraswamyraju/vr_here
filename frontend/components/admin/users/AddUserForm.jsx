import React from 'react';
import { USER_ROLES } from './constants';

const AddUserForm = ({ draft, setDraft, onCreateUser, isCreating, partners = [] }) => (
  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
    <p className="font-semibold text-slate-800">Add User</p>
    <p className="text-xs text-slate-500 mb-3">A password setup email will be sent automatically.</p>
    <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
      <input value={draft.name} onChange={(event) => setDraft((prev) => ({ ...prev, name: event.target.value }))} placeholder="Name" className="p-2 border rounded-lg border-slate-300 bg-white text-sm font-semibold" />
      <input value={draft.email} onChange={(event) => setDraft((prev) => ({ ...prev, email: event.target.value }))} placeholder="Email" className="p-2 border rounded-lg border-slate-300 bg-white text-sm" />
      <input value={draft.phone} onChange={(event) => setDraft((prev) => ({ ...prev, phone: event.target.value }))} placeholder="Phone" className="p-2 border rounded-lg border-slate-300 bg-white text-sm" />
      <select value={draft.role} onChange={(event) => setDraft((prev) => ({ ...prev, role: event.target.value }))} className="p-2 border rounded-lg border-slate-300 bg-white text-sm font-bold">
        {USER_ROLES.map((role) => (
          <option key={role} value={role}>{role}</option>
        ))}
      </select>
    </div>

    {draft.role === 'client' && (
      <div className="mt-2.5 flex items-center gap-2">
        <span className="text-xs font-bold text-slate-600 shrink-0">🤝 Referral Partner:</span>
        <select
          value={draft.referredByPartner || ''}
          onChange={(e) => setDraft(prev => ({ ...prev, referredByPartner: e.target.value }))}
          className="p-1.5 border rounded-lg border-slate-300 bg-white text-xs font-semibold max-w-xs"
        >
          <option value="">-- No Partner (Direct Registration) --</option>
          {partners.map(p => (
            <option key={p._id} value={p._id}>
              {p.name} ({p.phone || p.email})
            </option>
          ))}
        </select>
      </div>
    )}

    <button onClick={onCreateUser} disabled={isCreating} className="mt-3 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold disabled:opacity-50 transition">
      {isCreating ? 'Creating...' : 'Create User & Send Password Link'}
    </button>
  </div>
);

export default AddUserForm;

